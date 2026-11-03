#!/usr/bin/env python3
"""Summarize DNS questions and responses from a classic PCAP without exposing packet data.

Supported link layers are Ethernet (including a bounded stack of 802.1Q tags), raw IP,
Linux cooked capture v1/v2. The parser accepts unfragmented IPv4 and IPv6 with a bounded
set of simple extension headers. TCP DNS is intentionally not decoded or reassembled.

Example:
    python3 tools/pcap-dns-summary.py --pcap capture.pcap \
        --rules app/src/main/assets/anti-ad-domains.txt --output .toolchain/safe/summary.json

The JSON contains only packet counts and per-domain aggregate counts. It does not include
addresses, link-layer identifiers, timestamps, DNS transaction IDs, or packet payloads.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Dict, Iterable, Optional, Set, Tuple


DLT_EN10MB = 1
DLT_RAW = 101
DLT_LINUX_SLL = 113
DLT_LINUX_SLL2 = 276

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
VLAN_TYPES = {0x8100, 0x88A8, 0x9100}
UDP_PROTOCOL = 17
DNS_PORT = 53
MAX_CAPTURED_PACKET_BYTES = 16 * 1024 * 1024
MAX_VLAN_TAGS = 4
MAX_IPV6_EXTENSIONS = 8
MAX_IPV6_EXTENSION_BYTES = 2048
MAX_DNS_POINTER_HOPS = 128


class CaptureError(Exception):
    """A malformed or unsupported classic PCAP file header."""


class PacketError(Exception):
    """A malformed packet or DNS message."""


class UnsupportedPacket(Exception):
    """A valid packet feature this summary intentionally does not decode."""


@dataclass(frozen=True)
class DnsMessage:
    transaction_id: int
    qr: bool
    opcode: int
    rcode: int
    domain: str
    qtype: int
    qclass: int
    answer_count: int


@dataclass
class DomainCounts:
    queries: int = 0
    responses: int = 0
    types: Counter = field(default_factory=Counter)
    rcodes: Counter = field(default_factory=Counter)
    answer_counts: Counter = field(default_factory=Counter)


def default_rules_path() -> Path:
    return Path(__file__).resolve().parent.parent / "app" / "src" / "main" / "assets" / "anti-ad-domains.txt"


def load_blocklist(path: Path) -> Set[str]:
    rules: Set[str] = set()
    with path.open("r", encoding="utf-8", errors="strict") as handle:
        for line in handle:
            rule = line.strip()
            if not rule or rule.startswith("#"):
                continue
            normalized = rule.rstrip(".").lower()
            if normalized:
                rules.add(normalized)
    return rules


def matches_blocklist(domain: str, rules: Set[str]) -> bool:
    candidate = domain.lower()
    while candidate:
        if candidate in rules:
            return True
        dot = candidate.find(".")
        if dot < 0:
            break
        candidate = candidate[dot + 1 :]
    return False


def summarize_pcap(pcap_path: Path, rules_path: Path) -> Dict[str, object]:
    rules = load_blocklist(rules_path)
    domains: Dict[str, DomainCounts] = {}
    packet_count = 0
    malformed_count = 0

    with pcap_path.open("rb") as handle:
        endian, snaplen, linktype = read_global_header(handle)
        while True:
            record_header = handle.read(16)
            if not record_header:
                break
            packet_count += 1
            if len(record_header) != 16:
                malformed_count += 1
                break

            _, _, captured_length, original_length = struct.unpack(
                endian + "IIII", record_header
            )
            if captured_length > MAX_CAPTURED_PACKET_BYTES:
                malformed_count += 1
                if not discard_exact(handle, captured_length):
                    break
                continue

            packet = handle.read(captured_length)
            if len(packet) != captured_length:
                malformed_count += 1
                break
            if captured_length > snaplen or original_length < captured_length:
                malformed_count += 1
                continue

            try:
                dns_payload = extract_udp_dns_payload(packet, linktype)
                if dns_payload is None:
                    continue
                message = parse_dns_message(dns_payload)
            except UnsupportedPacket:
                continue
            except (PacketError, IndexError, struct.error, ValueError):
                malformed_count += 1
                continue

            # This report targets ordinary DNS queries/responses; other valid opcodes are
            # extracted by the parser but left out of the domain totals.
            if message.opcode != 0:
                continue
            counts = domains.setdefault(message.domain, DomainCounts())
            if message.qr:
                counts.responses += 1
                counts.rcodes[rcode_name(message.rcode)] += 1
                counts.answer_counts[str(message.answer_count)] += 1
            else:
                counts.queries += 1
                counts.types[type_name(message.qtype)] += 1

    output_domains = []
    for domain in sorted(domains):
        counts = domains[domain]
        output_domains.append(
            {
                "domain": domain,
                "queries": counts.queries,
                "responses": counts.responses,
                "types": dict(sorted(counts.types.items())),
                "rcodes": dict(sorted(counts.rcodes.items())),
                "answerCounts": dict(sorted(counts.answer_counts.items())),
                "matchesBlocklist": matches_blocklist(domain, rules),
            }
        )
    return {
        "packetCount": packet_count,
        "malformedCount": malformed_count,
        "domains": output_domains,
    }


def read_global_header(handle: BinaryIO) -> Tuple[str, int, int]:
    header = handle.read(24)
    if len(header) != 24:
        raise CaptureError("invalid PCAP global header")
    magic = header[:4]
    magics = {
        b"\xd4\xc3\xb2\xa1": "<",  # microsecond timestamps, little-endian
        b"\xa1\xb2\xc3\xd4": ">",  # microsecond timestamps, big-endian
        b"\x4d\x3c\xb2\xa1": "<",  # nanosecond timestamps, little-endian
        b"\xa1\xb2\x3c\x4d": ">",  # nanosecond timestamps, big-endian
    }
    endian = magics.get(magic)
    if endian is None:
        raise CaptureError("unsupported PCAP magic")
    major, minor, _, _, snaplen, network = struct.unpack(endian + "HHIIII", header[4:])
    if major != 2 or minor not in (3, 4) or snaplen == 0:
        raise CaptureError("unsupported PCAP header version or snap length")
    return endian, snaplen, network & 0xFFFF


def discard_exact(handle: BinaryIO, length: int) -> bool:
    remaining = length
    while remaining > 0:
        chunk = handle.read(min(65_536, remaining))
        if not chunk:
            return False
        remaining -= len(chunk)
    return True


def extract_udp_dns_payload(packet: bytes, linktype: int) -> Optional[bytes]:
    if linktype == DLT_EN10MB:
        protocol, offset = parse_ethernet(packet)
    elif linktype == DLT_RAW:
        if not packet:
            raise PacketError("empty raw packet")
        version = packet[0] >> 4
        if version not in (4, 6):
            raise PacketError("invalid raw IP version")
        protocol = ETH_P_IP if version == 4 else ETH_P_IPV6
        offset = 0
    elif linktype == DLT_LINUX_SLL:
        if len(packet) < 16:
            raise PacketError("truncated Linux cooked header")
        protocol = _u16(packet, 14)
        offset = 16
    elif linktype == DLT_LINUX_SLL2:
        if len(packet) < 20:
            raise PacketError("truncated Linux cooked v2 header")
        protocol = _u16(packet, 0)
        offset = 20
    else:
        raise PacketError("unsupported PCAP link type")

    if protocol == ETH_P_IP:
        source_port, destination_port, udp_payload = parse_ipv4_udp(packet, offset)
    elif protocol == ETH_P_IPV6:
        source_port, destination_port, udp_payload = parse_ipv6_udp(packet, offset)
    else:
        return None
    if source_port != DNS_PORT and destination_port != DNS_PORT:
        return None
    return udp_payload


def parse_ethernet(packet: bytes) -> Tuple[int, int]:
    if len(packet) < 14:
        raise PacketError("truncated Ethernet header")
    protocol = _u16(packet, 12)
    offset = 14
    tags = 0
    while protocol in VLAN_TYPES:
        if tags >= MAX_VLAN_TAGS or offset > len(packet) - 4:
            raise PacketError("invalid or excessively nested VLAN header")
        protocol = _u16(packet, offset + 2)
        offset += 4
        tags += 1
    return protocol, offset


def parse_ipv4_udp(packet: bytes, offset: int) -> Tuple[int, int, bytes]:
    if offset < 0 or offset > len(packet) - 20:
        raise PacketError("truncated IPv4 header")
    first = packet[offset]
    if first >> 4 != 4:
        raise PacketError("invalid IPv4 version")
    header_length = (first & 0x0F) * 4
    if header_length < 20 or offset > len(packet) - header_length:
        raise PacketError("invalid IPv4 header length")
    total_length = _u16(packet, offset + 2)
    if total_length < header_length or total_length > len(packet) - offset:
        raise PacketError("invalid IPv4 total length")
    fragment = _u16(packet, offset + 6)
    if fragment & 0x8000:
        raise PacketError("IPv4 reserved fragmentation flag is set")
    if fragment & 0x3FFF:
        raise UnsupportedPacket("fragmented IPv4 packet")
    if packet[offset + 9] != UDP_PROTOCOL:
        return 0, 0, b""
    return parse_udp(packet, offset + header_length, offset + total_length)


def parse_ipv6_udp(packet: bytes, offset: int) -> Tuple[int, int, bytes]:
    if offset < 0 or offset > len(packet) - 40:
        raise PacketError("truncated IPv6 header")
    if packet[offset] >> 4 != 6:
        raise PacketError("invalid IPv6 version")
    payload_length = _u16(packet, offset + 4)
    end = offset + 40 + payload_length
    next_header = packet[offset + 6]
    if payload_length == 0:
        if next_header == 59:  # Valid empty packet with No Next Header.
            return 0, 0, b""
        raise UnsupportedPacket("IPv6 zero-payload jumbograms are not decoded")
    if end > len(packet):
        raise PacketError("invalid IPv6 payload length")

    cursor = offset + 40
    extension_count = 0
    extension_bytes = 0
    simple_extensions = {0, 43, 60, 135, 139, 140}
    while next_header in simple_extensions or next_header in (44, 51):
        extension_count += 1
        if extension_count > MAX_IPV6_EXTENSIONS:
            raise UnsupportedPacket("too many IPv6 extension headers")
        if next_header == 44:
            if cursor > end - 8:
                raise PacketError("truncated IPv6 fragment header")
            raise UnsupportedPacket("fragmented IPv6 packet")
        if cursor > end - 2:
            raise PacketError("truncated IPv6 extension header")
        following_header = packet[cursor]
        length_field = packet[cursor + 1]
        if next_header == 51:  # Authentication Header length is in four-byte units.
            extension_length = (length_field + 2) * 4
            if extension_length < 12:
                raise PacketError("invalid IPv6 authentication header length")
        else:
            extension_length = (length_field + 1) * 8
        if cursor > end - extension_length:
            raise PacketError("IPv6 extension header exceeds payload")
        extension_bytes += extension_length
        if extension_bytes > MAX_IPV6_EXTENSION_BYTES:
            raise UnsupportedPacket("IPv6 extension chain exceeds bound")
        cursor += extension_length
        next_header = following_header

    if next_header == 50:  # ESP is encrypted; no transport header can be inspected.
        raise UnsupportedPacket("encrypted IPv6 payload")
    if next_header != UDP_PROTOCOL:
        return 0, 0, b""
    return parse_udp(packet, cursor, end)


def parse_udp(packet: bytes, offset: int, end: int) -> Tuple[int, int, bytes]:
    if offset < 0 or end < offset or offset > end - 8:
        raise PacketError("truncated UDP header")
    source_port = _u16(packet, offset)
    destination_port = _u16(packet, offset + 2)
    udp_length = _u16(packet, offset + 4)
    if udp_length < 8 or udp_length != end - offset:
        raise PacketError("invalid UDP length")
    return source_port, destination_port, packet[offset + 8 : end]


def parse_dns_message(payload: bytes) -> DnsMessage:
    if len(payload) < 12:
        raise PacketError("truncated DNS header")
    transaction_id = _u16(payload, 0)
    flags = _u16(payload, 2)
    question_count = _u16(payload, 4)
    answer_count = _u16(payload, 6)
    authority_count = _u16(payload, 8)
    additional_count = _u16(payload, 10)
    if question_count != 1:
        raise PacketError("DNS message must contain exactly one question")

    domain, cursor = parse_dns_name(payload, 12)
    if cursor > len(payload) - 4:
        raise PacketError("truncated DNS question")
    qtype = _u16(payload, cursor)
    qclass = _u16(payload, cursor + 2)
    cursor += 4

    for count in (answer_count, authority_count, additional_count):
        cursor = skip_resource_records(payload, cursor, count)
    if cursor != len(payload):
        raise PacketError("trailing bytes in DNS message")

    return DnsMessage(
        transaction_id=transaction_id,
        qr=bool(flags & 0x8000),
        opcode=(flags >> 11) & 0x0F,
        rcode=flags & 0x0F,
        domain=domain,
        qtype=qtype,
        qclass=qclass,
        answer_count=answer_count,
    )


def skip_resource_records(message: bytes, cursor: int, count: int) -> int:
    for _ in range(count):
        _, cursor = parse_dns_name(message, cursor)
        if cursor > len(message) - 10:
            raise PacketError("truncated DNS resource record")
        data_length = _u16(message, cursor + 8)
        cursor += 10
        if data_length > len(message) - cursor:
            raise PacketError("truncated DNS resource data")
        cursor += data_length
    return cursor


def parse_dns_name(message: bytes, start: int) -> Tuple[str, int]:
    if start < 0 or start >= len(message):
        raise PacketError("DNS name begins outside message")
    labels = []
    cursor = start
    consumed_end: Optional[int] = None
    expanded_length = 1  # root terminator
    pointer_hops = 0
    visited_pointers: Set[int] = set()

    while True:
        if cursor < 0 or cursor >= len(message):
            raise PacketError("unterminated DNS name")
        length = message[cursor]
        if (length & 0xC0) == 0xC0:
            if cursor + 1 >= len(message):
                raise PacketError("truncated DNS compression pointer")
            target = ((length & 0x3F) << 8) | message[cursor + 1]
            if target >= cursor or target >= len(message) or cursor in visited_pointers:
                raise PacketError("invalid DNS compression pointer")
            visited_pointers.add(cursor)
            pointer_hops += 1
            if pointer_hops > MAX_DNS_POINTER_HOPS:
                raise PacketError("DNS compression pointer chain exceeds bound")
            if consumed_end is None:
                consumed_end = cursor + 2
            cursor = target
            continue
        if length & 0xC0:
            raise PacketError("unsupported DNS label encoding")
        cursor += 1
        if length == 0:
            if consumed_end is None:
                consumed_end = cursor
            break
        if length > 63 or cursor > len(message) - length:
            raise PacketError("invalid or truncated DNS label")
        expanded_length += length + 1
        if expanded_length > 255:
            raise PacketError("DNS name exceeds maximum expanded length")
        label = []
        for value in message[cursor : cursor + length]:
            if value < 0x20 or value > 0x7E or value == 0x7F:
                raise PacketError("DNS label contains a non-printable byte")
            character = chr(value)
            if character.isascii() and (character.isalnum() or character in "-_"):
                label.append(character.lower())
            else:
                # Keep unusual printable label bytes distinct from separators and URLs.
                label.append("\\" + format(value, "03d"))
        labels.append("".join(label))
        cursor += length

    if not labels:
        return ".", consumed_end
    return ".".join(labels), consumed_end


def type_name(value: int) -> str:
    common = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        41: "OPT",
        65: "HTTPS",
        255: "ANY",
    }
    return common.get(value, "TYPE" + str(value))


def rcode_name(value: int) -> str:
    common = {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED",
    }
    return common.get(value, "RCODE" + str(value))


def _u16(data: bytes, offset: int) -> int:
    return (data[offset] << 8) | data[offset + 1]


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pcap", required=True, help="classic PCAP capture to summarize")
    parser.add_argument(
        "--rules",
        default=str(default_rules_path()),
        help="plain domain blocklist (default: app/src/main/assets/anti-ad-domains.txt)",
    )
    parser.add_argument("--output", required=True, help="path for the sanitized JSON summary")
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    try:
        result = summarize_pcap(Path(args.pcap), Path(args.rules))
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as handle:
            json.dump(result, handle, ensure_ascii=True, indent=2, sort_keys=True)
            handle.write("\n")
        return 0
    except (CaptureError, OSError, UnicodeError):
        # Keep paths and capture contents out of console output as well as JSON.
        print("Unable to create DNS summary.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
