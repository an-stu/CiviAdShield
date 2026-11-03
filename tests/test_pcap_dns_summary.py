import json
import importlib.util
import struct
import sys
import tempfile
import unittest
from pathlib import Path

SUMMARY_PATH = Path(__file__).resolve().parents[1] / "tools" / "pcap-dns-summary.py"
SUMMARY_SPEC = importlib.util.spec_from_file_location("pcap_dns_summary", SUMMARY_PATH)
summary = importlib.util.module_from_spec(SUMMARY_SPEC)
sys.modules[SUMMARY_SPEC.name] = summary
SUMMARY_SPEC.loader.exec_module(summary)


CLIENT_IP = bytes((192, 0, 2, 1))
DNS_IP = bytes((10, 111, 0, 2))
MAC_A = bytes.fromhex("aabbccddeeff")
MAC_B = bytes.fromhex("112233445566")


def dns_query(domain, qtype=1, transaction_id=0x1234):
    labels = domain.rstrip(".").split(".")
    qname = b"".join(bytes((len(label),)) + label.encode("ascii") for label in labels) + b"\0"
    return struct.pack(">HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", qtype, 1)


def dns_response(domain, qtype=1, rcode=0, answer_count=1, transaction_id=0x1234):
    query = dns_query(domain, qtype, transaction_id)
    header = struct.pack(">HHHHHH", transaction_id, 0x8180 | rcode, 1,
                         answer_count, 0, 0)
    question = query[12:]
    answer = b""
    for _ in range(answer_count):
        answer += b"\xc0\x0c" + struct.pack(">HHIH", qtype, 1, 60, 4) + b"\x01\x02\x03\x04"
    return header + question + answer


def compression_cycle_response(transaction_id=0x4444):
    return (struct.pack(">HHHHHH", transaction_id, 0x8180, 1, 0, 0, 0)
            + b"\xc0\x0c" + struct.pack(">HH", 1, 1))


def udp_segment(dns_payload, source_port=53000, destination_port=53):
    return struct.pack(">HHHH", source_port, destination_port,
                       8 + len(dns_payload), 0) + dns_payload


def ipv4_packet(udp, fragment=0):
    total_length = 20 + len(udp)
    header = bytearray(20)
    header[0] = 0x45
    struct.pack_into(">H", header, 2, total_length)
    struct.pack_into(">H", header, 4, 0x1111)
    struct.pack_into(">H", header, 6, fragment)
    header[8] = 64
    header[9] = 17
    header[12:16] = CLIENT_IP
    header[16:20] = DNS_IP
    # Checksum validation is outside this summary's scope; packet lengths and fragments are checked.
    return bytes(header) + udp


def ipv6_packet(udp, extension=None, fragment=False):
    if fragment:
        extension = bytes((17, 0, 0, 8, 0, 0, 0, 1))
        next_header = 44
    elif extension is not None:
        next_header = 0
    else:
        next_header = 17
    extension = extension or b""
    payload = extension + udp
    header = bytearray(40)
    header[0] = 0x60
    struct.pack_into(">H", header, 4, len(payload))
    header[6] = next_header
    header[7] = 64
    header[8:24] = bytes.fromhex("20010db8000000000000000000000001")
    header[24:40] = bytes.fromhex("20010db8000000000000000000000002")
    return bytes(header) + payload


def ethernet_frame(ip_packet, ethertype=0x0800, vlan=False):
    if vlan:
        return MAC_A + MAC_B + struct.pack(">H", 0x8100) + b"\0\x07" \
            + struct.pack(">H", ethertype) + ip_packet
    return MAC_A + MAC_B + struct.pack(">H", ethertype) + ip_packet


def cooked_frame(ip_packet, ethertype, version):
    if version == 1:
        header = struct.pack(">HHH", 0, 1, 6) + MAC_A + b"\0\0" + struct.pack(">H", ethertype)
    else:
        header = struct.pack(">H", ethertype) + b"\0\0" + struct.pack(">I", 1) \
            + struct.pack(">H", 1) + bytes((0, 6)) + MAC_A + b"\0\0"
    return header + ip_packet


def write_pcap(path, frames, linktype=1, snaplen=65535, endian="<", truncate_last=0):
    with path.open("wb") as handle:
        handle.write(struct.pack(endian + "IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))
        for index, frame in enumerate(frames):
            captured = len(frame)
            original = captured
            if truncate_last and index == len(frames) - 1:
                captured += truncate_last
            handle.write(struct.pack(endian + "IIII", index, 0, captured, original))
            handle.write(frame)


class PcapDnsSummaryTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.rules = self.root / "rules.txt"
        self.rules.write_text("# block rules\nexample.com\n# comment\n", encoding="utf-8")

    def tearDown(self):
        self.tempdir.cleanup()

    def summarize(self, frames, linktype=1, **kwargs):
        capture = self.root / "capture.pcap"
        write_pcap(capture, frames, linktype=linktype, **kwargs)
        return summary.summarize_pcap(capture, self.rules)

    def test_aggregates_queries_responses_types_rcodes_and_boundary_block_match(self):
        domain = "sub.example.com"
        frames = [
            ethernet_frame(ipv4_packet(udp_segment(dns_query(domain, 1)))),
            ethernet_frame(ipv4_packet(udp_segment(dns_response(domain, 1), 53, 53000))),
            ethernet_frame(ipv4_packet(udp_segment(dns_query(domain, 28)))),
        ]
        result = self.summarize(frames)

        self.assertEqual(3, result["packetCount"])
        self.assertEqual(0, result["malformedCount"])
        self.assertEqual(1, len(result["domains"]))
        row = result["domains"][0]
        self.assertEqual(domain, row["domain"])
        self.assertEqual(2, row["queries"])
        self.assertEqual(1, row["responses"])
        self.assertEqual({"A": 1, "AAAA": 1}, row["types"])
        self.assertEqual({"NOERROR": 1}, row["rcodes"])
        self.assertEqual({"1": 1}, row["answerCounts"])
        self.assertTrue(row["matchesBlocklist"])
        self.assertEqual(
            {"domain", "queries", "responses", "types", "rcodes", "answerCounts", "matchesBlocklist"},
            set(row),
        )

    def test_suffix_match_requires_label_boundary(self):
        self.assertTrue(summary.matches_blocklist("x.ads.example.com", {"example.com"}))
        self.assertTrue(summary.matches_blocklist("example.com", {"example.com"}))
        self.assertFalse(summary.matches_blocklist("notexample.com", {"example.com"}))

    def test_supports_vlan_raw_linux_cooked_v1_and_v2(self):
        query = dns_query("links.example")
        ip = ipv4_packet(udp_segment(query))
        frames_by_link = [
            (1, ethernet_frame(ip, vlan=True)),
            (101, ip),
            (113, cooked_frame(ip, 0x0800, version=1)),
            (276, cooked_frame(ip, 0x0800, version=2)),
        ]
        for linktype, frame in frames_by_link:
            with self.subTest(linktype=linktype):
                result = self.summarize([frame], linktype=linktype)
                self.assertEqual(0, result["malformedCount"])
                self.assertEqual(1, result["domains"][0]["queries"])

    def test_skips_ipv4_and_ipv6_udp_fragments_without_malformed_count(self):
        dns = dns_query("fragment.example")
        ipv4_fragment = ethernet_frame(ipv4_packet(udp_segment(dns), fragment=0x2000))
        ipv6_fragment = ethernet_frame(
            ipv6_packet(udp_segment(dns), fragment=True), ethertype=0x86DD
        )
        result = self.summarize([ipv4_fragment, ipv6_fragment])
        self.assertEqual(2, result["packetCount"])
        self.assertEqual(0, result["malformedCount"])
        self.assertEqual([], result["domains"])

    def test_skips_supported_ipv6_extension_chain(self):
        extension = bytes((17, 0, 0, 0, 0, 0, 0, 0))
        frame = ethernet_frame(
            ipv6_packet(udp_segment(dns_query("ipv6.example")), extension=extension),
            ethertype=0x86DD,
        )
        result = self.summarize([frame])
        self.assertEqual(0, result["malformedCount"])
        self.assertEqual("ipv6.example", result["domains"][0]["domain"])

    def test_counts_compression_loop_and_truncated_capture_as_malformed(self):
        bad_dns = ethernet_frame(ipv4_packet(udp_segment(compression_cycle_response(), 53, 53000)))
        capture = self.root / "malformed.pcap"
        write_pcap(capture, [bad_dns], linktype=1)
        with capture.open("ab") as handle:
            handle.write(struct.pack("<IIII", 1, 0, 50, 50))
            handle.write(b"\x00\x01\x02")
        result = summary.summarize_pcap(capture, self.rules)
        self.assertEqual(2, result["packetCount"])
        self.assertEqual(2, result["malformedCount"])
        self.assertEqual([], result["domains"])

    def test_counts_capture_lengths_over_snaplen_as_malformed(self):
        capture = self.root / "oversnap.pcap"
        write_pcap(capture, [b"\0" * 11], snaplen=10)
        result = summary.summarize_pcap(capture, self.rules)
        self.assertEqual(1, result["packetCount"])
        self.assertEqual(1, result["malformedCount"])

    def test_reads_big_endian_classic_pcap(self):
        frame = ethernet_frame(ipv4_packet(udp_segment(dns_query("big-endian.example"))))
        result = self.summarize([frame], endian=">")
        self.assertEqual("big-endian.example", result["domains"][0]["domain"])

    def test_cli_writes_only_sanitized_aggregate_fields(self):
        capture = self.root / "private.pcap"
        output = self.root / "summary.json"
        frame = ethernet_frame(ipv4_packet(udp_segment(dns_query("private.example"))), vlan=True)
        url_like_label = ethernet_frame(
            ipv4_packet(udp_segment(dns_query("http://secret.example")))
        )
        write_pcap(capture, [frame, url_like_label])
        status = summary.main(
            ["--pcap", str(capture), "--rules", str(self.rules), "--output", str(output)]
        )
        self.assertEqual(0, status)
        raw_json = output.read_text(encoding="utf-8")
        result = json.loads(raw_json)
        self.assertEqual({"packetCount", "malformedCount", "domains"}, set(result))
        for forbidden in (
            "192.0.2.1", "10.111.0.2", "aabbccddeeff", "transaction_id", "payload", "http://"
        ):
            self.assertNotIn(forbidden, raw_json)
        self.assertIn("private.example", raw_json)
        self.assertIn(r"http\\058\\047\\047secret.example", raw_json)


if __name__ == "__main__":
    unittest.main()
