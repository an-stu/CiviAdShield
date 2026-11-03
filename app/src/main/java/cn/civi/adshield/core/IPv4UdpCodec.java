package cn.civi.adshield.core;

/** IPv4/UDP packet parser and reply builder for complete, unfragmented datagrams. */
public final class IPv4UdpCodec {
    private static final int IPV4_HEADER_MIN = 20;
    private static final int UDP_HEADER_LENGTH = 8;
    private static final int MAX_DNS_PAYLOAD = 4096;

    private IPv4UdpCodec() {
    }

    public static final class Packet {
        public final byte[] sourceAddress;
        public final byte[] destinationAddress;
        public final int sourcePort;
        public final int destinationPort;
        public final byte[] payload;

        private Packet(byte[] sourceAddress, byte[] destinationAddress,
                       int sourcePort, int destinationPort, byte[] payload) {
            this.sourceAddress = sourceAddress;
            this.destinationAddress = destinationAddress;
            this.sourcePort = sourcePort;
            this.destinationPort = destinationPort;
            this.payload = payload;
        }
    }

    /** Parses one IPv4 UDP datagram from the first {@code length} bytes of the buffer. */
    public static Packet parse(byte[] bytes, int length) {
        if (bytes == null || length < IPV4_HEADER_MIN || length > bytes.length) {
            throw malformed("truncated IPv4 header");
        }
        int first = bytes[0] & 0xff;
        if ((first >>> 4) != 4) {
            throw malformed("not an IPv4 packet");
        }
        int headerLength = (first & 0x0f) * 4;
        if (headerLength < IPV4_HEADER_MIN || length < headerLength) {
            throw malformed("invalid IPv4 header length");
        }
        int totalLength = u16(bytes, 2);
        if (totalLength < headerLength + UDP_HEADER_LENGTH
                || totalLength > length) {
            throw malformed("invalid IPv4 total length");
        }
        if (bytes[9] != 17) {
            throw malformed("IPv4 packet is not UDP");
        }
        int fragment = u16(bytes, 6);
        if ((fragment & 0x8000) != 0 || (fragment & 0x3fff) != 0) {
            throw malformed("fragmented IPv4 packets are unsupported");
        }
        if (checksum(bytes, 0, headerLength) != 0) {
            throw malformed("invalid IPv4 header checksum");
        }

        int udpOffset = headerLength;
        int udpLength = u16(bytes, udpOffset + 4);
        if (udpLength < UDP_HEADER_LENGTH || udpLength != totalLength - headerLength) {
            throw malformed("invalid UDP length");
        }
        int udpChecksum = u16(bytes, udpOffset + 6);
        if (udpChecksum != 0 && !validUdpChecksum(bytes, 12,
                udpOffset, udpLength)) {
            throw malformed("invalid UDP checksum");
        }

        byte[] source = copy(bytes, 12, 4);
        byte[] destination = copy(bytes, 16, 4);
        int sourcePort = u16(bytes, udpOffset);
        int destinationPort = u16(bytes, udpOffset + 2);
        byte[] payload = copy(bytes, udpOffset + UDP_HEADER_LENGTH,
                udpLength - UDP_HEADER_LENGTH);
        return new Packet(source, destination, sourcePort, destinationPort, payload);
    }

    /** Builds a complete IPv4 UDP datagram replying to the supplied packet. */
    public static byte[] reply(Packet request, byte[] payload) {
        if (request == null || payload == null) {
            throw new IllegalArgumentException("request and payload are required");
        }
        if (payload.length > MAX_DNS_PAYLOAD) {
            throw new IllegalArgumentException("DNS UDP payload exceeds 4096 bytes");
        }
        if (request.sourceAddress == null || request.destinationAddress == null
                || request.sourceAddress.length != 4 || request.destinationAddress.length != 4
                || request.sourcePort < 0 || request.sourcePort > 65535
                || request.destinationPort < 0 || request.destinationPort > 65535) {
            throw new IllegalArgumentException("invalid request packet fields");
        }

        int udpLength = UDP_HEADER_LENGTH + payload.length;
        int totalLength = IPV4_HEADER_MIN + udpLength;
        byte[] reply = new byte[totalLength];
        reply[0] = 0x45;
        put16(reply, 2, totalLength);
        put16(reply, 4, 0);
        put16(reply, 6, 0x4000);
        reply[8] = 64;
        reply[9] = 17;
        System.arraycopy(request.destinationAddress, 0, reply, 12, 4);
        System.arraycopy(request.sourceAddress, 0, reply, 16, 4);
        put16(reply, 10, checksum(reply, 0, IPV4_HEADER_MIN));

        int udpOffset = IPV4_HEADER_MIN;
        put16(reply, udpOffset, request.destinationPort);
        put16(reply, udpOffset + 2, request.sourcePort);
        put16(reply, udpOffset + 4, udpLength);
        System.arraycopy(payload, 0, reply, udpOffset + UDP_HEADER_LENGTH, payload.length);
        int udpChecksum = udpChecksum(reply, udpOffset, udpLength);
        put16(reply, udpOffset + 6, udpChecksum == 0 ? 0xffff : udpChecksum);
        return reply;
    }

    private static boolean validUdpChecksum(byte[] bytes, int sourceAddressOffset,
                                           int udpOffset, int udpLength) {
        long sum = 0;
        sum = addWords(bytes, sourceAddressOffset, 8, sum);
        sum += 17;
        sum += udpLength;
        sum = addWords(bytes, udpOffset, udpLength, sum);
        return fold(sum) == 0xffff;
    }

    private static int udpChecksum(byte[] packet, int udpOffset, int udpLength) {
        long sum = 0;
        sum = addWords(packet, 12, 8, sum);
        sum += 17;
        sum += udpLength;
        sum = addWords(packet, udpOffset, udpLength, sum);
        return (~fold(sum)) & 0xffff;
    }

    private static int checksum(byte[] bytes, int offset, int length) {
        return (~fold(addWords(bytes, offset, length, 0))) & 0xffff;
    }

    private static long addWords(byte[] bytes, int offset, int length, long initial) {
        long sum = initial;
        int end = offset + length;
        int cursor = offset;
        while (cursor + 1 < end) {
            sum += ((bytes[cursor] & 0xff) << 8) | (bytes[cursor + 1] & 0xff);
            cursor += 2;
        }
        if (cursor < end) {
            sum += (bytes[cursor] & 0xff) << 8;
        }
        return sum;
    }

    private static int fold(long sum) {
        while ((sum >>> 16) != 0) {
            sum = (sum & 0xffff) + (sum >>> 16);
        }
        return (int) sum;
    }

    private static byte[] copy(byte[] bytes, int offset, int length) {
        byte[] result = new byte[length];
        System.arraycopy(bytes, offset, result, 0, length);
        return result;
    }

    private static int u16(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 8) | (bytes[offset + 1] & 0xff);
    }

    private static void put16(byte[] bytes, int offset, int value) {
        bytes[offset] = (byte) (value >>> 8);
        bytes[offset + 1] = (byte) value;
    }

    private static IllegalArgumentException malformed(String message) {
        return new IllegalArgumentException(message);
    }
}
