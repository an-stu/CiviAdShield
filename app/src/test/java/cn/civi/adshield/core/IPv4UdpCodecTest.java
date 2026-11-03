package cn.civi.adshield.core;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class IPv4UdpCodecTest {
    @Test
    public void parsesAtOffsetAndBuildsReplyWithReversedAddressesAndValidChecksums() {
        byte[] requestBytes = datagram(new byte[]{1, 2, 3, 4});
        byte[] prefixed = new byte[requestBytes.length + 5];
        System.arraycopy(requestBytes, 0, prefixed, 0, requestBytes.length);
        IPv4UdpCodec.Packet request = IPv4UdpCodec.parse(prefixed, requestBytes.length);

        assertArrayEquals(new byte[]{10, 0, 0, 1}, request.sourceAddress);
        assertArrayEquals(new byte[]{8, 8, 8, 8}, request.destinationAddress);
        assertEquals(53000, request.sourcePort);
        assertEquals(53, request.destinationPort);
        assertArrayEquals(new byte[]{1, 2, 3, 4}, request.payload);

        byte[] replyBytes = IPv4UdpCodec.reply(request, new byte[]{9, 8, 7});
        IPv4UdpCodec.Packet reply = IPv4UdpCodec.parse(replyBytes, replyBytes.length);
        assertArrayEquals(request.destinationAddress, reply.sourceAddress);
        assertArrayEquals(request.sourceAddress, reply.destinationAddress);
        assertEquals(request.destinationPort, reply.sourcePort);
        assertEquals(request.sourcePort, reply.destinationPort);
        assertArrayEquals(new byte[]{9, 8, 7}, reply.payload);
    }

    @Test
    public void rejectsFragmentsLengthsAndBadChecksums() {
        final byte[] fragment = datagram(new byte[]{1});
        put16(fragment, 6, 0x2000); // More fragments.
        refreshIpChecksum(fragment);
        expectIllegalArgument(new Runnable() {
            @Override
            public void run() {
                IPv4UdpCodec.parse(fragment, fragment.length);
            }
        });

        final byte[] badIpChecksum = datagram(new byte[]{1});
        badIpChecksum[10] ^= 1;
        expectIllegalArgument(new Runnable() {
            @Override
            public void run() {
                IPv4UdpCodec.parse(badIpChecksum, badIpChecksum.length);
            }
        });

        final byte[] badUdpLength = datagram(new byte[]{1, 2});
        put16(badUdpLength, 24, 9);
        expectIllegalArgument(new Runnable() {
            @Override
            public void run() {
                IPv4UdpCodec.parse(badUdpLength, badUdpLength.length);
            }
        });

        final byte[] badUdpChecksum = datagram(new byte[]{1, 2});
        put16(badUdpChecksum, 26, 0x1234);
        expectIllegalArgument(new Runnable() {
            @Override
            public void run() {
                IPv4UdpCodec.parse(badUdpChecksum, badUdpChecksum.length);
            }
        });
    }

    @Test
    public void rejectsOversizedDnsPayloadInReply() {
        final byte[] bytes = datagram(new byte[0]);
        final IPv4UdpCodec.Packet packet = IPv4UdpCodec.parse(bytes, bytes.length);
        expectIllegalArgument(new Runnable() {
            @Override
            public void run() {
                IPv4UdpCodec.reply(packet, new byte[4097]);
            }
        });
    }

    @Test
    public void honorsSuppliedBufferLength() {
        final byte[] bytes = datagram(new byte[]{1, 2, 3});
        expectIllegalArgument(new Runnable() {
            @Override
            public void run() {
                IPv4UdpCodec.parse(bytes, bytes.length - 1);
            }
        });
        expectIllegalArgument(new Runnable() {
            @Override
            public void run() {
                IPv4UdpCodec.parse(bytes, bytes.length + 1);
            }
        });
    }

    private static byte[] datagram(byte[] payload) {
        int udpLength = 8 + payload.length;
        byte[] packet = new byte[20 + udpLength];
        packet[0] = 0x45;
        put16(packet, 2, packet.length);
        put16(packet, 4, 1);
        put16(packet, 6, 0x4000);
        packet[8] = 64;
        packet[9] = 17;
        packet[12] = 10;
        packet[15] = 1;
        packet[16] = 8;
        packet[17] = 8;
        packet[18] = 8;
        packet[19] = 8;
        put16(packet, 20, 53000);
        put16(packet, 22, 53);
        put16(packet, 24, udpLength);
        System.arraycopy(payload, 0, packet, 28, payload.length);
        refreshIpChecksum(packet);
        return packet;
    }

    private static void refreshIpChecksum(byte[] packet) {
        put16(packet, 10, 0);
        put16(packet, 10, checksum(packet, 0, 20));
    }

    private static int checksum(byte[] bytes, int offset, int length) {
        long sum = 0;
        for (int i = offset; i < offset + length; i += 2) {
            sum += ((bytes[i] & 0xff) << 8) | (bytes[i + 1] & 0xff);
        }
        while ((sum >>> 16) != 0) {
            sum = (sum & 0xffff) + (sum >>> 16);
        }
        return (~(int) sum) & 0xffff;
    }

    private static void expectIllegalArgument(Runnable action) {
        try {
            action.run();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            // expected
        }
    }

    private static void put16(byte[] bytes, int offset, int value) {
        bytes[offset] = (byte) (value >>> 8);
        bytes[offset + 1] = (byte) value;
    }
}
