package cn.civi.adshield.core;

import org.junit.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class TcpDnsEndpointTest {
    private static final byte[] CLIENT_IP = new byte[] {(byte) 192, 0, 2, 10};
    private static final byte[] DNS_IP = new byte[] {10, 111, 0, 2};
    private static final int CLIENT_PORT = 53_321;
    private static final int CLIENT_ISN = 0x12345678;

    @Test
    public void performsChecksumValidSynHandshakeAndResendsDuplicateSynAck() throws Exception {
        final List<byte[]> sent = new ArrayList<>();
        TcpDnsEndpoint endpoint = endpoint(new AtomicInteger(), sent);
        byte[] syn = clientPacket(CLIENT_IP, CLIENT_PORT, CLIENT_ISN, 0, 0x02, null);

        endpoint.accept(syn, syn.length, 100);
        assertEquals(1, sent.size());
        TcpFields synAck = assertValidServerPacket(sent.get(0));
        assertEquals(0x12, synAck.flags);
        assertEquals(CLIENT_ISN + 1, synAck.acknowledgment);
        assertEquals(8192, synAck.window);
        assertEquals(53, synAck.sourcePort);
        assertEquals(CLIENT_PORT, synAck.destinationPort);
        assertArrayEquals(DNS_IP, Arrays.copyOfRange(sent.get(0), 12, 16));
        assertArrayEquals(CLIENT_IP, Arrays.copyOfRange(sent.get(0), 16, 20));

        endpoint.accept(syn, syn.length, 101);
        assertEquals(2, sent.size());
        assertArrayEquals(sent.get(0), sent.get(1));

        byte[] finalAck = clientPacket(CLIENT_IP, CLIENT_PORT, CLIENT_ISN + 1,
                synAck.sequence + 1, 0x10, null);
        endpoint.accept(finalAck, finalAck.length, 102);
        assertEquals(2, sent.size());
    }

    @Test
    public void acceptsSplitDnsRequestAndSegmentsResponseWithChecksums() throws Exception {
        final List<byte[]> sent = new ArrayList<>();
        final AtomicInteger resolutions = new AtomicInteger();
        final byte[] query = query("example.com");
        TcpDnsEndpoint endpoint = new TcpDnsEndpoint(new TcpDnsEndpoint.Resolver() {
            @Override
            public byte[] resolve(byte[] request) {
                resolutions.incrementAndGet();
                assertArrayEquals(query, request);
                return largeResponse(request);
            }
        }, sink(sent));

        TcpFields handshake = connect(endpoint, sent, CLIENT_IP, CLIENT_PORT, CLIENT_ISN, 200);
        byte[] framed = frame(query);
        int dataSequence = CLIENT_ISN + 1;
        int split = 7;

        byte[] firstPart = clientPacket(CLIENT_IP, CLIENT_PORT, dataSequence,
                handshake.sequence + 1, 0x18, Arrays.copyOfRange(framed, 0, split));
        int beforeFirstPart = sent.size();
        endpoint.accept(firstPart, firstPart.length, 201);
        assertEquals(beforeFirstPart + 1, sent.size());
        TcpFields partialAck = assertValidServerPacket(sent.get(sent.size() - 1));
        assertEquals(0x10, partialAck.flags);
        assertEquals(dataSequence + split, partialAck.acknowledgment);
        assertEquals(0, resolutions.get());

        byte[] rest = Arrays.copyOfRange(framed, split, framed.length);
        byte[] secondPart = clientPacket(CLIENT_IP, CLIENT_PORT, dataSequence + split,
                handshake.sequence + 1, 0x18, rest);
        int beforeResponse = sent.size();
        endpoint.accept(secondPart, secondPart.length, 202);
        assertEquals(1, resolutions.get());
        assertTrue(sent.size() >= beforeResponse + 2);

        List<TcpFields> responseSegments = new ArrayList<>();
        ByteArrayCollector responseStream = new ByteArrayCollector();
        for (int index = beforeResponse; index < sent.size(); index++) {
            TcpFields fields = assertValidServerPacket(sent.get(index));
            assertTrue((fields.flags & 0x18) == 0x18); // ACK | PSH
            assertTrue(fields.payload.length <= 1200);
            responseSegments.add(fields);
            responseStream.write(fields.payload);
        }
        assertEquals(0x19, responseSegments.get(responseSegments.size() - 1).flags);
        for (int index = 1; index < responseSegments.size(); index++) {
            TcpFields previous = responseSegments.get(index - 1);
            assertEquals(previous.sequence + previous.payload.length,
                    responseSegments.get(index).sequence);
        }

        byte[] framedResponse = responseStream.toByteArray();
        int dnsLength = u16(framedResponse, 0);
        byte[] response = Arrays.copyOfRange(framedResponse, 2, framedResponse.length);
        assertEquals(dnsLength, response.length);
        assertTrue(DnsCodec.isValidResponse(query, response));
        assertEquals(1, resolutions.get());
    }

    @Test
    public void duplicateRequestAndDuplicateAckResendWithoutResolvingAgain() throws Exception {
        final List<byte[]> sent = new ArrayList<>();
        final AtomicInteger resolutions = new AtomicInteger();
        final byte[] query = query("duplicate.example");
        TcpDnsEndpoint endpoint = new TcpDnsEndpoint(new TcpDnsEndpoint.Resolver() {
            @Override
            public byte[] resolve(byte[] request) {
                resolutions.incrementAndGet();
                return largeResponse(request);
            }
        }, sink(sent));

        TcpFields handshake = connect(endpoint, sent, CLIENT_IP, CLIENT_PORT, CLIENT_ISN, 300);
        byte[] framed = frame(query);
        int dataSequence = CLIENT_ISN + 1;
        byte[] requestPacket = clientPacket(CLIENT_IP, CLIENT_PORT, dataSequence,
                handshake.sequence + 1, 0x18, framed);
        endpoint.accept(requestPacket, requestPacket.length, 301);
        int firstResponsePacketCount = sent.size() - 1;
        assertTrue(firstResponsePacketCount >= 2);
        assertEquals(1, resolutions.get());

        endpoint.accept(requestPacket, requestPacket.length, 302);
        assertEquals(1, resolutions.get());
        assertEquals(1 + firstResponsePacketCount * 2, sent.size());
        for (int index = 0; index < firstResponsePacketCount; index++) {
            assertArrayEquals(sent.get(1 + index), sent.get(1 + firstResponsePacketCount + index));
        }

        int serverEnd = handshake.sequence + 1 + largeResponse(query).length + 3;
        byte[] duplicateAck = clientPacket(CLIENT_IP, CLIENT_PORT,
                dataSequence + framed.length, handshake.sequence + 1, 0x10, null);
        endpoint.accept(duplicateAck, duplicateAck.length, 303);
        assertEquals(1 + firstResponsePacketCount * 3, sent.size());
        assertEquals(1, resolutions.get());
        for (int index = 0; index < firstResponsePacketCount; index++) {
            assertArrayEquals(sent.get(1 + index),
                    sent.get(1 + firstResponsePacketCount * 2 + index));
        }

        byte[] responseAck = clientPacket(CLIENT_IP, CLIENT_PORT,
                dataSequence + framed.length, serverEnd, 0x10, null);
        endpoint.accept(responseAck, responseAck.length, 304);
        int beforeFinAck = sent.size();
        byte[] fin = clientPacket(CLIENT_IP, CLIENT_PORT,
                dataSequence + framed.length, serverEnd, 0x11, null);
        endpoint.accept(fin, fin.length, 305);
        assertEquals(beforeFinAck + 1, sent.size());
        TcpFields finAck = assertValidServerPacket(sent.get(sent.size() - 1));
        assertEquals(0x10, finAck.flags);
        assertEquals(dataSequence + framed.length + 1, finAck.acknowledgment);
    }

    @Test
    public void rejectsBadIpAndTcpChecksumsBeforeCreatingSession() throws Exception {
        final List<byte[]> sent = new ArrayList<>();
        TcpDnsEndpoint endpoint = endpoint(new AtomicInteger(), sent);
        byte[] badIp = clientPacket(CLIENT_IP, CLIENT_PORT, CLIENT_ISN, 0, 0x02, null);
        badIp[8] ^= 0x01;
        endpoint.accept(badIp, badIp.length, 400);
        assertTrue(sent.isEmpty());

        byte[] badTcp = clientPacket(CLIENT_IP, CLIENT_PORT, CLIENT_ISN, 0, 0x02, null);
        badTcp[24] ^= 0x01;
        endpoint.accept(badTcp, badTcp.length, 401);
        assertTrue(sent.isEmpty());

        byte[] validSyn = clientPacket(CLIENT_IP, CLIENT_PORT, CLIENT_ISN, 0, 0x02, null);
        endpoint.accept(validSyn, validSyn.length, 402);
        assertEquals(1, sent.size());
        assertValidServerPacket(sent.get(0));
    }

    @Test
    public void limitsSessionsAndLazilyExpiresThemAfterFifteenSeconds() throws Exception {
        final List<byte[]> sent = new ArrayList<>();
        TcpDnsEndpoint endpoint = endpoint(new AtomicInteger(), sent);
        for (int index = 0; index < 32; index++) {
            int port = 20_000 + index;
            byte[] syn = clientPacket(CLIENT_IP, port, CLIENT_ISN + index, 0, 0x02, null);
            endpoint.accept(syn, syn.length, 1_000L + index);
        }
        assertEquals(32, sent.size());

        byte[] overflowSyn = clientPacket(CLIENT_IP, 30_000, CLIENT_ISN + 100, 0, 0x02, null);
        endpoint.accept(overflowSyn, overflowSyn.length, 1_100);
        assertEquals(32, sent.size());

        endpoint.accept(overflowSyn, overflowSyn.length, 17_001);
        assertEquals(33, sent.size());
    }

    @Test
    public void outOfOrderDataGetsCurrentExpectedAcknowledgmentAndBadAckIsIgnored()
            throws Exception {
        final List<byte[]> sent = new ArrayList<>();
        TcpDnsEndpoint endpoint = endpoint(new AtomicInteger(), sent);
        TcpFields handshake = connect(endpoint, sent, CLIENT_IP, CLIENT_PORT, CLIENT_ISN, 500);
        int dataSequence = CLIENT_ISN + 1;

        byte[] badAck = clientPacket(CLIENT_IP, CLIENT_PORT, dataSequence,
                handshake.sequence + 100, 0x10, null);
        endpoint.accept(badAck, badAck.length, 501);
        assertEquals(1, sent.size());

        byte[] outOfOrder = clientPacket(CLIENT_IP, CLIENT_PORT, dataSequence + 4,
                handshake.sequence + 1, 0x18, new byte[] {1, 2, 3});
        endpoint.accept(outOfOrder, outOfOrder.length, 502);
        assertEquals(2, sent.size());
        TcpFields ack = assertValidServerPacket(sent.get(1));
        assertEquals(dataSequence, ack.acknowledgment);
        assertEquals(0x10, ack.flags);
    }

    @Test
    public void resolverFailureReturnsValidatedServfailInsteadOfLeavingQueryHanging()
            throws Exception {
        final List<byte[]> sent = new ArrayList<>();
        final byte[] query = query("resolver-error.example");
        TcpDnsEndpoint endpoint = new TcpDnsEndpoint(new TcpDnsEndpoint.Resolver() {
            @Override
            public byte[] resolve(byte[] request) throws IOException {
                throw new IOException("upstream unavailable");
            }
        }, sink(sent));

        TcpFields handshake = connect(endpoint, sent, CLIENT_IP, CLIENT_PORT, CLIENT_ISN, 600);
        byte[] framedQuery = frame(query);
        byte[] request = clientPacket(CLIENT_IP, CLIENT_PORT, CLIENT_ISN + 1,
                handshake.sequence + 1, 0x18, framedQuery);
        endpoint.accept(request, request.length, 602);

        assertEquals(2, sent.size());
        TcpFields servfailPacket = assertValidServerPacket(sent.get(1));
        assertEquals(0x19, servfailPacket.flags);
        assertEquals(0x0002, u16(servfailPacket.payload, 4) & 0x000f);
        byte[] servfail = Arrays.copyOfRange(servfailPacket.payload, 2,
                servfailPacket.payload.length);
        assertTrue(DnsCodec.isValidResponse(query, servfail));
    }

    private static TcpDnsEndpoint endpoint(final AtomicInteger resolutions,
                                           final List<byte[]> sent) {
        return new TcpDnsEndpoint(new TcpDnsEndpoint.Resolver() {
            @Override
            public byte[] resolve(byte[] query) {
                resolutions.incrementAndGet();
                return DnsCodec.errorResponse(query, 3);
            }
        }, sink(sent));
    }

    private static TcpDnsEndpoint.Sink sink(final List<byte[]> sent) {
        return new TcpDnsEndpoint.Sink() {
            @Override
            public void send(byte[] packet) {
                sent.add(packet.clone());
            }
        };
    }

    private static TcpFields connect(TcpDnsEndpoint endpoint, List<byte[]> sent,
                                     byte[] sourceAddress, int sourcePort, int clientIsn,
                                     long nowMillis) throws IOException {
        byte[] syn = clientPacket(sourceAddress, sourcePort, clientIsn, 0, 0x02, null);
        endpoint.accept(syn, syn.length, nowMillis);
        TcpFields synAck = assertValidServerPacket(sent.get(sent.size() - 1));
        byte[] ack = clientPacket(sourceAddress, sourcePort, clientIsn + 1,
                synAck.sequence + 1, 0x10, null);
        endpoint.accept(ack, ack.length, nowMillis + 1);
        return synAck;
    }

    private static byte[] clientPacket(byte[] sourceAddress, int sourcePort, int sequence,
                                       int acknowledgment, int flags, byte[] payload) {
        byte[] data = payload == null ? new byte[0] : payload;
        int totalLength = 40 + data.length;
        byte[] packet = new byte[totalLength];
        packet[0] = 0x45;
        put16(packet, 2, totalLength);
        put16(packet, 4, 0x4321);
        put16(packet, 6, 0x4000);
        packet[8] = 64;
        packet[9] = 6;
        System.arraycopy(sourceAddress, 0, packet, 12, 4);
        System.arraycopy(DNS_IP, 0, packet, 16, 4);
        put16(packet, 10, checksum(packet, 0, 20));

        put16(packet, 20, sourcePort);
        put16(packet, 22, 53);
        put32(packet, 24, sequence);
        put32(packet, 28, acknowledgment);
        packet[32] = 0x50;
        packet[33] = (byte) flags;
        put16(packet, 34, 8192);
        if (data.length > 0) {
            System.arraycopy(data, 0, packet, 40, data.length);
        }
        int tcpChecksum = tcpChecksum(packet, 20, 20 + data.length);
        put16(packet, 36, tcpChecksum == 0 ? 0xffff : tcpChecksum);
        return packet;
    }

    private static TcpFields assertValidServerPacket(byte[] packet) {
        assertTrue(packet.length >= 40);
        assertEquals(0x45, packet[0] & 0xff);
        int totalLength = u16(packet, 2);
        assertEquals(totalLength, packet.length);
        assertEquals(6, packet[9] & 0xff);
        assertEquals(0xffff, fold(addWords(packet, 0, 20, 0)));
        int tcpLength = totalLength - 20;
        long sum = addWords(packet, 12, 8, 0);
        sum += 6;
        sum += tcpLength;
        sum = addWords(packet, 20, tcpLength, sum);
        assertEquals(0xffff, fold(sum));
        assertArrayEquals(DNS_IP, Arrays.copyOfRange(packet, 12, 16));

        TcpFields fields = new TcpFields();
        fields.sourcePort = u16(packet, 20);
        fields.destinationPort = u16(packet, 22);
        fields.sequence = u32(packet, 24);
        fields.acknowledgment = u32(packet, 28);
        fields.flags = packet[33] & 0xff;
        fields.window = u16(packet, 34);
        fields.payload = Arrays.copyOfRange(packet, 40, totalLength);
        return fields;
    }

    private static byte[] query(String domain) {
        String[] labels = domain.split("\\.");
        int nameLength = 1;
        for (String label : labels) {
            nameLength += 1 + label.length();
        }
        byte[] query = new byte[12 + nameLength + 4];
        put16(query, 0, 0x5152);
        put16(query, 2, 0x0100);
        put16(query, 4, 1);
        int cursor = 12;
        for (String label : labels) {
            query[cursor++] = (byte) label.length();
            for (int index = 0; index < label.length(); index++) {
                query[cursor++] = (byte) label.charAt(index);
            }
        }
        query[cursor++] = 0;
        put16(query, cursor, 1);
        put16(query, cursor + 2, 1);
        return query;
    }

    private static byte[] largeResponse(byte[] query) {
        int questionEnd = DnsCodec.parseQuestion(query).questionEnd;
        int rdataLength = 1_500;
        byte[] response = new byte[questionEnd + 12 + rdataLength];
        System.arraycopy(query, 0, response, 0, questionEnd);
        put16(response, 2, 0x8180);
        put16(response, 6, 1);
        put16(response, 8, 0);
        put16(response, 10, 0);

        int cursor = questionEnd;
        response[cursor++] = (byte) 0xc0;
        response[cursor++] = 12;
        put16(response, cursor, 16); // TXT
        put16(response, cursor + 2, 1);
        cursor += 4;
        cursor += 4; // TTL
        put16(response, cursor, rdataLength);
        cursor += 2;
        Arrays.fill(response, cursor, response.length, (byte) 0x41);
        assertTrue(DnsCodec.isValidResponse(query, response));
        return response;
    }

    private static byte[] frame(byte[] query) {
        byte[] framed = new byte[query.length + 2];
        put16(framed, 0, query.length);
        System.arraycopy(query, 0, framed, 2, query.length);
        return framed;
    }

    private static int tcpChecksum(byte[] packet, int tcpOffset, int tcpLength) {
        long sum = addWords(packet, 12, 8, 0);
        sum += 6;
        sum += tcpLength;
        sum = addWords(packet, tcpOffset, tcpLength, sum);
        return (~fold(sum)) & 0xffff;
    }

    private static int checksum(byte[] packet, int offset, int length) {
        return (~fold(addWords(packet, offset, length, 0))) & 0xffff;
    }

    private static long addWords(byte[] bytes, int offset, int length, long sum) {
        int cursor = offset;
        int end = offset + length;
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

    private static int u16(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 8) | (bytes[offset + 1] & 0xff);
    }

    private static int u32(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 24)
                | ((bytes[offset + 1] & 0xff) << 16)
                | ((bytes[offset + 2] & 0xff) << 8)
                | (bytes[offset + 3] & 0xff);
    }

    private static void put16(byte[] bytes, int offset, int value) {
        bytes[offset] = (byte) (value >>> 8);
        bytes[offset + 1] = (byte) value;
    }

    private static void put32(byte[] bytes, int offset, int value) {
        bytes[offset] = (byte) (value >>> 24);
        bytes[offset + 1] = (byte) (value >>> 16);
        bytes[offset + 2] = (byte) (value >>> 8);
        bytes[offset + 3] = (byte) value;
    }

    private static final class TcpFields {
        int sourcePort;
        int destinationPort;
        int sequence;
        int acknowledgment;
        int flags;
        int window;
        byte[] payload;
    }

    private static final class ByteArrayCollector {
        private final java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();

        void write(byte[] bytes) {
            output.write(bytes, 0, bytes.length);
        }

        byte[] toByteArray() {
            return output.toByteArray();
        }
    }
}
