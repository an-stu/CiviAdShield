package cn.civi.adshield.core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Small stateful IPv4 TCP endpoint for DNS traffic addressed to 10.111.0.2:53.
 *
 * <p>Use one dedicated background executor for calls to this class. It handles one DNS message
 * per TCP connection, keeps at most 32 sessions, and does not schedule retransmission timers.
 * Retransmission is limited to a duplicate request or a duplicate ACK for a known outstanding
 * response segment. Sessions remain available to acknowledge the client's FIN until it arrives
 * or the 15-second idle timeout expires.</p>
 */
public final class TcpDnsEndpoint {
    private static final byte[] DNS_ADDRESS = new byte[] {10, 111, 0, 2};
    private static final int IPV4_HEADER_LENGTH = 20;
    private static final int TCP_HEADER_LENGTH = 20;
    private static final int DESTINATION_PORT = 53;
    private static final int MAX_SESSIONS = 32;
    private static final long IDLE_TIMEOUT_MS = 15_000L;
    private static final int MAX_DNS_MESSAGE_LENGTH = 4096;
    private static final int MAX_RESPONSE_LENGTH = 65_535;
    private static final int MAX_TCP_PAYLOAD = 1200;
    private static final int MAX_CACHED_RESPONSE_BYTES = 64 * 1024;
    private static final int TCP_SYN = 0x02;
    private static final int TCP_RST = 0x04;
    private static final int TCP_PSH = 0x08;
    private static final int TCP_ACK = 0x10;
    private static final int TCP_FIN = 0x01;

    private final Resolver resolver;
    private final Sink sink;
    private final SecureRandom random = new SecureRandom();
    private final Map<FlowKey, Session> sessions = new HashMap<>();
    private int nextIpId;
    private boolean closed;

    /** Resolves one validated DNS query and returns a DNS response message. */
    public interface Resolver {
        byte[] resolve(byte[] query) throws IOException;
    }

    /** Receives complete IPv4 packets that this endpoint wants to transmit. */
    public interface Sink {
        void send(byte[] packet) throws IOException;
    }

    public TcpDnsEndpoint(Resolver resolver, Sink sink) {
        if (resolver == null || sink == null) {
            throw new IllegalArgumentException("resolver and sink are required");
        }
        this.resolver = resolver;
        this.sink = sink;
    }

    /**
     * Accepts one IPv4 packet. Malformed, unsupported, unrelated, and out-of-session packets are
     * silently dropped. Resolver I/O failures become DNS SERVFAIL responses; sink failures are
     * propagated as {@link IOException}.
     */
    public synchronized void accept(byte[] ipv4Packet, int length, long nowMillis)
            throws IOException {
        expireIdleSessions(nowMillis);
        if (closed || ipv4Packet == null || length < IPV4_HEADER_LENGTH
                || length > ipv4Packet.length) {
            return;
        }

        ParsedPacket packet = parsePacket(ipv4Packet, length);
        if (packet == null || packet.destinationPort != DESTINATION_PORT
                || !isDnsAddress(packet.destinationAddress)) {
            return;
        }

        FlowKey key = new FlowKey(packet.sourceAddress, packet.sourcePort);
        Session session = sessions.get(key);
        int flags = packet.flags;

        if ((flags & TCP_SYN) != 0 && (flags & TCP_ACK) == 0
                && (flags & (TCP_RST | TCP_FIN)) == 0 && packet.payloadLength == 0) {
            handleSyn(key, packet, session, nowMillis);
            return;
        }
        if (session == null) {
            return;
        }

        if ((flags & TCP_RST) != 0) {
            handleReset(key, session, packet);
            return;
        }
        if ((flags & TCP_SYN) != 0) {
            // Only an exact retransmission of the client's opening SYN is meaningful.
            if ((flags & TCP_ACK) == 0 && packet.sequence == session.clientInitialSequence
                    && packet.payloadLength == 0 && session.synAckPacket != null) {
                touch(session, nowMillis);
                sink.send(session.synAckPacket.clone());
            }
            return;
        }

        if (session.state == Session.STATE_SYN_RECEIVED) {
            handleFinalHandshake(key, session, packet, nowMillis);
        } else {
            handleEstablished(key, session, packet, nowMillis);
        }
    }

    /** Clears all connection state and makes future accepts inert. */
    public synchronized void close() {
        closed = true;
        sessions.clear();
    }

    private void handleSyn(FlowKey key, ParsedPacket packet, Session current, long nowMillis)
            throws IOException {
        if (current != null && packet.sequence == current.clientInitialSequence
                && current.synAckPacket != null) {
            touch(current, nowMillis);
            sink.send(current.synAckPacket.clone());
            return;
        }
        if (current == null && sessions.size() >= MAX_SESSIONS) {
            return;
        }

        Session session = new Session(key, packet.sequence, random.nextInt(), nowMillis);
        byte[] synAck = buildPacket(session, session.serverInitialSequence,
                session.clientNextSequence, TCP_SYN | TCP_ACK, null, 0, 0);
        session.synAckPacket = synAck;
        sessions.put(key, session);
        sink.send(synAck.clone());
    }

    private void handleFinalHandshake(FlowKey key, Session session, ParsedPacket packet,
                                      long nowMillis) throws IOException {
        if ((packet.flags & TCP_ACK) == 0 || packet.sequence != session.clientNextSequence
                || packet.acknowledgment != session.serverNextSequence) {
            return;
        }
        session.state = Session.STATE_ESTABLISHED;
        session.serverAcknowledgedSequence = packet.acknowledgment;
        touch(session, nowMillis);

        if (packet.payloadLength > 0) {
            boolean accepted = acceptInOrderData(session, packet, nowMillis);
            if (!accepted) {
                sessions.remove(key);
                return;
            }
        }
        if ((packet.flags & TCP_FIN) != 0) {
            acceptClientFin(key, session, packet, nowMillis);
        }
    }

    private void handleEstablished(FlowKey key, Session session, ParsedPacket packet,
                                   long nowMillis) throws IOException {
        if ((packet.flags & TCP_ACK) == 0 || !isValidAcknowledgment(session,
                packet.acknowledgment)) {
            return;
        }
        if (packet.payloadLength == 0 && (packet.flags & TCP_FIN) == 0
                && packet.sequence != session.clientNextSequence) {
            return;
        }

        boolean duplicateAck = packet.acknowledgment == session.serverAcknowledgedSequence;
        if (!duplicateAck) {
            session.serverAcknowledgedSequence = packet.acknowledgment;
        }
        touch(session, nowMillis);

        if (packet.payloadLength > 0) {
            if (packet.sequence == session.clientNextSequence) {
                boolean accepted = acceptInOrderData(session, packet, nowMillis);
                if (!accepted) {
                    sessions.remove(key);
                    return;
                }
            } else if (isExactDuplicateData(session, packet)) {
                if (hasCachedResponse(session)) {
                    sendResponseFrom(session, 0);
                } else {
                    sendAck(session);
                }
            } else {
                // No out-of-order buffering: request the next in-order client byte.
                sendAck(session);
            }
        } else if (packet.payloadLength == 0 && duplicateAck
                && (packet.flags & TCP_FIN) == 0 && hasCachedResponse(session)) {
            int firstOutstanding = responseSegmentContaining(session,
                    packet.acknowledgment);
            if (firstOutstanding >= 0) {
                sendResponseFrom(session, firstOutstanding);
            }
        }

        if ((packet.flags & TCP_FIN) != 0) {
            acceptClientFin(key, session, packet, nowMillis);
        }
    }

    private boolean acceptInOrderData(Session session, ParsedPacket packet, long nowMillis)
            throws IOException {
        if (session.queryResolved) {
            sendAck(session);
            return false;
        }

        int existingLength = session.request.size();
        if ((long) existingLength + packet.payloadLength > MAX_DNS_MESSAGE_LENGTH + 2L) {
            sendAck(session);
            return false;
        }
        byte[] chunk = packet.payloadBytes();
        session.request.write(chunk, 0, chunk.length);
        session.clientNextSequence += packet.payloadLength;
        touch(session, nowMillis);

        byte[] requestBytes = session.request.toByteArray();
        if (requestBytes.length >= 2 && session.expectedDnsLength < 0) {
            session.expectedDnsLength = u16(requestBytes, 0);
            if (session.expectedDnsLength == 0
                    || session.expectedDnsLength > MAX_DNS_MESSAGE_LENGTH) {
                sendAck(session);
                return false;
            }
        }

        if (session.expectedDnsLength < 0
                || requestBytes.length < session.expectedDnsLength + 2) {
            sendAck(session);
            return true;
        }
        if (requestBytes.length != session.expectedDnsLength + 2) {
            sendAck(session);
            return false;
        }

        byte[] query = Arrays.copyOfRange(requestBytes, 2, requestBytes.length);
        try {
            DnsCodec.parseQuestion(query);
        } catch (IllegalArgumentException malformedDns) {
            session.queryResolved = true;
            sendAck(session);
            return true;
        }

        session.queryResolved = true;
        byte[] response;
        try {
            response = resolver.resolve(query.clone());
        } catch (IOException resolverFailure) {
            response = DnsCodec.errorResponse(query, 2); // SERVFAIL
        }
        if (response == null || response.length == 0 || response.length > MAX_RESPONSE_LENGTH
                || !DnsCodec.isValidResponse(query, response)) {
            sendAck(session);
            return true;
        }
        session.responseLength = response.length;
        session.responseStartSequence = session.serverNextSequence;
        cacheResponsePacketsIfBounded(session, response);
        if (session.responsePackets == null) {
            // Large responses retain only their DNS body; packet headers are regenerated on retry.
            session.responseDns = response.clone();
        }
        session.serverNextSequence = session.responseStartSequence + response.length + 3;
        sendResponseFrom(session, 0);
        return true;
    }

    private void acceptClientFin(FlowKey key, Session session, ParsedPacket packet,
                                 long nowMillis) throws IOException {
        int finSequence = packet.sequence + packet.payloadLength;
        if (finSequence != session.clientNextSequence) {
            sendAck(session);
            return;
        }
        session.clientNextSequence = finSequence + 1;
        touch(session, nowMillis);
        sendAck(session);
        sessions.remove(key);
    }

    private void handleReset(FlowKey key, Session session, ParsedPacket packet) {
        if (packet.sequence != session.clientNextSequence) {
            return;
        }
        if ((packet.flags & TCP_ACK) != 0
                && !isValidAcknowledgment(session, packet.acknowledgment)) {
            return;
        }
        sessions.remove(key);
    }

    private void sendAck(Session session) throws IOException {
        byte[] packet = buildPacket(session, session.serverNextSequence,
                session.clientNextSequence, TCP_ACK, null, 0, 0);
        sink.send(packet);
    }

    /** Resends cached packets, or regenerates bounded segments from the cached DNS body. */
    private void sendResponseFrom(Session session, int firstSegment) throws IOException {
        if (!hasCachedResponse(session)) {
            return;
        }
        if (session.responsePackets != null) {
            if (firstSegment < 0 || firstSegment >= session.responsePackets.length) {
                return;
            }
            for (int index = firstSegment; index < session.responsePackets.length; index++) {
                sink.send(session.responsePackets[index].clone());
            }
            return;
        }

        int streamLength = session.responseLength + 2;
        int segmentCount = (streamLength + MAX_TCP_PAYLOAD - 1) / MAX_TCP_PAYLOAD;
        if (firstSegment < 0 || firstSegment >= segmentCount) {
            return;
        }

        int offset = firstSegment * MAX_TCP_PAYLOAD;
        for (int segment = firstSegment; offset < streamLength; segment++) {
            int payloadLength = Math.min(MAX_TCP_PAYLOAD, streamLength - offset);
            boolean last = offset + payloadLength == streamLength;
            int flags = TCP_ACK | TCP_PSH | (last ? TCP_FIN : 0);
            int sequence = session.responseStartSequence + offset;
            byte[] payload = responseStreamRange(session, offset, payloadLength);
            byte[] packet = buildPacket(session, sequence, session.clientNextSequence,
                    flags, payload, 0, payload.length);
            sink.send(packet);
            offset += payloadLength;
        }
    }

    private int responseSegmentContaining(Session session, int acknowledgment) {
        if (!hasCachedResponse(session)) {
            return -1;
        }
        int streamLength = session.responseLength + 2;
        int segmentCount = (streamLength + MAX_TCP_PAYLOAD - 1) / MAX_TCP_PAYLOAD;
        for (int segment = 0; segment < segmentCount; segment++) {
            int offset = segment * MAX_TCP_PAYLOAD;
            int payloadLength = Math.min(MAX_TCP_PAYLOAD, streamLength - offset);
            boolean last = offset + payloadLength == streamLength;
            int sequence = session.responseStartSequence + offset;
            long consumed = payloadLength + (last ? 1L : 0L);
            if (sequenceDistance(sequence, acknowledgment) < consumed) {
                return segment;
            }
        }
        return -1;
    }

    private byte[] responseStreamRange(Session session, int offset, int length) {
        return responseStreamRange(session.responseDns, session.responseLength, offset, length);
    }

    private void cacheResponsePacketsIfBounded(Session session, byte[] response) {
        int streamLength = response.length + 2;
        int segmentCount = (streamLength + MAX_TCP_PAYLOAD - 1) / MAX_TCP_PAYLOAD;
        long cachedBytes = streamLength
                + (long) segmentCount * (IPV4_HEADER_LENGTH + TCP_HEADER_LENGTH);
        if (cachedBytes > MAX_CACHED_RESPONSE_BYTES) {
            return;
        }

        byte[][] packets = new byte[segmentCount][];
        int offset = 0;
        for (int index = 0; index < segmentCount; index++) {
            int payloadLength = Math.min(MAX_TCP_PAYLOAD, streamLength - offset);
            boolean last = offset + payloadLength == streamLength;
            int flags = TCP_ACK | TCP_PSH | (last ? TCP_FIN : 0);
            byte[] payload = responseStreamRange(response, response.length, offset,
                    payloadLength);
            packets[index] = buildPacket(session, session.responseStartSequence + offset,
                    session.clientNextSequence, flags, payload, 0, payload.length);
            offset += payloadLength;
        }
        session.responsePackets = packets;
    }

    private boolean hasCachedResponse(Session session) {
        return session.responsePackets != null || session.responseDns != null;
    }

    private byte[] responseStreamRange(byte[] response, int responseLength,
                                       int offset, int length) {
        byte[] result = new byte[length];
        for (int index = 0; index < length; index++) {
            int streamIndex = offset + index;
            if (streamIndex == 0) {
                result[index] = (byte) (responseLength >>> 8);
            } else if (streamIndex == 1) {
                result[index] = (byte) responseLength;
            } else {
                result[index] = response[streamIndex - 2];
            }
        }
        return result;
    }

    private boolean isExactDuplicateData(Session session, ParsedPacket packet) {
        if (packet.payloadLength == 0 || session.request.size() == 0) {
            return false;
        }
        long offsetLong = sequenceDistance(session.clientInitialSequence + 1,
                packet.sequence);
        if (offsetLong > Integer.MAX_VALUE) {
            return false;
        }
        int offset = (int) offsetLong;
        if (offset < 0 || (long) offset + packet.payloadLength > session.request.size()) {
            return false;
        }
        byte[] accepted = session.request.toByteArray();
        for (int index = 0; index < packet.payloadLength; index++) {
            if (accepted[offset + index] != packet.bytes[packet.payloadOffset + index]) {
                return false;
            }
        }
        return true;
    }

    private boolean isValidAcknowledgment(Session session, int acknowledgment) {
        long outstanding = sequenceDistance(session.serverAcknowledgedSequence,
                session.serverNextSequence);
        long acknowledged = sequenceDistance(session.serverAcknowledgedSequence,
                acknowledgment);
        return acknowledged <= outstanding;
    }

    private void expireIdleSessions(long nowMillis) {
        Iterator<Session> iterator = sessions.values().iterator();
        while (iterator.hasNext()) {
            Session session = iterator.next();
            if (nowMillis >= session.lastActivityAt
                    && nowMillis - session.lastActivityAt >= IDLE_TIMEOUT_MS) {
                iterator.remove();
            }
        }
    }

    private void touch(Session session, long nowMillis) {
        if (nowMillis > session.lastActivityAt) {
            session.lastActivityAt = nowMillis;
        }
    }

    private byte[] buildPacket(Session session, int sequence, int acknowledgment, int flags,
                               byte[] payload, int payloadOffset, int payloadLength) {
        int totalLength = IPV4_HEADER_LENGTH + TCP_HEADER_LENGTH + payloadLength;
        byte[] packet = new byte[totalLength];
        packet[0] = 0x45;
        put16(packet, 2, totalLength);
        put16(packet, 4, nextIpId++ & 0xffff);
        put16(packet, 6, 0x4000); // Don't fragment.
        packet[8] = 64;
        packet[9] = 6;
        System.arraycopy(DNS_ADDRESS, 0, packet, 12, 4);
        putAddress(packet, 16, session.key.sourceAddress);
        put16(packet, 10, ipv4Checksum(packet, 0, IPV4_HEADER_LENGTH));

        int tcpOffset = IPV4_HEADER_LENGTH;
        put16(packet, tcpOffset, DESTINATION_PORT);
        put16(packet, tcpOffset + 2, session.key.sourcePort);
        put32(packet, tcpOffset + 4, sequence);
        put32(packet, tcpOffset + 8, acknowledgment);
        packet[tcpOffset + 12] = 0x50;
        packet[tcpOffset + 13] = (byte) flags;
        put16(packet, tcpOffset + 14, 8192);
        if (payloadLength > 0) {
            System.arraycopy(payload, payloadOffset, packet,
                    tcpOffset + TCP_HEADER_LENGTH, payloadLength);
        }
        int tcpLength = TCP_HEADER_LENGTH + payloadLength;
        int tcpChecksum = tcpChecksum(packet, 12, 16, tcpOffset, tcpLength);
        put16(packet, tcpOffset + 16, tcpChecksum == 0 ? 0xffff : tcpChecksum);
        return packet;
    }

    private ParsedPacket parsePacket(byte[] bytes, int length) {
        if ((bytes[0] & 0xf0) != 0x40) {
            return null;
        }
        int ipHeaderLength = (bytes[0] & 0x0f) * 4;
        if (ipHeaderLength < IPV4_HEADER_LENGTH || ipHeaderLength > length) {
            return null;
        }
        int totalLength = u16(bytes, 2);
        if (totalLength < ipHeaderLength + TCP_HEADER_LENGTH || totalLength > length
                || bytes[9] != 6) {
            return null;
        }
        int fragment = u16(bytes, 6);
        if ((fragment & 0x8000) != 0 || (fragment & 0x3fff) != 0
                || fold(addWords(bytes, 0, ipHeaderLength, 0)) != 0xffff) {
            return null;
        }
        byte[] sourceAddress = Arrays.copyOfRange(bytes, 12, 16);
        byte[] destinationAddress = Arrays.copyOfRange(bytes, 16, 20);
        int tcpOffset = ipHeaderLength;
        int tcpLength = totalLength - ipHeaderLength;
        int tcpHeaderLength = ((bytes[tcpOffset + 12] & 0xf0) >>> 4) * 4;
        if (tcpHeaderLength < TCP_HEADER_LENGTH || tcpHeaderLength > tcpLength
                || !validTcpChecksum(bytes, 12, 16, tcpOffset, tcpLength)) {
            return null;
        }
        int sourcePort = u16(bytes, tcpOffset);
        int destinationPort = u16(bytes, tcpOffset + 2);
        if (sourcePort == 0) {
            return null;
        }
        int payloadOffset = tcpOffset + tcpHeaderLength;
        int payloadLength = totalLength - payloadOffset;
        return new ParsedPacket(bytes, sourceAddress, destinationAddress, sourcePort,
                destinationPort, u32(bytes, tcpOffset + 4), u32(bytes, tcpOffset + 8),
                bytes[tcpOffset + 13] & 0xff, payloadOffset, payloadLength);
    }

    private boolean isDnsAddress(byte[] address) {
        return address.length == DNS_ADDRESS.length
                && address[0] == DNS_ADDRESS[0] && address[1] == DNS_ADDRESS[1]
                && address[2] == DNS_ADDRESS[2] && address[3] == DNS_ADDRESS[3];
    }

    private static boolean validTcpChecksum(byte[] bytes, int sourceOffset,
                                            int destinationOffset, int tcpOffset,
                                            int tcpLength) {
        long sum = 0;
        sum = addWords(bytes, sourceOffset, 8, sum);
        sum += 6;
        sum += tcpLength;
        sum = addWords(bytes, tcpOffset, tcpLength, sum);
        return fold(sum) == 0xffff;
    }

    private static int tcpChecksum(byte[] bytes, int sourceOffset, int destinationOffset,
                                   int tcpOffset, int tcpLength) {
        long sum = 0;
        sum = addWords(bytes, sourceOffset, 8, sum);
        sum += 6;
        sum += tcpLength;
        sum = addWords(bytes, tcpOffset, tcpLength, sum);
        return (~fold(sum)) & 0xffff;
    }

    private static int ipv4Checksum(byte[] bytes, int offset, int length) {
        return (~fold(addWords(bytes, offset, length, 0))) & 0xffff;
    }

    private static long addWords(byte[] bytes, int offset, int length, long initial) {
        long sum = initial;
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

    private static long sequenceDistance(int start, int end) {
        return (end - start) & 0xffffffffL;
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

    private static void putAddress(byte[] bytes, int offset, int address) {
        put32(bytes, offset, address);
    }

    private static final class ParsedPacket {
        final byte[] bytes;
        final byte[] sourceAddress;
        final byte[] destinationAddress;
        final int sourcePort;
        final int destinationPort;
        final int sequence;
        final int acknowledgment;
        final int flags;
        final int payloadOffset;
        final int payloadLength;

        ParsedPacket(byte[] bytes, byte[] sourceAddress, byte[] destinationAddress,
                     int sourcePort, int destinationPort, int sequence, int acknowledgment,
                     int flags, int payloadOffset, int payloadLength) {
            this.bytes = bytes;
            this.sourceAddress = sourceAddress;
            this.destinationAddress = destinationAddress;
            this.sourcePort = sourcePort;
            this.destinationPort = destinationPort;
            this.sequence = sequence;
            this.acknowledgment = acknowledgment;
            this.flags = flags;
            this.payloadOffset = payloadOffset;
            this.payloadLength = payloadLength;
        }

        byte[] payloadBytes() {
            return Arrays.copyOfRange(bytes, payloadOffset, payloadOffset + payloadLength);
        }
    }

    private static final class FlowKey {
        final int sourceAddress;
        final int sourcePort;

        FlowKey(byte[] sourceAddress, int sourcePort) {
            this.sourceAddress = u32(sourceAddress, 0);
            this.sourcePort = sourcePort;
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) {
                return true;
            }
            if (!(other instanceof FlowKey)) {
                return false;
            }
            FlowKey that = (FlowKey) other;
            return sourceAddress == that.sourceAddress && sourcePort == that.sourcePort;
        }

        @Override
        public int hashCode() {
            return 31 * sourceAddress + sourcePort;
        }
    }

    private static final class Session {
        static final int STATE_SYN_RECEIVED = 1;
        static final int STATE_ESTABLISHED = 2;

        final FlowKey key;
        final int clientInitialSequence;
        final int serverInitialSequence;
        final ByteArrayOutputStream request = new ByteArrayOutputStream();
        int clientNextSequence;
        int serverNextSequence;
        int serverAcknowledgedSequence;
        int state = STATE_SYN_RECEIVED;
        int expectedDnsLength = -1;
        long lastActivityAt;
        boolean queryResolved;
        byte[] synAckPacket;
        byte[] responseDns;
        byte[][] responsePackets;
        int responseLength;
        int responseStartSequence;

        Session(FlowKey key, int clientInitialSequence, int serverInitialSequence,
                long nowMillis) {
            this.key = key;
            this.clientInitialSequence = clientInitialSequence;
            this.serverInitialSequence = serverInitialSequence;
            this.clientNextSequence = clientInitialSequence + 1;
            this.serverNextSequence = serverInitialSequence + 1;
            this.serverAcknowledgedSequence = serverInitialSequence + 1;
            this.lastActivityAt = nowMillis;
        }
    }
}
