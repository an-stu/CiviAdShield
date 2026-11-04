package cn.civi.adshield.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Small, dependency-free DNS wire-format helpers for UDP DNS messages. */
public final class DnsCodec {
    private static final int DNS_HEADER_LENGTH = 12;
    private static final int MAX_NAME_LENGTH = 255;
    private static final int TYPE_CNAME = 5;
    private static final int CLASS_IN = 1;
    private static final int MAX_CNAME_HOPS = 64;

    private DnsCodec() {
    }

    /** Parsed DNS question. {@code questionEnd} is the first byte after QCLASS. */
    public static final class Question {
        public final String domain;
        public final int type;
        public final int questionClass;
        public final int questionEnd;

        private Question(String domain, int type, int questionClass, int questionEnd) {
            this.domain = domain;
            this.type = type;
            this.questionClass = questionClass;
            this.questionEnd = questionEnd;
        }
    }

    /**
     * Parses a standard DNS query containing exactly one question.
     *
     * @throws IllegalArgumentException if the message is malformed, is a response,
     *                                  uses a nonzero opcode, or has a compressed question name
     */
    public static Question parseQuestion(byte[] message) {
        requireMessage(message);
        if (message.length < DNS_HEADER_LENGTH || message.length > 65535) {
            throw malformed("truncated DNS header");
        }
        int flags = u16(message, 2);
        if ((flags & 0x8000) != 0) {
            throw malformed("DNS message is a response");
        }
        if ((flags & 0x7800) != 0) {
            throw malformed("unsupported DNS opcode");
        }
        if (u16(message, 4) != 1) {
            throw malformed("DNS query must contain exactly one question");
        }

        Name name = readName(message, DNS_HEADER_LENGTH, false);
        int cursor = name.end;
        if (cursor > message.length - 4) {
            throw malformed("truncated DNS question");
        }
        int type = u16(message, cursor);
        int qclass = u16(message, cursor + 2);
        int questionEnd = cursor + 4;

        cursor = validateResourceRecords(message, questionEnd, u16(message, 6));
        cursor = validateResourceRecords(message, cursor, u16(message, 8));
        cursor = validateResourceRecords(message, cursor, u16(message, 10));
        if (cursor != message.length) {
            throw malformed("trailing bytes after DNS sections");
        }
        return new Question(name.domain, type, qclass, questionEnd);
    }

    /** Returns a NOERROR/NODATA response containing only the original question. */
    public static byte[] blockedResponse(byte[] query) {
        return errorResponse(query, 0);
    }

    /** Returns a response with the specified four-bit DNS RCODE and no resource records. */
    public static byte[] errorResponse(byte[] query, int rcode) {
        if (rcode < 0 || rcode > 15) {
            throw new IllegalArgumentException("DNS RCODE must be between 0 and 15");
        }
        Question question = parseQuestion(query);
        byte[] response = new byte[question.questionEnd];
        System.arraycopy(query, 0, response, 0, response.length);

        int queryFlags = u16(query, 2);
        // Preserve RD and CD, set QR and RA, and return the requested RCODE.
        int responseFlags = 0x8000 | 0x0080 | (queryFlags & (0x0100 | 0x0010)) | rcode;
        put16(response, 2, responseFlags);
        put16(response, 4, 1);
        put16(response, 6, 0);
        put16(response, 8, 0);
        put16(response, 10, 0);
        return response;
    }

    /**
     * Checks whether {@code response} is a structurally valid DNS response to {@code query}.
     * The DNS ID, opcode, and single question must match; names are compared case-insensitively.
     */
    public static boolean isValidResponse(byte[] query, byte[] response) {
        try {
            Question q = parseQuestion(query);
            if (response == null || response.length < DNS_HEADER_LENGTH || response.length > 65535) {
                return false;
            }
            int flags = u16(response, 2);
            if ((flags & 0x8000) == 0 || (flags & 0x7800) != 0
                    || (flags & 0x7800) != (u16(query, 2) & 0x7800)
                    || u16(response, 0) != u16(query, 0)
                    || u16(response, 4) != 1) {
                return false;
            }

            Name name = readName(response, DNS_HEADER_LENGTH, true);
            int cursor = name.end;
            if (cursor > response.length - 4) {
                return false;
            }
            int type = u16(response, cursor);
            int qclass = u16(response, cursor + 2);
            if (!name.domain.equalsIgnoreCase(q.domain) || type != q.type || qclass != q.questionClass) {
                return false;
            }
            cursor += 4;
            // TC explicitly marks an incomplete DNS body. Correlate the header and question,
            // then leave any possibly cut-off resource record uninterpreted.
            if ((flags & 0x0200) != 0) {
                return true;
            }
            cursor = validateResourceRecords(response, cursor, u16(response, 6));
            cursor = validateResourceRecords(response, cursor, u16(response, 8));
            cursor = validateResourceRecords(response, cursor, u16(response, 10));
            return cursor == response.length;
        } catch (IllegalArgumentException ignored) {
            return false;
        }
    }

    /**
     * Returns the CNAME targets reachable from the original question through answer records.
     * Only IN-class CNAME records in the answer section participate. A response must first
     * correlate structurally with the query; truncated or negative responses have no targets.
     *
     * @throws IllegalArgumentException if the response is not valid for {@code query}, a CNAME
     *                                  RDATA is malformed, records conflict, or the reachable
     *                                  chain loops or exceeds 64 hops
     */
    public static List<String> cnameTargets(byte[] query, byte[] response) {
        if (!isValidResponse(query, response)) {
            throw malformed("DNS response is not valid for query");
        }

        int flags = u16(response, 2);
        if ((flags & 0x0200) != 0 || (flags & 0x000f) != 0) {
            return Collections.emptyList();
        }

        Question question = parseQuestion(query);
        Name responseQuestion = readName(response, DNS_HEADER_LENGTH, true);
        int cursor = responseQuestion.end;
        if (cursor > response.length - 4) {
            throw malformed("truncated DNS response question");
        }
        cursor += 4;

        Map<String, String> cnameByOwner = new HashMap<>();
        int answerCount = u16(response, 6);
        for (int i = 0; i < answerCount; i++) {
            Name owner = readName(response, cursor, true);
            cursor = owner.end;
            if (cursor > response.length - 10) {
                throw malformed("truncated DNS answer record");
            }
            int type = u16(response, cursor);
            int recordClass = u16(response, cursor + 2);
            int rdLength = u16(response, cursor + 8);
            cursor += 10;
            if (rdLength > response.length - cursor) {
                throw malformed("truncated DNS answer data");
            }

            if (type == TYPE_CNAME && recordClass == CLASS_IN) {
                Name target = readName(response, cursor, true);
                if (target.end - cursor != rdLength) {
                    throw malformed("CNAME RDLENGTH does not match encoded target name");
                }
                String ownerName = owner.domain.toLowerCase(Locale.ROOT);
                String targetName = target.domain.toLowerCase(Locale.ROOT);
                String previous = cnameByOwner.get(ownerName);
                if (previous != null && !previous.equals(targetName)) {
                    throw malformed("conflicting CNAME targets for one owner");
                }
                if (previous == null) {
                    cnameByOwner.put(ownerName, targetName);
                }
            }
            cursor += rdLength;
        }

        String current = question.domain.toLowerCase(Locale.ROOT);
        Set<String> visited = new HashSet<>();
        visited.add(current);
        List<String> targets = new ArrayList<>();
        for (int hop = 0; hop < MAX_CNAME_HOPS; hop++) {
            String target = cnameByOwner.get(current);
            if (target == null) {
                return targets.isEmpty() ? Collections.emptyList()
                        : Collections.unmodifiableList(targets);
            }
            if (!visited.add(target)) {
                throw malformed("CNAME chain contains a cycle");
            }
            targets.add(target);
            current = target;
        }
        if (cnameByOwner.containsKey(current)) {
            throw malformed("CNAME chain exceeds 64 hops");
        }
        return targets.isEmpty() ? Collections.emptyList() : Collections.unmodifiableList(targets);
    }

    private static int validateResourceRecords(byte[] message, int cursor, int count) {
        for (int i = 0; i < count; i++) {
            Name owner = readName(message, cursor, true);
            cursor = owner.end;
            if (cursor > message.length - 10) {
                throw malformed("truncated DNS resource record");
            }
            int rdLength = u16(message, cursor + 8);
            cursor += 10;
            if (rdLength > message.length - cursor) {
                throw malformed("truncated DNS resource data");
            }
            cursor += rdLength;
        }
        return cursor;
    }

    private static Name readName(byte[] message, int start, boolean allowCompression) {
        if (start < 0 || start >= message.length) {
            throw malformed("DNS name starts outside message");
        }
        StringBuilder domain = new StringBuilder();
        int cursor = start;
        int consumedEnd = -1;
        int expandedLength = 1; // terminating root label
        int labelCount = 0;
        int pointerHops = 0;
        boolean jumped = false;

        while (true) {
            if (cursor >= message.length) {
                throw malformed("unterminated DNS name");
            }
            int length = message[cursor] & 0xff;
            if ((length & 0xc0) == 0xc0) {
                if (!allowCompression || cursor + 1 >= message.length) {
                    throw malformed("compressed or truncated DNS question name");
                }
                int target = ((length & 0x3f) << 8) | (message[cursor + 1] & 0xff);
                if (target >= cursor || target >= message.length) {
                    throw malformed("invalid DNS compression pointer");
                }
                if (!jumped) {
                    consumedEnd = cursor + 2;
                    jumped = true;
                }
                cursor = target;
                if (++pointerHops > 128) {
                    throw malformed("DNS compression chain is too long");
                }
                continue;
            }
            if ((length & 0xc0) != 0) {
                throw malformed("unsupported DNS label encoding");
            }
            cursor++;
            if (length == 0) {
                if (!jumped) {
                    consumedEnd = cursor;
                }
                break;
            }
            if (length > 63 || cursor > message.length - length) {
                throw malformed("invalid or truncated DNS label");
            }
            expandedLength += 1 + length;
            if (expandedLength > MAX_NAME_LENGTH) {
                throw malformed("DNS name is too long");
            }
            if (labelCount++ > 0) {
                domain.append('.');
            }
            for (int i = 0; i < length; i++) {
                int character = message[cursor + i] & 0xff;
                if (character < 0x21 || character > 0x7e || character == '.') {
                    throw malformed("DNS label is not printable ASCII");
                }
                domain.append((char) character);
            }
            cursor += length;
        }
        if (labelCount == 0) {
            domain.append('.');
        }
        return new Name(domain.toString(), consumedEnd);
    }

    private static void requireMessage(byte[] message) {
        if (message == null) {
            throw malformed("DNS message is null");
        }
    }

    private static IllegalArgumentException malformed(String message) {
        return new IllegalArgumentException(message);
    }

    static int u16(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 8) | (bytes[offset + 1] & 0xff);
    }

    static void put16(byte[] bytes, int offset, int value) {
        bytes[offset] = (byte) (value >>> 8);
        bytes[offset + 1] = (byte) value;
    }

    private static final class Name {
        final String domain;
        final int end;

        Name(String domain, int end) {
            this.domain = domain.toLowerCase(Locale.ROOT);
            this.end = end;
        }
    }
}
