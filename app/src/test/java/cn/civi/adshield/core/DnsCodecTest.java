package cn.civi.adshield.core;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class DnsCodecTest {
    @Test
    public void parsesQuestionAndBuildsQuestionOnlyNoDataResponse() {
        byte[] query = query("ads.example.com", 1, 1, true);
        DnsCodec.Question question = DnsCodec.parseQuestion(query);
        assertEquals("ads.example.com", question.domain);
        assertEquals(1, question.type);
        assertEquals(1, question.questionClass);

        byte[] response = DnsCodec.blockedResponse(query);
        assertEquals(question.questionEnd, response.length);
        assertTrue((u16(response, 2) & 0x8080) == 0x8080); // QR and RA
        assertEquals(1, u16(response, 4));
        assertEquals(0, u16(response, 6));
        assertEquals(0, u16(response, 8));
        assertEquals(0, u16(response, 10));
        assertTrue(DnsCodec.isValidResponse(query, response));
    }

    @Test
    public void errorResponseSetsRcodeAndRejectsInvalidRcode() {
        byte[] query = query("example.com", 28, 1, false);
        byte[] response = DnsCodec.errorResponse(query, 3);
        assertEquals(3, u16(response, 2) & 0x0f);
        assertTrue(DnsCodec.isValidResponse(query, response));
        expectIllegalArgument(new Runnable() {
            @Override
            public void run() {
                DnsCodec.errorResponse(query, 16);
            }
        });
    }

    @Test
    public void rejectsMalformedQueriesAndCompressedNames() {
        final byte[] good = query("example.com", 1, 1, false);

        final byte[] responseAsQuery = good.clone();
        put16(responseAsQuery, 2, 0x8000);
        expectIllegalArgument(new Runnable() {
            @Override
            public void run() {
                DnsCodec.parseQuestion(responseAsQuery);
            }
        });

        final byte[] nonzeroOpcode = good.clone();
        put16(nonzeroOpcode, 2, 0x0800);
        expectIllegalArgument(new Runnable() {
            @Override
            public void run() {
                DnsCodec.parseQuestion(nonzeroOpcode);
            }
        });

        final byte[] wrongQuestionCount = good.clone();
        put16(wrongQuestionCount, 4, 2);
        expectIllegalArgument(new Runnable() {
            @Override
            public void run() {
                DnsCodec.parseQuestion(wrongQuestionCount);
            }
        });

        final byte[] compressedQuestion = new byte[18];
        put16(compressedQuestion, 4, 1);
        compressedQuestion[12] = (byte) 0xc0;
        compressedQuestion[13] = 12; // Self-reference, rejected before dereferencing.
        put16(compressedQuestion, 14, 1);
        put16(compressedQuestion, 16, 1);
        expectIllegalArgument(new Runnable() {
            @Override
            public void run() {
                DnsCodec.parseQuestion(compressedQuestion);
            }
        });

        final byte[] truncated = new byte[good.length - 1];
        System.arraycopy(good, 0, truncated, 0, truncated.length);
        expectIllegalArgument(new Runnable() {
            @Override
            public void run() {
                DnsCodec.parseQuestion(truncated);
            }
        });
    }

    @Test
    public void validatesResponseIdQuestionAndPacketBounds() {
        byte[] query = query("Example.COM", 1, 1, false);
        byte[] response = DnsCodec.blockedResponse(query);
        int nameLength = response.length - 16;
        // DNS names are ASCII on the wire; lower-case the QNAME in the response.
        for (int i = 12; i < 12 + nameLength; i++) {
            if (response[i] >= 'A' && response[i] <= 'Z') {
                response[i] = (byte) (response[i] + ('a' - 'A'));
            }
        }
        assertTrue(DnsCodec.isValidResponse(query, response));

        byte[] wrongId = response.clone();
        wrongId[1]++;
        assertFalse(DnsCodec.isValidResponse(query, wrongId));

        byte[] wrongQuestion = response.clone();
        int typeOffset = DnsCodec.parseQuestion(query).questionEnd - 4;
        put16(wrongQuestion, typeOffset, 28);
        assertFalse(DnsCodec.isValidResponse(query, wrongQuestion));

        byte[] truncatedRecord = response.clone();
        put16(truncatedRecord, 6, 1); // Claims one answer without adding its bytes.
        assertFalse(DnsCodec.isValidResponse(query, truncatedRecord));
    }

    @Test
    public void rejectsCompressionLoopsInResponses() {
        byte[] query = query("example.com", 1, 1, false);
        byte[] response = new byte[18];
        put16(response, 0, u16(query, 0));
        put16(response, 2, 0x8000);
        put16(response, 4, 1);
        response[12] = (byte) 0xc0;
        response[13] = 12;
        put16(response, 14, 1);
        put16(response, 16, 1);
        assertFalse(DnsCodec.isValidResponse(query, response));
    }

    @Test
    public void acceptsCorrelatedTruncatedResponseWithoutParsingPartialRecordBody() {
        byte[] query = query("example.com", 1, 1, false);
        byte[] response = DnsCodec.blockedResponse(query);
        byte[] withPartialRecord = new byte[response.length + 5];
        System.arraycopy(response, 0, withPartialRecord, 0, response.length);
        int recordStart = response.length;
        withPartialRecord[recordStart] = (byte) 0xc0;
        withPartialRecord[recordStart + 1] = 12; // Owner points to the question.
        put16(withPartialRecord, 6, 1);
        assertFalse(DnsCodec.isValidResponse(query, withPartialRecord));

        put16(withPartialRecord, 2, u16(withPartialRecord, 2) | 0x0200);
        assertTrue(DnsCodec.isValidResponse(query, withPartialRecord));
    }

    private static byte[] query(String domain, int type, int qclass, boolean withOpt) {
        String[] labels = domain.split("\\.");
        int nameLength = 1;
        for (String label : labels) {
            nameLength += 1 + label.length();
        }
        byte[] query = new byte[12 + nameLength + 4 + (withOpt ? 11 : 0)];
        put16(query, 0, 0x1234);
        put16(query, 2, 0x0100); // RD
        put16(query, 4, 1);
        put16(query, 10, withOpt ? 1 : 0);
        int cursor = 12;
        for (String label : labels) {
            query[cursor++] = (byte) label.length();
            for (int i = 0; i < label.length(); i++) {
                query[cursor++] = (byte) label.charAt(i);
            }
        }
        query[cursor++] = 0;
        put16(query, cursor, type);
        put16(query, cursor + 2, qclass);
        cursor += 4;
        if (withOpt) {
            query[cursor++] = 0; // root owner
            put16(query, cursor, 41);
            put16(query, cursor + 2, 1232);
            put16(query, cursor + 4, 0);
            put16(query, cursor + 6, 0);
        }
        return query;
    }

    private static void expectIllegalArgument(Runnable action) {
        try {
            action.run();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertNotNull(expected.getMessage());
        }
    }

    private static int u16(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 8) | (bytes[offset + 1] & 0xff);
    }

    private static void put16(byte[] bytes, int offset, int value) {
        bytes[offset] = (byte) (value >>> 8);
        bytes[offset + 1] = (byte) value;
    }
}
