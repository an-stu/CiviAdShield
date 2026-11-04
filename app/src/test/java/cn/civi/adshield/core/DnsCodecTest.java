package cn.civi.adshield.core;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

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

    @Test
    public void followsReachableCompressedCnameChainAndReturnsImmutableTargets() {
        byte[] query = query("ads.example.net", 1, 1, false);
        byte[] response = DnsCodec.blockedResponse(query);

        int firstTargetOffset = response.length + 2 + 10;
        byte[] firstTarget = encodeName("edge.example.net");
        response = appendRecord(response, pointer(12), 5, 1, firstTarget);

        // The second owner points to the first target. Its RDATA encodes "landing" plus a
        // compression pointer to the already encoded "example.net" suffix.
        int exampleSuffixOffset = firstTargetOffset + 5;
        byte[] secondTarget = labelAndPointer("landing", exampleSuffixOffset);
        response = appendRecord(response, pointer(firstTargetOffset), 5, 1, secondTarget);
        response = withCounts(response, 2, 0, 0);

        assertTrue(DnsCodec.isValidResponse(query, response));
        List<String> targets = DnsCodec.cnameTargets(query, response);
        assertEquals(Arrays.asList("edge.example.net", "landing.example.net"), targets);
        try {
            targets.add("unexpected.example");
            fail("CNAME target list must be immutable");
        } catch (UnsupportedOperationException expected) {
            // Expected: callers cannot mutate the returned chain.
        }
    }

    @Test
    public void onlyFollowsReachableAnswerCnames() {
        byte[] query = query("ads.example.com", 1, 1, false);
        byte[] response = DnsCodec.blockedResponse(query);
        response = appendRecord(response, encodeName("other.example.com"), 5, 1,
                encodeName("unrelated.example.net"));
        response = appendRecord(response, pointer(12), 5, 1, encodeName("landing.example.com"));
        // CNAME records in authority and additional sections are valid wire data but are not
        // part of the answer chain.
        response = appendRecord(response, pointer(12), 5, 1, encodeName("authority.example.net"));
        response = appendRecord(response, pointer(12), 5, 1, encodeName("additional.example.net"));
        response = withCounts(response, 2, 1, 1);

        assertTrue(DnsCodec.isValidResponse(query, response));
        assertEquals(Collections.singletonList("landing.example.com"),
                DnsCodec.cnameTargets(query, response));
    }

    @Test
    public void returnsEmptyForNoCnameTruncatedAndNegativeResponses() {
        byte[] query = query("ads.example.com", 1, 1, false);
        byte[] response = DnsCodec.blockedResponse(query);
        assertEquals(Collections.emptyList(), DnsCodec.cnameTargets(query, response));

        byte[] negative = response.clone();
        put16(negative, 2, u16(negative, 2) | 3); // NXDOMAIN
        assertTrue(DnsCodec.isValidResponse(query, negative));
        assertEquals(Collections.emptyList(), DnsCodec.cnameTargets(query, negative));

        byte[] truncated = new byte[response.length + 1];
        System.arraycopy(response, 0, truncated, 0, response.length);
        truncated[response.length] = (byte) 0xc0; // Partial compression pointer in truncated body.
        put16(truncated, 2, u16(truncated, 2) | 0x0200);
        put16(truncated, 6, 1);
        assertTrue(DnsCodec.isValidResponse(query, truncated));
        assertEquals(Collections.emptyList(), DnsCodec.cnameTargets(query, truncated));
    }

    @Test
    public void rejectsUncorrelatedResponses() {
        byte[] query = query("ads.example.com", 1, 1, false);
        byte[] response = DnsCodec.blockedResponse(query);
        response[0]++;
        assertFalse(DnsCodec.isValidResponse(query, response));
        expectIllegalArgument(new Runnable() {
            @Override
            public void run() {
                DnsCodec.cnameTargets(query, response);
            }
        });
    }

    @Test
    public void rejectsReachableCnameCyclesAndConflictingOwners() {
        byte[] query = query("a.example.com", 1, 1, false);
        byte[] cycle = DnsCodec.blockedResponse(query);
        cycle = appendRecord(cycle, encodeName("a.example.com"), 5, 1, encodeName("b.example.com"));
        cycle = appendRecord(cycle, encodeName("b.example.com"), 5, 1, encodeName("a.example.com"));
        cycle = withCounts(cycle, 2, 0, 0);
        assertTrue(DnsCodec.isValidResponse(query, cycle));
        final byte[] cyclicResponse = cycle;
        expectIllegalArgument(new Runnable() {
            @Override
            public void run() {
                DnsCodec.cnameTargets(query, cyclicResponse);
            }
        });

        byte[] conflicting = DnsCodec.blockedResponse(query);
        conflicting = appendRecord(conflicting, pointer(12), 5, 1, encodeName("one.example.net"));
        conflicting = appendRecord(conflicting, pointer(12), 5, 1, encodeName("two.example.net"));
        conflicting = withCounts(conflicting, 2, 0, 0);
        assertTrue(DnsCodec.isValidResponse(query, conflicting));
        final byte[] conflictingResponse = conflicting;
        expectIllegalArgument(new Runnable() {
            @Override
            public void run() {
                DnsCodec.cnameTargets(query, conflictingResponse);
            }
        });
    }

    @Test
    public void rejectsCnameRdataLengthMismatchAndInvalidCompressionPointers() {
        byte[] query = query("example.com", 1, 1, false);
        byte[] response = DnsCodec.blockedResponse(query);
        byte[] pointerAndExtraRootByte = concat(pointer(12), new byte[]{0});
        response = appendRecord(response, pointer(12), 5, 1, pointerAndExtraRootByte);
        // The extra zero byte begins a valid root-owned authority record, so the outer DNS
        // sections remain well-formed while the CNAME RDLENGTH is longer than its encoded name.
        response = appendRecord(response, new byte[]{0}, 2, 1, new byte[0]);
        response = withCounts(response, 1, 1, 0);
        assertTrue(DnsCodec.isValidResponse(query, response));
        final byte[] mismatchedLengthResponse = response;
        expectIllegalArgument(new Runnable() {
            @Override
            public void run() {
                DnsCodec.cnameTargets(query, mismatchedLengthResponse);
            }
        });

        byte[] selfPointerResponse = DnsCodec.blockedResponse(query);
        int rdataOffset = selfPointerResponse.length + 2 + 10;
        selfPointerResponse = appendRecord(selfPointerResponse, pointer(12), 5, 1,
                pointer(rdataOffset));
        selfPointerResponse = withCounts(selfPointerResponse, 1, 0, 0);
        assertTrue(DnsCodec.isValidResponse(query, selfPointerResponse));
        final byte[] invalidPointerResponse = selfPointerResponse;
        expectIllegalArgument(new Runnable() {
            @Override
            public void run() {
                DnsCodec.cnameTargets(query, invalidPointerResponse);
            }
        });

        byte[] outOfBoundsResponse = DnsCodec.blockedResponse(query);
        outOfBoundsResponse = appendRecord(outOfBoundsResponse, pointer(12), 5, 1, pointer(0x3fff));
        outOfBoundsResponse = withCounts(outOfBoundsResponse, 1, 0, 0);
        assertTrue(DnsCodec.isValidResponse(query, outOfBoundsResponse));
        final byte[] outOfBounds = outOfBoundsResponse;
        expectIllegalArgument(new Runnable() {
            @Override
            public void run() {
                DnsCodec.cnameTargets(query, outOfBounds);
            }
        });
    }

    @Test
    public void permitsSixtyFourCnameHopsButRejectsLongerChains() {
        byte[] query = query("n0.example.net", 1, 1, false);
        byte[] sixtyFour = cnameChainResponse(query, 64);
        assertTrue(DnsCodec.isValidResponse(query, sixtyFour));
        assertEquals(64, DnsCodec.cnameTargets(query, sixtyFour).size());

        byte[] sixtyFive = cnameChainResponse(query, 65);
        assertTrue(DnsCodec.isValidResponse(query, sixtyFive));
        expectIllegalArgument(new Runnable() {
            @Override
            public void run() {
                DnsCodec.cnameTargets(query, sixtyFive);
            }
        });
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

    private static byte[] cnameChainResponse(byte[] query, int hops) {
        byte[] response = DnsCodec.blockedResponse(query);
        for (int i = 0; i < hops; i++) {
            response = appendRecord(response, encodeName("n" + i + ".example.net"), 5, 1,
                    encodeName("n" + (i + 1) + ".example.net"));
        }
        return withCounts(response, hops, 0, 0);
    }

    private static byte[] appendRecord(byte[] packet, byte[] owner, int type, int recordClass,
                                       byte[] rdata) {
        return appendRecord(packet, owner, type, recordClass, rdata, rdata.length);
    }

    private static byte[] appendRecord(byte[] packet, byte[] owner, int type, int recordClass,
                                       byte[] rdata, int rdLength) {
        byte[] result = new byte[packet.length + owner.length + 10 + rdata.length];
        System.arraycopy(packet, 0, result, 0, packet.length);
        int cursor = packet.length;
        System.arraycopy(owner, 0, result, cursor, owner.length);
        cursor += owner.length;
        put16(result, cursor, type);
        put16(result, cursor + 2, recordClass);
        put16(result, cursor + 8, rdLength);
        System.arraycopy(rdata, 0, result, cursor + 10, rdata.length);
        return result;
    }

    private static byte[] withCounts(byte[] packet, int answers, int authorities, int additionals) {
        byte[] result = packet.clone();
        put16(result, 6, answers);
        put16(result, 8, authorities);
        put16(result, 10, additionals);
        return result;
    }

    private static byte[] encodeName(String domain) {
        if (".".equals(domain)) {
            return new byte[]{0};
        }
        String[] labels = domain.split("\\.");
        int length = 1;
        for (String label : labels) {
            length += 1 + label.length();
        }
        byte[] result = new byte[length];
        int cursor = 0;
        for (String label : labels) {
            result[cursor++] = (byte) label.length();
            for (int i = 0; i < label.length(); i++) {
                result[cursor++] = (byte) label.charAt(i);
            }
        }
        result[cursor] = 0;
        return result;
    }

    private static byte[] labelAndPointer(String label, int target) {
        byte[] result = new byte[label.length() + 3];
        result[0] = (byte) label.length();
        for (int i = 0; i < label.length(); i++) {
            result[i + 1] = (byte) label.charAt(i);
        }
        put16(result, label.length() + 1, 0xc000 | target);
        return result;
    }

    private static byte[] pointer(int target) {
        byte[] result = new byte[2];
        put16(result, 0, 0xc000 | target);
        return result;
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] result = new byte[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
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
