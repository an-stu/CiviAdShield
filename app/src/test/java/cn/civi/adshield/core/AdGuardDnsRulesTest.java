package cn.civi.adshield.core;

import org.junit.Test;

import java.io.StringReader;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class AdGuardDnsRulesTest {
    @Test
    public void matchesPlainWildcardAndDomainAnchoredRulesOnLabelBoundaries() throws Exception {
        AdGuardDnsRules rules = load(
                "plain.example\n"
                        + "*.wild.example\n"
                        + "||anchor.example^\n");

        assertEquals(AdGuardDnsRules.Decision.BLOCK, rules.decide("plain.example"));
        assertEquals(AdGuardDnsRules.Decision.BLOCK, rules.decide("a.b.plain.example"));
        assertEquals(AdGuardDnsRules.Decision.BLOCK, rules.decide("a.wild.example"));
        assertEquals(AdGuardDnsRules.Decision.BLOCK, rules.decide("a.anchor.example"));
        assertEquals(AdGuardDnsRules.Decision.NONE, rules.decide("notplain.example"));
        assertEquals(AdGuardDnsRules.Decision.NONE, rules.decide("anchor.example.evil"));
    }

    @Test
    public void appliesExceptionAndImportantPrecedenceAcrossParentAndChildDomains()
            throws Exception {
        AdGuardDnsRules rules = load(
                "||normal.test^\n"
                        + "@@||normal.test^\n"
                        + "@@||parent.test^\n"
                        + "||child.parent.test^$important\n"
                        + "||allowparent.test^$important\n"
                        + "@@||child.allowparent.test^$important\n"
                        + "||allowchild.test^\n"
                        + "@@||allowchild.test^$important\n");

        assertEquals(AdGuardDnsRules.Decision.ALLOW, rules.decide("x.normal.test"));
        assertEquals(AdGuardDnsRules.Decision.BLOCK, rules.decide("x.child.parent.test"));
        assertEquals(AdGuardDnsRules.Decision.ALLOW, rules.decide("x.child.allowparent.test"));
        assertEquals(AdGuardDnsRules.Decision.ALLOW, rules.decide("allowchild.test"));
        assertEquals(AdGuardDnsRules.Decision.ALLOW, rules.decide("x.allowchild.test"));
    }

    @Test
    public void badfilterDisablesOnlyExactPatternAndCanonicalModifierSet() throws Exception {
        AdGuardDnsRules rules = load(
                "||cancel.example^$important\n"
                        + "||cancel.example^$badfilter,important\n"
                        + "||survive.example^$important\n"
                        + "||survive.example^\n"
                        + "||survive.example^$badfilter\n"
                        + "||same.example^\n"
                        + "same.example$badfilter\n"
                        + "@@||exception.example^$important\n"
                        + "@@||exception.example^$badfilter,important\n"
                        + "||exception.example^\n"
                        + "||before.example^$badfilter,important\n"
                        + "||before.example^$important\n");

        assertEquals(AdGuardDnsRules.Decision.NONE, rules.decide("cancel.example"));
        assertEquals(AdGuardDnsRules.Decision.BLOCK, rules.decide("survive.example"));
        assertEquals(AdGuardDnsRules.Decision.BLOCK, rules.decide("same.example"));
        assertEquals(AdGuardDnsRules.Decision.BLOCK, rules.decide("exception.example"));
        assertEquals(AdGuardDnsRules.Decision.NONE, rules.decide("before.example"));
        assertEquals(3, rules.acceptedRules());
        assertEquals(4, rules.disabledRules());
        assertEquals(0, rules.ignoredRules());
    }

    @Test
    public void ignoresUnknownWebModifiersRegexCosmeticAndPathRulesAsWholeLines()
            throws Exception {
        AdGuardDnsRules rules = load(
                "||script.example^$script\n"
                        + "@@||generichide.example^$generichide\n"
                        + "||thirdparty.example^$important,third-party\n"
                        + "||path.example/banner.js\n"
                        + "/^regex\\.example$/\n"
                        + "cosmetic.example##.ad\n"
                        + "cosmetic.example#@#.ad\n"
                        + "cosmetic.example#?#.ad\n"
                        + "cosmetic.example#$#.ad\n"
                        + "cosmetic.example#%#.ad\n"
                        + "||partial.example^*\n");

        assertEquals(AdGuardDnsRules.Decision.NONE, rules.decide("script.example"));
        assertEquals(AdGuardDnsRules.Decision.NONE, rules.decide("generichide.example"));
        assertEquals(AdGuardDnsRules.Decision.NONE, rules.decide("thirdparty.example"));
        assertEquals(AdGuardDnsRules.Decision.NONE, rules.decide("path.example"));
        assertEquals(AdGuardDnsRules.Decision.NONE, rules.decide("cosmetic.example"));
        assertEquals(0, rules.acceptedRules());
        assertEquals(11, rules.ignoredRules());
        assertEquals(0, rules.disabledRules());
    }

    @Test
    public void stripsLeadingBomAndNormalizesIdnWithoutBreakingBoundaries() throws Exception {
        AdGuardDnsRules rules = load("\uFEFF||bücher.example^\n");
        String punycode = DomainRules.normalize("bücher.example");
        assertEquals("xn--bcher-kva.example", punycode);
        assertEquals(AdGuardDnsRules.Decision.BLOCK,
                rules.decide("WWW.XN--BCHER-KVA.EXAMPLE."));
        assertEquals(AdGuardDnsRules.Decision.NONE, rules.decide("notxn--bcher-kva.example"));
        assertEquals(1, rules.acceptedRules());
        assertEquals(0, rules.ignoredRules());
    }

    @Test
    public void rejectsIpLiteralsAndControlCharacters() throws Exception {
        AdGuardDnsRules rules = load(
                "||127.0.0.1^\n"
                        + "||192.168.1.10^\n"
                        + "||control.example^" + (char) 1 + "\n"
                        + "||safe.example^\n");
        assertEquals(AdGuardDnsRules.Decision.NONE, rules.decide("127.0.0.1"));
        assertEquals(AdGuardDnsRules.Decision.NONE, rules.decide("192.168.1.10"));
        assertEquals(AdGuardDnsRules.Decision.NONE, rules.decide("control.example"));
        assertEquals(AdGuardDnsRules.Decision.BLOCK, rules.decide("safe.example"));
        assertEquals(1, rules.acceptedRules());
        assertEquals(3, rules.ignoredRules());
    }

    @Test
    public void exposesImmutableSetsAndUniqueDomainCount() throws Exception {
        AdGuardDnsRules rules = load(
                "||shared.example^\n"
                        + "*.shared.example\n"
                        + "@@||shared.example^\n"
                        + "@@allowed.example\n");

        assertEquals(4, rules.acceptedRules());
        assertEquals(2, rules.size());
        assertEquals(1, rules.blockDomains().size());
        assertEquals(2, rules.exceptionDomains().size());
        assertTrue(rules.blockDomains().contains("shared.example"));
        assertTrue(rules.exceptionDomains().contains("allowed.example"));
        try {
            rules.blockDomains().add("mutated.example");
            fail("block domain set must be immutable");
        } catch (UnsupportedOperationException expected) {
            assertFalse(rules.blockDomains().contains("mutated.example"));
        }
        try {
            rules.exceptionDomains().add("mutated.example");
            fail("exception domain set must be immutable");
        } catch (UnsupportedOperationException expected) {
            assertFalse(rules.exceptionDomains().contains("mutated.example"));
        }
    }

    private static AdGuardDnsRules load(String source) throws Exception {
        return AdGuardDnsRules.load(new StringReader(source));
    }
}
