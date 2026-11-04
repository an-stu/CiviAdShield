package cn.civi.adshield.core;

import java.io.StringReader;
import java.util.Arrays;
import java.util.Collections;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class DnsBlockPolicyTest {
    @Test
    public void appliesUserAndImportedRulePrecedence() throws Exception {
        DomainRules antiAd = domains("||anti.example^");
        DomainRules custom = domains("||custom.example^");
        DomainRules allow = domains("||userallow.example^");
        AdGuardDnsRules adguard = adguard(
                "@@||anti.example^",
                "@@||custom.example^",
                "||userallow.example^$important",
                "||adguard-only.example^");
        DnsBlockPolicy policy = new DnsBlockPolicy(
                antiAd, custom, allow, adguard, true, true);

        assertFalse("AdGuard exception unblocks a base rule", policy.blocks("ads.anti.example"));
        assertTrue("custom rule wins over imported exception", policy.blocks("x.custom.example"));
        assertFalse("user allow wins over an important imported block",
                policy.blocks("x.userallow.example"));
        assertTrue("enabled imported rule blocks", policy.blocks("x.adguard-only.example"));
    }

    @Test
    public void sourceTogglesDisableOnlyTheirOwnBlockingSource() throws Exception {
        DomainRules antiAd = domains("anti.example");
        DomainRules emptyCustom = domains("");
        DomainRules emptyAllow = domains("");
        AdGuardDnsRules adguard = adguard("||adguard.example^");

        DnsBlockPolicy neither = new DnsBlockPolicy(
                antiAd, emptyCustom, emptyAllow, adguard, false, false);
        assertFalse(neither.blocks("anti.example"));
        assertFalse(neither.blocks("adguard.example"));

        DnsBlockPolicy antiOnly = new DnsBlockPolicy(
                antiAd, emptyCustom, emptyAllow, adguard, true, false);
        assertTrue(antiOnly.blocks("anti.example"));
        assertFalse(antiOnly.blocks("adguard.example"));

        DnsBlockPolicy adguardOnly = new DnsBlockPolicy(
                antiAd, emptyCustom, emptyAllow, adguard, false, true);
        assertFalse(adguardOnly.blocks("anti.example"));
        assertTrue(adguardOnly.blocks("adguard.example"));
    }

    @Test
    public void blocksAliasTargetsButPreservesAllowedOriginalsAndTargets() throws Exception {
        DomainRules antiAd = domains("ads.cdn.example");
        DomainRules custom = domains("");
        DomainRules allow = domains("allowed.original.example\nallowed.target.example");
        AdGuardDnsRules adguard = adguard(
                "@@||adguard-allowed.original.example^",
                "@@||adguard-allowed.target.example^");
        DnsBlockPolicy policy = new DnsBlockPolicy(
                antiAd, custom, allow, adguard, true, true);

        assertFalse(policy.blocks("ordinary.example"));
        assertTrue("a blocked CNAME target blocks an otherwise allowed query",
                policy.blocksAliases("ordinary.example", Arrays.asList("edge.ads.cdn.example")));
        assertFalse("user allow on the original query preserves its alias chain",
                policy.blocksAliases("allowed.original.example", Arrays.asList("ads.cdn.example")));
        assertFalse("user allow on an alias target permits the chain",
                policy.blocksAliases("ordinary.example", Arrays.asList("allowed.target.example")));
        assertFalse("an imported exception on the original preserves its alias chain",
                policy.blocksAliases("adguard-allowed.original.example",
                        Arrays.asList("ads.cdn.example")));
        assertFalse("an imported exception on the target allows that target",
                policy.blocksAliases("ordinary.example",
                        Arrays.asList("adguard-allowed.target.example")));
        assertFalse("null target lists behave as empty", policy.blocksAliases("ordinary.example", null));
    }

    @Test
    public void anAlreadyBlockedOriginalRemainsBlocked() throws Exception {
        DnsBlockPolicy policy = new DnsBlockPolicy(
                domains("blocked.original.example"), domains(""), domains(""),
                adguard(""), true, false);

        assertTrue(policy.blocksAliases("blocked.original.example",
                Collections.singletonList("allowed.target.example")));
    }

    @Test
    public void constructorRejectsNullRuleSources() throws Exception {
        final DomainRules rules = domains("");
        final AdGuardDnsRules imported = adguard("");
        expectIllegalArgument(new Runnable() {
            @Override
            public void run() {
                new DnsBlockPolicy(null, rules, rules, imported, true, true);
            }
        });
        expectIllegalArgument(new Runnable() {
            @Override
            public void run() {
                new DnsBlockPolicy(rules, null, rules, imported, true, true);
            }
        });
        expectIllegalArgument(new Runnable() {
            @Override
            public void run() {
                new DnsBlockPolicy(rules, rules, null, imported, true, true);
            }
        });
        expectIllegalArgument(new Runnable() {
            @Override
            public void run() {
                new DnsBlockPolicy(rules, rules, rules, null, true, true);
            }
        });
    }

    private static DomainRules domains(String source) throws Exception {
        return DomainRules.load(new StringReader(source));
    }

    private static AdGuardDnsRules adguard(String... lines) throws Exception {
        StringBuilder source = new StringBuilder();
        for (String line : lines) {
            source.append(line).append('\n');
        }
        return AdGuardDnsRules.load(new StringReader(source.toString()));
    }

    private static void expectIllegalArgument(Runnable action) {
        try {
            action.run();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage() != null);
        }
    }
}
