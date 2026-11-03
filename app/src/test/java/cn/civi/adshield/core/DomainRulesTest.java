package cn.civi.adshield.core;

import org.junit.Test;

import java.io.IOException;
import java.io.StringReader;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class DomainRulesTest {
    @Test
    public void loadsHostsExactAndSupportedAdblockRules() throws IOException {
        String source = ""
                + "! whole-line comment\n"
                + "# another comment\n"
                + "0.0.0.0 ads.example.com tracker.example.net # hosts comment\n"
                + "127.0.0.1 pixel.example.org\n"
                + "||doubleclick.example^\n"
                + "*.wild.example\n"
                + "plain.example\n"
                + "plain.example/path\n"
                + "||path.example^$third-party\n"
                + "example.com##.sponsored\n"
                + "example.net#$#alert(1)\n"
                + "192.168.1.10\n";
        DomainRules rules = DomainRules.load(new StringReader(source));

        assertEquals(6, rules.size());
        assertTrue(rules.matches("ads.example.com"));
        assertTrue(rules.matches("sub.ads.example.com"));
        assertTrue(rules.matches("deep.tracker.example.net"));
        assertTrue(rules.matches("sub.doubleclick.example"));
        assertTrue(rules.matches("wild.example"));
        assertTrue(rules.matches("sub.wild.example"));
        assertTrue(rules.matches("x.plain.example"));
        assertFalse(rules.matches("notads.example.com"));
        assertFalse(rules.matches("example.com")); // Cosmetic selector is ignored.
        assertFalse(rules.matches("example.net"));
        assertFalse(rules.matches("path.example"));
        assertFalse(rules.matches("192.168.1.10"));
    }

    @Test
    public void normalizesIdnsAndRejectsInvalidDomainsAndIpAddresses() {
        assertEquals("xn--bcher-kva.de", DomainRules.normalize("Bücher.de"));
        assertEquals("example.com", DomainRules.normalize("Example.COM."));
        assertNull(DomainRules.normalize(""));
        assertNull(DomainRules.normalize("bad..example"));
        assertNull(DomainRules.normalize("-bad.example"));
        assertNull(DomainRules.normalize("bad.example/path"));
        assertNull(DomainRules.normalize("192.168.1.1"));
        assertNull(DomainRules.normalize("bad_domain.example"));
    }

    @Test
    public void suffixMatchHonorsLabelBoundariesAndWhitelistCanBeSeparate() throws IOException {
        DomainRules blacklist = DomainRules.load(new StringReader("example.com\n"));
        DomainRules whitelist = DomainRules.load(new StringReader("safe.example.com\n"));

        assertTrue(blacklist.matches("example.com"));
        assertTrue(blacklist.matches("www.example.com"));
        assertFalse(blacklist.matches("notexample.com"));
        assertFalse(blacklist.matches("example.com.attacker.org"));
        assertTrue(whitelist.matches("safe.example.com"));
        assertTrue(whitelist.matches("child.safe.example.com"));
        assertFalse(whitelist.matches("other.example.com"));
    }

    @Test
    public void exposesImmutableNormalizedDomains() throws IOException {
        DomainRules rules = DomainRules.load(new StringReader("||ads.example^\n"));
        Set<String> domains = rules.domains();
        assertTrue(domains.contains("ads.example"));
        try {
            domains.add("other.example");
            fail("Domain set should be immutable");
        } catch (UnsupportedOperationException expected) {
            assertEquals(1, rules.size());
        }
    }
}
