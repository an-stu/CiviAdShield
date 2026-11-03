package cn.civi.adshield.core;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.net.IDN;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/** Immutable, suffix-aware domain rules loaded from hosts and common adblock syntax. */
public final class DomainRules {
    private final Set<String> domains;

    private DomainRules(Set<String> domains) {
        this.domains = Collections.unmodifiableSet(domains);
    }

    /** Loads supported domain rules from a hosts/adblock-style text source. */
    public static DomainRules load(Reader input) throws IOException {
        if (input == null) {
            throw new IllegalArgumentException("rule reader is null");
        }
        Set<String> domains = new HashSet<String>();
        BufferedReader reader = input instanceof BufferedReader
                ? (BufferedReader) input : new BufferedReader(input);
        String line;
        while ((line = reader.readLine()) != null) {
            parseLine(line, domains);
        }
        return new DomainRules(domains);
    }

    /** Converts a valid domain or IDN to lowercase ASCII/punycode; returns null when invalid. */
    public static String normalize(String domain) {
        if (domain == null || domain.length() == 0 || !domain.equals(domain.trim())) {
            return null;
        }
        String value = domain;
        if (value.endsWith(".")) {
            value = value.substring(0, value.length() - 1);
        }
        if (value.length() == 0 || value.startsWith(".") || value.endsWith(".")
                || value.indexOf("..") >= 0 || value.indexOf('/') >= 0
                || value.indexOf('\\') >= 0 || value.indexOf(':') >= 0
                || value.indexOf('@') >= 0) {
            return null;
        }
        try {
            String ascii = IDN.toASCII(value, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
            if (ascii.length() > 253) {
                return null;
            }
            String[] labels = ascii.split("\\.", -1);
            for (String label : labels) {
                if (label.length() == 0 || label.length() > 63 || label.startsWith("-")
                        || label.endsWith("-")) {
                    return null;
                }
            }
            if (isIpLiteral(ascii)) {
                return null;
            }
            return ascii;
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }

    /** Returns true when a rule matches the domain itself or one of its subdomains. */
    public boolean matches(String domain) {
        String normalized = normalize(domain);
        if (normalized == null) {
            return false;
        }
        int start = 0;
        while (true) {
            if (domains.contains(normalized.substring(start))) {
                return true;
            }
            int dot = normalized.indexOf('.', start);
            if (dot < 0) {
                return false;
            }
            start = dot + 1;
        }
    }

    public int size() {
        return domains.size();
    }

    /** Returns the immutable normalized rule set. */
    public Set<String> domains() {
        return domains;
    }

    private static void parseLine(String rawLine, Set<String> domains) {
        String line = rawLine.trim();
        if (line.length() == 0 || line.startsWith("!") || line.startsWith("#")) {
            return;
        }
        if (line.contains("##") || line.contains("#@#") || line.contains("#?#")
                || line.contains("#$#") || line.contains("#%#")) {
            return;
        }
        int hash = line.indexOf('#');
        if (hash >= 0) {
            if (hash > 0 && !Character.isWhitespace(line.charAt(hash - 1))) {
                return;
            }
            line = line.substring(0, hash).trim();
            if (line.length() == 0) {
                return;
            }
        }

        String[] tokens = line.split("\\s+");
        if (isHostsAddress(tokens[0])) {
            for (int i = 1; i < tokens.length; i++) {
                addRule(tokens[i], false, domains);
            }
            return;
        }
        if (isIpLiteral(tokens[0])) {
            return;
        }
        if (tokens.length != 1) {
            return;
        }
        addRule(tokens[0], true, domains);
    }

    private static void addRule(String token, boolean allowAdblock, Set<String> domains) {
        String domain = token;
        if (allowAdblock && domain.startsWith("||")) {
            if (domain.length() < 4 || !domain.endsWith("^")
                    || domain.indexOf('$') >= 0 || domain.indexOf('*', 2) >= 0) {
                return;
            }
            domain = domain.substring(2, domain.length() - 1);
        }
        if (domain.startsWith("*.")) {
            domain = domain.substring(2);
        } else if (domain.indexOf('*') >= 0) {
            return;
        }
        if (domain.indexOf('^') >= 0 || domain.indexOf('/') >= 0 || domain.indexOf('?') >= 0
                || domain.indexOf('=') >= 0 || domain.indexOf('[') >= 0 || domain.indexOf(']') >= 0) {
            return;
        }
        String normalized = normalize(domain);
        if (normalized != null && !isIpLiteral(normalized)) {
            domains.add(normalized);
        }
    }

    private static boolean isHostsAddress(String token) {
        return "0.0.0.0".equals(token) || "127.0.0.1".equals(token);
    }

    private static boolean isIpLiteral(String token) {
        if (token.indexOf(':') >= 0) {
            return true; // IPv6 literals are never domain rules.
        }
        String[] octets = token.split("\\.", -1);
        if (octets.length != 4) {
            return false;
        }
        for (String octet : octets) {
            if (octet.length() == 0 || octet.length() > 3) {
                return false;
            }
            int value = 0;
            for (int i = 0; i < octet.length(); i++) {
                char c = octet.charAt(i);
                if (c < '0' || c > '9') {
                    return false;
                }
                value = value * 10 + c - '0';
            }
            if (value > 255) {
                return false;
            }
        }
        return true;
    }
}
