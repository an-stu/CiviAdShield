package cn.civi.adshield.core;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Immutable DNS-only evaluator for the domain rules in an AdGuard-style filter. Blank and comment
 * lines are not counted. Supported {@code $badfilter} directives are control lines: they are not
 * counted as accepted or ignored, while each supported rule entry they remove increments
 * {@link #disabledRules()}.
 */
public final class AdGuardDnsRules {
    public enum Decision {
        NONE,
        BLOCK,
        ALLOW
    }

    private final Set<String> blockDomains;
    private final Set<String> exceptionDomains;
    private final Set<String> normalBlocks;
    private final Set<String> normalExceptions;
    private final Set<String> importantBlocks;
    private final Set<String> importantExceptions;
    private final int size;
    private final int acceptedRules;
    private final int ignoredRules;
    private final int disabledRules;

    private AdGuardDnsRules(Set<String> blockDomains, Set<String> exceptionDomains,
                            Set<String> normalBlocks, Set<String> normalExceptions,
                            Set<String> importantBlocks, Set<String> importantExceptions,
                            int acceptedRules, int ignoredRules, int disabledRules) {
        this.blockDomains = immutableCopy(blockDomains);
        this.exceptionDomains = immutableCopy(exceptionDomains);
        this.normalBlocks = immutableCopy(normalBlocks);
        this.normalExceptions = immutableCopy(normalExceptions);
        this.importantBlocks = immutableCopy(importantBlocks);
        this.importantExceptions = immutableCopy(importantExceptions);
        int uniqueCount = blockDomains.size();
        for (String domain : exceptionDomains) if (!blockDomains.contains(domain)) uniqueCount++;
        this.size = uniqueCount;
        this.acceptedRules = acceptedRules;
        this.ignoredRules = ignoredRules;
        this.disabledRules = disabledRules;
    }

    /** Loads DNS domain rules. The caller retains ownership of {@code input}. */
    public static AdGuardDnsRules load(Reader input) throws IOException {
        if (input == null) {
            throw new IllegalArgumentException("rule reader is null");
        }

        List<Rule> rules = new ArrayList<Rule>();
        Set<RuleKey> disabledKeys = new HashSet<RuleKey>();
        int ignored = 0;
        BufferedReader reader = input instanceof BufferedReader
                ? (BufferedReader) input : new BufferedReader(input);
        String rawLine;
        while ((rawLine = reader.readLine()) != null) {
            String line = prepareLine(rawLine);
            if (line == null) {
                continue;
            }
            ParseResult parsed = parseRule(line);
            if (parsed == null) {
                ignored++;
            } else if (parsed.badfilter) {
                disabledKeys.add(parsed.rule.key);
            } else {
                rules.add(parsed.rule);
            }
        }

        Set<String> allBlocks = new HashSet<String>();
        Set<String> allExceptions = new HashSet<String>();
        Set<String> normalBlocks = new HashSet<String>();
        Set<String> normalExceptions = new HashSet<String>();
        Set<String> importantBlocks = new HashSet<String>();
        Set<String> importantExceptions = new HashSet<String>();
        int accepted = 0;
        int disabled = 0;

        for (Rule rule : rules) {
            if (disabledKeys.contains(rule.key)) {
                disabled++;
                continue;
            }
            accepted++;
            if (rule.exception) {
                allExceptions.add(rule.domain);
                (rule.important ? importantExceptions : normalExceptions).add(rule.domain);
            } else {
                allBlocks.add(rule.domain);
                (rule.important ? importantBlocks : normalBlocks).add(rule.domain);
            }
        }

        return new AdGuardDnsRules(allBlocks, allExceptions,
                normalBlocks, normalExceptions, importantBlocks, importantExceptions,
                accepted, ignored, disabled);
    }

    /** Evaluates one domain using important-exception, important-block, exception, block order. */
    public Decision decide(String domain) {
        String normalized = DomainRules.normalize(domain);
        if (normalized == null) {
            return Decision.NONE;
        }
        if (matches(importantExceptions, normalized)) {
            return Decision.ALLOW;
        }
        if (matches(importantBlocks, normalized)) {
            return Decision.BLOCK;
        }
        if (matches(normalExceptions, normalized)) {
            return Decision.ALLOW;
        }
        if (matches(normalBlocks, normalized)) {
            return Decision.BLOCK;
        }
        return Decision.NONE;
    }

    /** Returns unique normalized domains with at least one retained block rule. */
    public Set<String> blockDomains() {
        return blockDomains;
    }

    /** Returns unique normalized domains with at least one retained exception rule. */
    public Set<String> exceptionDomains() {
        return exceptionDomains;
    }

    /** Returns the number of unique normalized domains retained across blocks and exceptions. */
    public int size() {
        return size;
    }

    /** Number of retained supported rule entries, including repeated source entries. */
    public int acceptedRules() {
        return acceptedRules;
    }

    /** Number of non-comment rule lines rejected as malformed or unsupported. */
    public int ignoredRules() {
        return ignoredRules;
    }

    /** Number of supported rule entries removed by matching badfilter directives. */
    public int disabledRules() {
        return disabledRules;
    }

    private static boolean matches(Set<String> rules, String normalizedDomain) {
        int start = 0;
        while (true) {
            if (rules.contains(normalizedDomain.substring(start))) {
                return true;
            }
            int dot = normalizedDomain.indexOf('.', start);
            if (dot < 0) {
                return false;
            }
            start = dot + 1;
        }
    }

    private static String prepareLine(String rawLine) {
        String line = rawLine;
        if (line.startsWith("\uFEFF")) {
            line = line.substring(1);
        }
        String trimmed = line.trim();
        if (trimmed.startsWith("\uFEFF")) {
            trimmed = trimmed.substring(1).trim();
        }
        if (trimmed.length() == 0 || trimmed.startsWith("!") || trimmed.startsWith("#")) {
            return null;
        }
        for (int index = 0; index < line.length(); index++) {
            if (Character.isISOControl(line.charAt(index))) {
                return "\u0000"; // Force the line through the ignored-rule path.
            }
        }
        return trimmed.length() == 0 ? null : trimmed;
    }

    private static ParseResult parseRule(String line) {
        boolean exception = line.startsWith("@@");
        String body = exception ? line.substring(2) : line;
        if (body.length() == 0 || body.startsWith("@@")) {
            return null;
        }

        String pattern = body;
        boolean important = false;
        boolean badfilter = false;
        int dollar = body.indexOf('$');
        if (dollar >= 0) {
            if (body.indexOf('$', dollar + 1) >= 0) {
                return null;
            }
            pattern = body.substring(0, dollar);
            String modifierText = body.substring(dollar + 1);
            if (modifierText.length() == 0) {
                return null;
            }
            String[] modifiers = modifierText.split(",", -1);
            for (String rawModifier : modifiers) {
                String modifier = rawModifier.toLowerCase(Locale.ROOT);
                if ("important".equals(modifier)) {
                    important = true;
                } else if ("badfilter".equals(modifier)) {
                    badfilter = true;
                } else {
                    return null;
                }
            }
        }

        PatternKind kind;
        String domain;
        if (pattern.startsWith("||")) {
            if (pattern.length() < 4 || !pattern.endsWith("^")
                    || pattern.substring(2, pattern.length() - 1).indexOf('^') >= 0) {
                return null;
            }
            kind = PatternKind.DOMAIN_ANCHOR;
            domain = pattern.substring(2, pattern.length() - 1);
        } else if (pattern.startsWith("*.")) {
            kind = PatternKind.WILDCARD;
            domain = pattern.substring(2);
        } else {
            kind = PatternKind.PLAIN;
            domain = pattern;
        }

        if (domain.length() == 0 || domain.indexOf('*') >= 0 || domain.indexOf('^') >= 0
                || domain.indexOf('|') >= 0 || domain.indexOf('$') >= 0) {
            return null;
        }
        String normalized = DomainRules.normalize(domain);
        if (normalized == null) {
            return null;
        }

        Rule rule = new Rule(normalized, exception, important,
                new RuleKey(normalized, kind, exception, important));
        return new ParseResult(rule, badfilter);
    }

    private static Set<String> immutableCopy(Set<String> values) {
        // Every input set is created by load() and is never mutated after construction.
        return Collections.unmodifiableSet(values);
    }

    private enum PatternKind {
        PLAIN,
        WILDCARD,
        DOMAIN_ANCHOR
    }

    private static final class Rule {
        final String domain;
        final boolean exception;
        final boolean important;
        final RuleKey key;

        Rule(String domain, boolean exception, boolean important, RuleKey key) {
            this.domain = domain;
            this.exception = exception;
            this.important = important;
            this.key = key;
        }
    }

    private static final class RuleKey {
        final String domain;
        final PatternKind kind;
        final boolean exception;
        final boolean important;

        RuleKey(String domain, PatternKind kind, boolean exception, boolean important) {
            this.domain = domain;
            this.kind = kind;
            this.exception = exception;
            this.important = important;
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) {
                return true;
            }
            if (!(other instanceof RuleKey)) {
                return false;
            }
            RuleKey that = (RuleKey) other;
            return exception == that.exception && important == that.important
                    && kind == that.kind && domain.equals(that.domain);
        }

        @Override
        public int hashCode() {
            int result = domain.hashCode();
            result = 31 * result + kind.hashCode();
            result = 31 * result + (exception ? 1 : 0);
            result = 31 * result + (important ? 1 : 0);
            return result;
        }
    }

    private static final class ParseResult {
        final Rule rule;
        final boolean badfilter;

        ParseResult(Rule rule, boolean badfilter) {
            this.rule = rule;
            this.badfilter = badfilter;
        }
    }
}
