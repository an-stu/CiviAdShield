package cn.civi.adshield.core;

/** Combines local DNS blocking sources without parsing wire messages or applying UI policy. */
public final class DnsBlockPolicy {
    private final DomainRules base;
    private final DomainRules custom;
    private final DomainRules allow;
    private final AdGuardDnsRules adguard;
    private final boolean antiAdEnabled;
    private final boolean adguardEnabled;

    public DnsBlockPolicy(DomainRules base, DomainRules custom, DomainRules allow,
                          AdGuardDnsRules adguard, boolean antiAdEnabled,
                          boolean adguardEnabled) {
        if (base == null || custom == null || allow == null || adguard == null) {
            throw new IllegalArgumentException("DNS rule sets must not be null");
        }
        this.base = base;
        this.custom = custom;
        this.allow = allow;
        this.adguard = adguard;
        this.antiAdEnabled = antiAdEnabled;
        this.adguardEnabled = adguardEnabled;
    }

    /** Returns whether the combined rules block this domain. */
    public boolean blocks(String domain) {
        if (allow.matches(domain)) {
            return false;
        }
        if (custom.matches(domain)) {
            return true;
        }
        if (adguardEnabled) {
            AdGuardDnsRules.Decision decision = adguard.decide(domain);
            if (decision == AdGuardDnsRules.Decision.ALLOW) {
                return false;
            }
            if (decision == AdGuardDnsRules.Decision.BLOCK) {
                return true;
            }
        }
        return antiAdEnabled && base.matches(domain);
    }

    /**
     * Returns whether the original domain or an alias target is blocked. An allow rule for the
     * original query preserves it and prevents alias-only blocking. A null target iterable is
     * treated as empty.
     */
    public boolean blocksAliases(String original, Iterable<String> targets) {
        if (blocks(original)) {
            return true;
        }
        if (isAllowedOriginal(original) || targets == null) {
            return false;
        }
        for (String target : targets) {
            if (blocks(target)) {
                return true;
            }
        }
        return false;
    }

    private boolean isAllowedOriginal(String original) {
        if (allow.matches(original)) {
            return true;
        }
        return adguardEnabled && !custom.matches(original)
                && adguard.decide(original) == AdGuardDnsRules.Decision.ALLOW;
    }
}
