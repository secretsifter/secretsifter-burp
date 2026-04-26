package com.secretscanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Thread-safe settings model.
 *
 * Primitive fields use volatile for visibility across threads.
 * The CDN blocklist is protected by synchronized methods.
 * Persistence keys are prefixed with "ss." to avoid collisions.
 */
public class ScanSettings {

    public enum ScanTier { FAST, LIGHT, FULL }

    // ---- preference keys ----
    private static final String KEY_ENABLED        = "ss.enabled";
    private static final String KEY_TIER           = "ss.tier";
    private static final String KEY_ENTROPY        = "ss.entropy";        // stored as String
    private static final String KEY_PII            = "ss.pii";
    private static final String KEY_CDNLIST        = "ss.cdnlist";        // newline-separated
    private static final String KEY_SCAN_REQUESTS  = "ss.scan_requests";  // scan req headers/body
    private static final String KEY_KEY_BLOCKLIST  = "ss.keyblocklist";   // newline-separated key name suppression list
    private static final String KEY_KEY_ALLOWLIST  = "ss.keyallowlist";   // newline-separated key name force-include list
    private static final String KEY_ALLOW_INSECURE_SSL   = "ss.allow_insecure_ssl";
    private static final String KEY_CUSTOM_RULES         = "ss.customrules";        // newline-separated rule lines
    private static final String KEY_CUSTOM_RULES_ENABLED = "ss.customrules_enabled";
    private static final String KEY_CUSTOM_RULES_ONLY    = "ss.customrules_only";   // raw mode: skip built-in scanners + FP gates

    // ---- fields ----
    private volatile boolean   enabled              = true;
    private volatile ScanTier  tier                 = ScanTier.FULL;
    private volatile double    entropyThreshold     = 3.5;
    private volatile boolean   piiEnabled           = true;
    private volatile boolean   scanRequestsEnabled  = true;
    private volatile boolean   allowInsecureSsl     = false;
    private volatile boolean   customRulesEnabled   = true;
    // Raw mode: when true, the proxy and bulk-scan paths run ONLY user-supplied custom rules
    // and bypass the FP gates (isProbableSecretValue, placeholder check, webpack-hash filter).
    // Allowlist/blocklist/CDN blocklist still apply. Burp's audit (SecretScanCheck) is unaffected.
    private volatile boolean   customRulesOnly      = false;

    // Key name blocklist — findings whose matched key name contains any entry are suppressed.
    // Defaults cover common app storage-key constants that are never credentials.
    private final List<String> keyBlocklist = new ArrayList<>(Arrays.asList(
            "STORAGE_KEY_", "storage_key_",
            "STATE_KEY_",   "state_key_",
            "NEXT_PUBLIC_", "REACT_APP_PUBLIC_", "VUE_APP_PUBLIC_"
    ));

    // Key name allowlist — findings whose matched key name contains any entry are always reported,
    // bypassing isProbableSecretValue() checks. Empty by default; users populate per engagement.
    private final List<String> keyAllowlist = new ArrayList<>();

    // Custom rules — user-defined patterns layered on top of built-ins.
    // Each entry is a raw rule line: "RuleName | regex | severity"
    // Parsed at scan time by SecretScanner. Empty by default.
    private final List<String> customRules = new ArrayList<>();

    private final List<String> cdnBlocklist = new ArrayList<>(Arrays.asList(
            // JS/CSS CDNs — static asset delivery, no secrets expected
            "cdnjs", "jsdelivr", "unpkg", "ajax.googleapis.com",
            "ajax.microsoft.com", "code.jquery.com", "stackpath", "maxcdn",
            "fonts.googleapis.com", "fonts.gstatic.com", "gstatic.com",
            // Analytics / tracking — no secrets, just noise
            "firebase", "segment.com", "segment.io", "doubleclick",
            "googletagmanager.com", "hotjar.com",
            "cloudflareinsights.com", "cdn.cookielaw.org",
            "dc.services.visualstudio.com",
            "launchdarkly.com", "data.microsoft.com",
            "rs.fullstory.com", "edge.fullstory.com",
            "sentry.io", "bat.bing.com", "snap.licdn.com",
            "platform.linkedin.com", "connect.facebook.net",
            "static.klaviyo.com", "static.ads-twitter.com",
            // NOTE: amazonaws.com and cloudfront.net intentionally excluded —
            // AWS API Gateway + CloudFront are used to serve real API responses.
            // Add them manually here if you want to skip those hosts.
            "akamaiedge.net",
            // Device fingerprinting / bot-detection CDNs — no app secrets, lots of noise
            "online-metrix.net",        // ThreatMetrix / LexisNexis Risk Solutions
            // SSO / identity providers — these are third-party auth pages, not app assets
            "microsoftonline.com",      // Microsoft Entra / Azure AD login
            "msauth.net",               // Microsoft auth CDN (aadcdn.msauth.net etc.)
            "msftauth.net",             // Microsoft alt auth domain
            "live.com",                 // Microsoft Live login
            // Adobe marketing cloud — DTM/Launch tag managers and analytics CDNs
            "adobedtm.com",             // Adobe DTM / Launch (assets.adobedtm.com etc.)
            "omtrdc.net",               // Adobe Analytics / Target
            "demdex.net",               // Adobe Audience Manager
            // General analytics / RUM CDNs
            "google-analytics.com",
            "nr-data.net",              // New Relic browser agent
            // Customer experience / feedback analytics
            "medallia.com",             // Medallia digital experience (analytics-fe.*)
            "medallia.eu"               // Medallia EU data-residency endpoint
    ));

    // =========================================================================
    // Getters / setters
    // =========================================================================

    public boolean isEnabled()                   { return enabled; }
    public void    setEnabled(boolean b)         { enabled = b; }

    public ScanTier getTier()                    { return tier; }
    public void     setTier(ScanTier t)          { if (t != null) tier = t; }

    public double getEntropyThreshold()          { return entropyThreshold; }
    public void   setEntropyThreshold(double t)  { entropyThreshold = t; }

    public boolean isPiiEnabled()                        { return piiEnabled; }
    public void    setPiiEnabled(boolean b)              { piiEnabled = b; }

    public boolean isScanRequestsEnabled()               { return scanRequestsEnabled; }
    public void    setScanRequestsEnabled(boolean b)     { scanRequestsEnabled = b; }

    public boolean isAllowInsecureSsl()                  { return allowInsecureSsl; }
    public void    setAllowInsecureSsl(boolean b)        { allowInsecureSsl = b; }

    public boolean isCustomRulesEnabled()                { return customRulesEnabled; }
    public void    setCustomRulesEnabled(boolean b)      { customRulesEnabled = b; }
    public boolean isCustomRulesOnly()                   { return customRulesOnly; }
    public void    setCustomRulesOnly(boolean b)         { customRulesOnly = b; }

    public synchronized List<String> getCdnBlocklist() {
        return new ArrayList<>(cdnBlocklist);
    }

    public synchronized void setCdnBlocklist(List<String> list) {
        cdnBlocklist.clear();
        if (list != null) cdnBlocklist.addAll(list);
    }

    public synchronized List<String> getKeyBlocklist() {
        return new ArrayList<>(keyBlocklist);
    }

    public synchronized void setKeyBlocklist(List<String> list) {
        keyBlocklist.clear();
        if (list != null) keyBlocklist.addAll(list);
    }

    /** Returns true if the key name contains any entry in the key blocklist (case-insensitive). */
    public synchronized boolean isKeyBlocked(String keyName) {
        if (keyName == null || keyName.isBlank()) return false;
        String kl = keyName.toLowerCase();
        for (String entry : keyBlocklist) {
            if (!entry.isBlank() && kl.contains(entry.toLowerCase())) return true;
        }
        return false;
    }

    public synchronized List<String> getKeyAllowlist() {
        return new ArrayList<>(keyAllowlist);
    }

    public synchronized void setKeyAllowlist(List<String> list) {
        keyAllowlist.clear();
        if (list != null) keyAllowlist.addAll(list);
    }

    public synchronized List<String> getCustomRules() {
        return new ArrayList<>(customRules);
    }

    public synchronized void setCustomRules(List<String> list) {
        customRules.clear();
        if (list != null) customRules.addAll(list);
    }

    /** Returns true if the key name contains any entry in the key allowlist (case-insensitive). */
    public synchronized boolean isKeyAllowlisted(String keyName) {
        if (keyName == null || keyAllowlist.isEmpty()) return false;
        String kl = keyName.toLowerCase();
        for (String entry : keyAllowlist) {
            if (!entry.isBlank() && kl.contains(entry.toLowerCase())) return true;
        }
        return false;
    }

    /**
     * Returns true if the given URL's hostname matches any entry in the CDN blocklist,
     * or if the hostname itself contains the word "cdn".
     *
     * The check is applied to the HOSTNAME only, not the full URL string, to avoid
     * false-positive CDN blocks for in-scope JS files whose path or filename happens
     * to contain a blocklist word (e.g., /js/firebase-init.js, /assets/cdn-config/app.js).
     */
    public boolean isExternalCdn(String urlOrHost) {
        if (urlOrHost == null || urlOrHost.isBlank()) return false;
        // Extract hostname when a full URL is passed; fall back to the raw value otherwise.
        String host;
        if (urlOrHost.startsWith("http://") || urlOrHost.startsWith("https://")) {
            try {
                host = new java.net.URL(urlOrHost).getHost().toLowerCase();
            } catch (Exception e) {
                host = urlOrHost.toLowerCase();
            }
        } else {
            host = urlOrHost.toLowerCase();
        }
        // Broad heuristic: any hostname starting with "cdn." is an asset CDN
        if (host.startsWith("cdn.") || host.equals("cdn")) return true;
        synchronized (this) {
            for (String entry : cdnBlocklist) {
                // Domain-suffix match: entry "segment.com" blocks cdn.segment.com,
                // abn.segment.com, analytics.segment.com but NOT api.mysegment.com
                String e = entry.toLowerCase();
                if (host.equals(e) || host.endsWith("." + e)) return true;
            }
        }
        return false;
    }

    // =========================================================================
    // Persistence
    // =========================================================================

    public void saveToPreferences(MontoyaApi api) {
        try {
            Preferences prefs = api.persistence().preferences();
            prefs.setBoolean(KEY_ENABLED,         enabled);
            prefs.setString(KEY_TIER,             tier.name());
            prefs.setString(KEY_ENTROPY,          String.valueOf(entropyThreshold));
            prefs.setBoolean(KEY_PII,             piiEnabled);
            prefs.setBoolean(KEY_SCAN_REQUESTS,       scanRequestsEnabled);
            prefs.setBoolean(KEY_ALLOW_INSECURE_SSL,  allowInsecureSsl);
            prefs.setString(KEY_CDNLIST,              String.join("\n", getCdnBlocklist()));
            prefs.setString(KEY_KEY_BLOCKLIST,    String.join("\n", getKeyBlocklist()));
            prefs.setString(KEY_KEY_ALLOWLIST,    String.join("\n", getKeyAllowlist()));
            prefs.setString(KEY_CUSTOM_RULES,         String.join("\n", getCustomRules()));
            prefs.setBoolean(KEY_CUSTOM_RULES_ENABLED, customRulesEnabled);
            prefs.setBoolean(KEY_CUSTOM_RULES_ONLY,    customRulesOnly);
        } catch (Exception ignored) {
            // Preferences not critical — continue silently
        }
    }

    public void loadFromPreferences(MontoyaApi api) {
        try {
            Preferences prefs = api.persistence().preferences();

            Boolean en = prefs.getBoolean(KEY_ENABLED);
            if (en != null) enabled = en;

            String tierStr = prefs.getString(KEY_TIER);
            if (tierStr != null) {
                try { tier = ScanTier.valueOf(tierStr); } catch (IllegalArgumentException ignored) {}
            }

            String entropyStr = prefs.getString(KEY_ENTROPY);
            if (entropyStr != null) {
                try { entropyThreshold = Double.parseDouble(entropyStr); } catch (NumberFormatException ignored) {}
            }

            Boolean pii = prefs.getBoolean(KEY_PII);
            if (pii != null) piiEnabled = pii;

            Boolean scanReqs = prefs.getBoolean(KEY_SCAN_REQUESTS);
            if (scanReqs != null) scanRequestsEnabled = scanReqs;

            Boolean insecureSsl = prefs.getBoolean(KEY_ALLOW_INSECURE_SSL);
            if (insecureSsl != null) allowInsecureSsl = insecureSsl;

            String cdnStr = prefs.getString(KEY_CDNLIST);
            if (cdnStr != null && !cdnStr.isBlank()) {
                List<String> loaded = new ArrayList<>();
                for (String line : cdnStr.split("\n")) {
                    String trimmed = line.trim();
                    if (!trimmed.isEmpty()) loaded.add(trimmed);
                }
                // Merge with built-in defaults: ensures entries added in updated JARs
                // are never silently dropped when old preferences are loaded on upgrade.
                java.util.LinkedHashSet<String> merged = new java.util.LinkedHashSet<>(getCdnBlocklist());
                merged.addAll(loaded);
                setCdnBlocklist(new ArrayList<>(merged));
            }

            String keyBlockStr = prefs.getString(KEY_KEY_BLOCKLIST);
            if (keyBlockStr != null && !keyBlockStr.isBlank()) {
                List<String> loaded = new ArrayList<>();
                for (String line : keyBlockStr.split("\n")) {
                    String trimmed = line.trim();
                    if (!trimmed.isEmpty()) loaded.add(trimmed);
                }
                setKeyBlocklist(loaded);
            }

            String keyAllowStr = prefs.getString(KEY_KEY_ALLOWLIST);
            if (keyAllowStr != null) {
                List<String> loaded = new ArrayList<>();
                for (String line : keyAllowStr.split("\n")) {
                    String trimmed = line.trim();
                    if (!trimmed.isEmpty()) loaded.add(trimmed);
                }
                setKeyAllowlist(loaded);
            }

            Boolean customRulesEn = prefs.getBoolean(KEY_CUSTOM_RULES_ENABLED);
            if (customRulesEn != null) customRulesEnabled = customRulesEn;

            Boolean customRulesOnlyEn = prefs.getBoolean(KEY_CUSTOM_RULES_ONLY);
            if (customRulesOnlyEn != null) customRulesOnly = customRulesOnlyEn;

            String customRulesStr = prefs.getString(KEY_CUSTOM_RULES);
            if (customRulesStr != null && !customRulesStr.isBlank()) {
                List<String> loaded = new ArrayList<>();
                for (String line : customRulesStr.split("\n")) {
                    String trimmed = line.trim();
                    if (!trimmed.isEmpty()) loaded.add(trimmed);
                }
                setCustomRules(loaded);
            }

        } catch (Exception ignored) {}
    }

    public void resetToDefaults() {
        enabled              = true;
        tier                 = ScanTier.FULL;
        entropyThreshold     = 3.5;
        piiEnabled           = true;
        scanRequestsEnabled  = true;
        allowInsecureSsl     = false;
        customRulesEnabled   = true;
        customRulesOnly      = false;
        synchronized (this) {
            keyBlocklist.clear();
            keyBlocklist.addAll(Arrays.asList(
                    "STORAGE_KEY_", "storage_key_",
                    "STATE_KEY_",   "state_key_",
                    "NEXT_PUBLIC_", "REACT_APP_PUBLIC_", "VUE_APP_PUBLIC_"
            ));
            keyAllowlist.clear();
            customRules.clear();
            cdnBlocklist.clear();
            cdnBlocklist.addAll(Arrays.asList(
                    "cdnjs", "jsdelivr", "unpkg", "ajax.googleapis.com",
                    "ajax.microsoft.com", "code.jquery.com", "stackpath", "maxcdn",
                    "fonts.googleapis.com", "fonts.gstatic.com", "gstatic.com",
                    "firebase", "segment.com", "segment.io", "doubleclick",
                    "googletagmanager.com", "hotjar.com",
                    "cloudflareinsights.com", "cdn.cookielaw.org",
                    "dc.services.visualstudio.com",
                    "launchdarkly.com", "data.microsoft.com",
                    "rs.fullstory.com", "edge.fullstory.com",
                    "sentry.io", "bat.bing.com", "snap.licdn.com",
                    "platform.linkedin.com", "connect.facebook.net",
                    "static.klaviyo.com", "static.ads-twitter.com",
                    "akamaiedge.net",
                    "online-metrix.net",
                    "microsoftonline.com",
                    "msauth.net",
                    "msftauth.net",
                    "live.com",
                    "adobedtm.com",
                    "omtrdc.net",
                    "demdex.net",
                    "google-analytics.com",
                    "nr-data.net",
                    "medallia.com",
                    "medallia.eu"
            ));
        }
    }
}
