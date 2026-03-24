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
    private static final String KEY_ALLOW_INSECURE_SSL = "ss.allow_insecure_ssl";

    // ---- fields ----
    private volatile boolean   enabled              = true;
    private volatile ScanTier  tier                 = ScanTier.FULL;
    private volatile double    entropyThreshold     = 3.5;
    private volatile boolean   piiEnabled           = true;
    private volatile boolean   scanRequestsEnabled  = true;
    private volatile boolean   allowInsecureSsl     = false;

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
            "online-metrix.net"         // ThreatMetrix / LexisNexis Risk Solutions
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
                setCdnBlocklist(loaded);
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

        } catch (Exception ignored) {}
    }

    public void resetToDefaults() {
        enabled              = true;
        tier                 = ScanTier.FULL;
        entropyThreshold     = 3.5;
        piiEnabled           = true;
        scanRequestsEnabled  = true;
        allowInsecureSsl     = false;
        synchronized (this) {
            keyBlocklist.clear();
            keyBlocklist.addAll(Arrays.asList(
                    "STORAGE_KEY_", "storage_key_",
                    "STATE_KEY_",   "state_key_",
                    "NEXT_PUBLIC_", "REACT_APP_PUBLIC_", "VUE_APP_PUBLIC_"
            ));
            keyAllowlist.clear();
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
                    "online-metrix.net"
            ));
        }
    }
}
