package com.secretscanner;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Session-scoped deduplication guard for api.siteMap().add() call sites.
 *
 * Burp only calls consolidateIssues() for issues returned from the passive scan check;
 * issues injected directly via api.siteMap().add() (Bulk Scan and the context-menu
 * rescan) skip that path entirely.
 *
 * This class prevents the same (normalised URL + matched value) pair from being
 * added more than once per session, regardless of which code path or rule found
 * it.  Value-based dedup ensures that when multiple rules match the same secret
 * (e.g. JWT_TOKEN, GENERIC_KV, and OAUTH_TOKEN all detecting the same JWT at the
 * same URL), only the first matching rule produces a site-map entry — preventing
 * the same credential from appearing 2–3 times with different rule names.
 */
public final class SitemapDeduplicator {

    /** Key separator — U+0000 cannot appear in a URL or matched value. */
    private static final char SEP = '\u0000';

    private static final ConcurrentHashMap<String, Boolean> seen =
            new ConcurrentHashMap<>();

    private SitemapDeduplicator() {}

    /**
     * Returns {@code true} (and marks the pair as seen) if this
     * (normalised url, matchedValue) has NOT been recorded before.
     * Returns {@code false} when the pair was already recorded — the caller
     * should skip the siteMap().add() call.
     */
    public static boolean tryAdd(String url, String value) {
        if (url == null)   url   = "";
        if (value == null) value = "";
        String key = url + SEP + value;
        return seen.putIfAbsent(key, Boolean.TRUE) == null;
    }

    /**
     * Atomically claims the (normalised url, ruleName) group, then marks each
     * matched value as seen for cross-rule deduplication.
     *
     * The group-level claim uses a single {@code putIfAbsent} so only one thread
     * (ProxyHandler or PassiveScanCheck, whichever arrives first) can win — this
     * eliminates the race where both paths interleave their per-value tryAdd calls
     * and both end up with anyNew=true, causing duplicate sitemap entries.
     *
     * @param group non-empty list of findings (typically the same ruleName)
     * @return true if the group should be added to the sitemap
     */
    public static boolean shouldAdd(List<SecretFinding> group) {
        if (group == null || group.isEmpty()) return false;
        SecretFinding first = group.get(0);
        String url = first.sourceUrl();
        if (url != null) {
            int h = url.indexOf('#');
            if (h >= 0) url = url.substring(0, h);
            // Strip query string: same endpoint with different params (e.g. ?userId=1 vs ?userId=2)
            // produces the same secret finding and should not create duplicate site-map entries.
            int q = url.indexOf('?');
            if (q >= 0) url = url.substring(0, q);
            for (String suf : new String[]{" [HTML]", " [JS]", " [JSON]", " [XML]", " [REQ-HEADERS]"})
                if (url.endsWith(suf)) { url = url.substring(0, url.length() - suf.length()); break; }
        }
        String normUrl = url == null ? "" : url;
        // Atomically claim this (url, ruleName) slot — \u0001 prefix distinguishes group
        // keys from per-value keys so they can never collide in the same map.
        String groupKey = '\u0001' + normUrl + SEP + first.ruleName();
        if (seen.putIfAbsent(groupKey, Boolean.TRUE) != null) return false;
        // Cross-rule value dedup: if every value in this group was already reported at
        // this URL by an earlier rule (e.g. REQ_HEADER and AZURE_APIM_004 both fire for
        // the same subscription key), suppress the duplicate group entirely.
        boolean anyNew = false;
        for (SecretFinding f : group) {
            if (tryAdd(normUrl, f.matchedValue())) anyNew = true;
        }
        return anyNew;
    }

    /** Clears all tracked entries — call on extension unload. */
    public static void clear() {
        seen.clear();
    }
}
