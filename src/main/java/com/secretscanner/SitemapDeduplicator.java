package com.secretscanner;

import com.secretscanner.core.IssueRegistry;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Session-scoped deduplication guard for api.siteMap().add() call sites.
 *
 * Burp only calls consolidateIssues() for issues returned from passiveAudit(); issues injected
 * directly via api.siteMap().add() (the WebSocket handler, Bulk Scan, and
 * context-menu rescan) skip that path entirely.
 *
 * One namespace for every path: a secret value at a URL (query and fragment ignored) is added
 * once per session, whichever path or rule finds it first. Earlier versions kept a separate map
 * for the proxy handler, so an in-scope response was filed twice (passive check + proxy), and
 * claimed a (url, rule) slot for the session, so a different secret at the same path under the
 * same rule was silently dropped. Keys hold the secret's keyed fingerprint, never the secret.
 */
public final class SitemapDeduplicator {

    /** Key separator — U+0000 cannot appear in a URL or a fingerprint. */
    private static final char SEP = '\u0000';

    /** Upper bound on remembered (url, value) pairs; cleared when exceeded to bound memory. */
    private static final int MAX_ENTRIES = 200_000;

    private static final ConcurrentHashMap<String, Boolean> seen = new ConcurrentHashMap<>();

    private SitemapDeduplicator() {}

    /** URL without fragment, query string or the scanner's " [JS]"-style source labels. */
    static String normalizeUrl(String url) {
        if (url == null) return "";
        String u = url;
        int h = u.indexOf('#');
        if (h >= 0) u = u.substring(0, h);
        u = u.replaceFirst(" \\[[^\\]]*\\]$", "");
        int q = u.indexOf('?');
        if (q >= 0) u = u.substring(0, q);
        return u;
    }

    /**
     * Returns {@code true} (and marks the pair as seen) if this (normalised url, value) has not
     * been recorded before.
     */
    public static boolean tryAdd(String url, String value) {
        if (seen.size() > MAX_ENTRIES) seen.clear();
        String key = normalizeUrl(url) + SEP + IssueRegistry.fingerprint(value == null ? "" : value);
        return seen.putIfAbsent(key, Boolean.TRUE) == null;
    }

    /**
     * True if the group holds at least one value not yet added at this URL by any path. All values
     * are marked seen. Synchronized so two paths racing on the same response cannot both win.
     */
    public static synchronized boolean shouldAdd(List<SecretFinding> group) {
        if (group == null || group.isEmpty()) return false;
        String url = group.get(0).sourceUrl();
        boolean anyNew = false;
        for (SecretFinding f : group) {
            if (tryAdd(url, f.matchedValue())) anyNew = true;
        }
        return anyNew;
    }

    /** Proxy and WebSocket handlers: same namespace as every other path. */
    public static boolean shouldAddProxy(List<SecretFinding> group) {
        return shouldAdd(group);
    }

    /**
     * An explicit, user-requested rescan always re-adds its issues (the user may have deleted
     * them in Burp); the values are still recorded so passive paths do not add them again.
     */
    public static synchronized boolean shouldAddForRescan(List<SecretFinding> group) {
        if (group == null || group.isEmpty()) return false;
        for (SecretFinding f : group) tryAdd(f.sourceUrl(), f.matchedValue());
        return true;
    }

    /** Clears all tracked entries — call on extension unload and when results are cleared. */
    public static void clear() {
        seen.clear();
    }
}
