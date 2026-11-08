package com.secretscanner;

import java.net.URL;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Lightweight bridge that lets the passive scan check forward findings
 * to the Bulk Scan panel's scope monitor without creating a circular dependency.
 *
 * Usage:
 *   - BulkScanPanel calls ScopeMonitor.setListener() when scope monitor is toggled on.
 *   - SecretScanCheck calls ScopeMonitor.notify() for every passive finding.
 *   - ScopeMonitor checks if the URL is in the watched set and dispatches to listener.
 */
public final class ScopeMonitor {

    public interface Listener {
        void onPassiveFinding(SecretFinding finding, String url);
    }

    private static volatile boolean          active           = false;
    private static volatile boolean          crossOriginFollow = false;
    private static volatile Listener         listener         = null;
    private static final Set<String>         watchedHosts =
            ConcurrentHashMap.newKeySet();
    private ScopeMonitor() {}

    // -------------------------------------------------------------------------

    public static void setActive(boolean on)            { active = on; }
    public static boolean isActive()                    { return active; }

    public static void setCrossOriginFollow(boolean on) { crossOriginFollow = on; }
    public static boolean isCrossOriginFollow()         { return crossOriginFollow; }

    public static void setListener(Listener l) { listener = l; }

    public static void addWatchedUrl(String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) return;
        String url = rawUrl.trim();
        // "example.com/app" (no scheme) is a host plus path, not a host
        if (!url.matches("(?i)^[a-z][a-z0-9+.\\-]*://.*")) url = "https://" + url;
        String host = extractHost(url);
        if (host != null) watchedHosts.add(host.toLowerCase());
        // Also store the URL prefix (scheme-less, lower-case) for path-level matching
        watchedHosts.add(stripScheme(url.toLowerCase()));
    }

    public static void clearWatched() { watchedHosts.clear(); }

    // -------------------------------------------------------------------------

    /**
     * Returns true if the given URL's host is in the watched-host set.
     * Used by the Bulk Scan scope monitor to avoid routing unrelated traffic.
     */
    public static boolean isWatched(String url) {
        if (url == null || url.isBlank()) return false;
        String host = extractHost(url);
        if (host == null) return false;
        return matchesWatched(host.toLowerCase(), url);
    }

    /**
     * Host equal to a watched host, or URL under a watched path prefix on a path boundary:
     * a watched "example.com" must not match "example.com.evil.net" or "example.community".
     */
    private static boolean matchesWatched(String host, String url) {
        String u = stripScheme(url.toLowerCase());
        for (String watched : watchedHosts) {
            if (host.equals(watched)) return true;
            if (watched.contains("/") || watched.contains(":")) {
                if (u.startsWith(watched)) {
                    if (u.length() == watched.length() || watched.endsWith("/")) return true;
                    char next = u.charAt(watched.length());
                    if (next == '/' || next == '?' || next == '#') return true;
                }
            }
        }
        return false;
    }

    private static String stripScheme(String url) {
        int i = url.indexOf("://");
        return i >= 0 ? url.substring(i + 3) : url;
    }

    /**
     * Called by SecretScanCheck after each passive scan.
     * Checks if the URL matches any watched entry and dispatches to the listener.
     */
    public static void notify(SecretFinding finding, String url) {
        if (!active || listener == null || url == null) return;
        String host = extractHost(url);
        boolean matches = host != null && matchesWatched(host.toLowerCase(), url);
        if (matches) {
            listener.onPassiveFinding(finding, url);
        }
    }

    // -------------------------------------------------------------------------

    private static String extractHost(String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) return null;
        try {
            return new URL(rawUrl).getHost();
        } catch (Exception e) {
            // Might be a hostname without scheme — return as-is
            return rawUrl.contains("/") ? null : rawUrl;
        }
    }

}
