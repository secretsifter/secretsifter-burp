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
        String host = extractHost(rawUrl);
        if (host != null) watchedHosts.add(host.toLowerCase());
        // Also store the raw URL prefix for path-level matching
        if (rawUrl != null && !rawUrl.isBlank()) watchedHosts.add(rawUrl.toLowerCase());
    }

    public static void clearWatched() { watchedHosts.clear(); }

    // -------------------------------------------------------------------------

    /**
     * Returns true if the given URL's host is in the watched-host set.
     * Used by SecretProxyHandler to avoid scanning unrelated traffic.
     */
    public static boolean isWatched(String url) {
        if (url == null || url.isBlank()) return false;
        String host = extractHost(url);
        if (host == null) return false;
        String h = host.toLowerCase();
        for (String watched : watchedHosts) {
            if (h.equals(watched) || url.toLowerCase().startsWith(watched)) return true;
        }
        return false;
    }

    /**
     * Called by SecretScanCheck after each passive scan.
     * Checks if the URL matches any watched entry and dispatches to the listener.
     */
    public static void notify(SecretFinding finding, String url) {
        if (!active || listener == null || url == null) return;
        String host = extractHost(url);
        boolean matches = false;
        if (host != null) {
            String h = host.toLowerCase();
            for (String watched : watchedHosts) {
                if (h.equals(watched) || url.toLowerCase().startsWith(watched)) {
                    matches = true;
                    break;
                }
            }
        }
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
