package com.secretscanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Context menu provider — adds "Rescan for Secrets" to the right-click menu
 * in Proxy History, Repeater, Logger, and the Site Map.
 *
 * Scanning runs on a background thread to avoid freezing the Burp UI.
 * Results are injected into Burp's site map via api.siteMap().add() so they
 * appear in Dashboard > Issue Activity alongside passive-scan findings.
 */
public class SecretContextMenu implements ContextMenuItemsProvider {

    private final SecretScanner   scanner;
    private final ScanSettings    settings;
    private final MontoyaApi      api;
    private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "SecretSifter-ContextMenu");
        t.setDaemon(true);
        return t;
    });

    public SecretContextMenu(SecretScanner scanner, ScanSettings settings, MontoyaApi api) {
        this.scanner  = scanner;
        this.settings = settings;
        this.api      = api;
    }

    /** Called by the extension unloading handler to interrupt any in-flight rescan. */
    public void shutdown() {
        executor.shutdownNow();
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        // Only show the menu item when there are HTTP messages to scan
        boolean hasTargets = !event.selectedRequestResponses().isEmpty()
                || event.messageEditorRequestResponse().isPresent();
        if (!hasTargets) return List.of();

        JMenuItem item = new JMenuItem("Rescan for Secrets");
        item.addActionListener(e -> {
            List<HttpRequestResponse> targets = new ArrayList<>();
            // MessageEditorHttpRequestResponse wraps the actual HttpRequestResponse
            event.messageEditorRequestResponse().ifPresent(me -> targets.add(me.requestResponse()));
            targets.addAll(event.selectedRequestResponses());
            executor.submit(() -> performRescan(targets));
        });
        return List.of(item);
    }

    private void performRescan(List<HttpRequestResponse> targets) {
        // 1. Extract the set of hosts from the selected items.
        Set<String> watchedHosts = new LinkedHashSet<>();
        for (HttpRequestResponse rr : targets) {
            try {
                if (rr.request() == null) continue;
                watchedHosts.add(new java.net.URL(rr.request().url()).getHost().toLowerCase());
            } catch (Exception ignored) {}
        }

        // 2. Expand to ALL site-map items for those hosts.
        //    When the user right-clicks a domain node in Target → Site Map, Burp passes
        //    only the root-path response (or a structural node with no response). Expanding
        //    to the full site map ensures every JS/HTML/JSON/XML file already captured by
        //    Burp for that domain is scanned — not just the single item Burp happened to select.
        //    This whole method runs on the background rescan executor; api.siteMap()
        //    .requestResponses() is thread-safe, so the (potentially large) snapshot is fetched
        //    here directly and never on the Event Dispatch Thread, which would freeze the Burp UI.
        List<HttpRequestResponse> toScan = new ArrayList<>();
        if (!watchedHosts.isEmpty()) {
            List<HttpRequestResponse> siteMapSnapshot;
            try {
                siteMapSnapshot = api.siteMap().requestResponses();
            } catch (Exception e) {
                siteMapSnapshot = java.util.List.of();
                if (api != null) api.logging().logToError("SecretContextMenu: site-map retrieval failed: " + e);
            }
            try {
                for (HttpRequestResponse sm : siteMapSnapshot) {
                    if (sm.request() == null || sm.response() == null) continue;
                    String itemUrl = sm.request().url();
                    if (itemUrl == null || itemUrl.isBlank()) continue;
                    if (settings.isExternalCdn(itemUrl)) continue;
                    try {
                        String host = new java.net.URL(itemUrl).getHost().toLowerCase();
                        for (String wh : watchedHosts) {
                            if (host.equals(wh) || host.endsWith("." + wh)) {
                                toScan.add(sm);
                                break;
                            }
                        }
                    } catch (Exception ignored) {}
                }
            } catch (Exception e) {
                if (api != null) api.logging().logToError("SecretContextMenu: site-map expansion failed: " + e.toString());
            }
        }

        // 3. The items the user actually selected come first (an edited Repeater response is not
        //    in the site map), followed by the rest of the host's site-map items.
        List<HttpRequestResponse> ordered = new ArrayList<>(targets);
        ordered.addAll(toScan);
        toScan = ordered;

        // 4. Scan each unique URL.
        //    scanRequestResponse covers: response body (with inline <script> extraction for
        //    HTML pages), request headers (Authorization, x-api-key, etc.), and request body.
        int     findingCount = 0;
        Set<String> seenUrls = new HashSet<>();

        for (HttpRequestResponse rr : toScan) {
            try {
                if (rr.request() == null) continue;
                String url = rr.request().url();
                if (!seenUrls.add(url != null ? url : "")) continue;  // skip duplicate URLs
                if (rr.response() == null) continue;
                List<SecretFinding> findings = scanner.scanRequestResponseExplicit(rr);
                findingCount += findings.size();
                // One AuditIssue per (URL, rule) group for a clean sitemap
                Map<String, List<SecretFinding>> grouped = new LinkedHashMap<>();
                for (SecretFinding f : findings)
                    grouped.computeIfAbsent(f.ruleName(), k -> new ArrayList<>()).add(f);
                for (List<SecretFinding> group : grouped.values()) {
                    // explicit rescan: always (re-)add, even if the issue was added or deleted before
                    if (!SitemapDeduplicator.shouldAddForRescan(group)) continue;
                    try { api.siteMap().add(SecretFinding.toGroupedAuditIssue(group, rr)); }
                    catch (Exception e) { if (api != null) api.logging().logToError(BulkScanPanel.redactUrls("siteMap.add failed for " + url + ": " + e)); }
                }
            } catch (Exception e) {
                if (api != null) api.logging().logToError("SecretContextMenu.performRescan: " + e.toString());
            }
        }

        if (api != null) api.logging().logToOutput(String.format(
                "SecretSifter rescan: %d finding(s) in %d item(s) across %d host(s).",
                findingCount, seenUrls.size(), watchedHosts.size()));
    }
}
