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
        //    Site-map snapshot must be fetched on the EDT — on macOS Burp's internal model is
        //    Swing-backed and requestResponses() returns an empty list from a background thread.
        List<HttpRequestResponse> toScan = new ArrayList<>();
        if (!watchedHosts.isEmpty()) {
            @SuppressWarnings("unchecked")
            java.util.List<HttpRequestResponse>[] smRef = new java.util.List[]{java.util.List.of()};
            try {
                javax.swing.SwingUtilities.invokeAndWait(() -> smRef[0] = api.siteMap().requestResponses());
            } catch (Exception ignored) {}
            try {
                for (HttpRequestResponse sm : smRef[0]) {
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

        // 3. Fallback: if the site map returned no items (e.g. called from Repeater or
        //    Proxy History before the target appears in the site map), scan the originally
        //    selected items directly.
        if (toScan.isEmpty()) {
            toScan = new ArrayList<>(targets);
        }

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
                List<SecretFinding> findings = scanner.scanRequestResponse(rr);
                findingCount += findings.size();
                // One AuditIssue per (URL, rule) group for a clean sitemap
                Map<String, List<SecretFinding>> grouped = new LinkedHashMap<>();
                for (SecretFinding f : findings)
                    grouped.computeIfAbsent(f.ruleName(), k -> new ArrayList<>()).add(f);
                for (List<SecretFinding> group : grouped.values()) {
                    if (!SitemapDeduplicator.shouldAdd(group)) continue;
                    try { api.siteMap().add(SecretFinding.toGroupedAuditIssue(group, rr)); }
                    catch (Exception e) { if (api != null) api.logging().logToError("siteMap.add failed for " + url + ": " + e.toString()); }
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
