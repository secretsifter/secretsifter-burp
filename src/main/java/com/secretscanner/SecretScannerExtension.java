package com.secretscanner;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.scancheck.ScanCheckType;

import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * SecretSifter — Burp Suite Extension (Montoya API)
 *
 * Detects exposed secrets, credentials, API keys, and PII in HTTP traffic.
 * Designed for BApp Store submission.
 *
 * Features:
 *   - Passive scanning of all proxy traffic (217 detection rules: anchored vendor tokens, entropy, KV,
 *     URL creds, DB connection strings, SSR state blobs, JSON walking, PII)
 *     Includes HTML inline script extraction (scans secrets in <script> tags)
 *   - Active rescan via right-click context menu with Save HTML Report option
 *   - Bulk Scan tab: paste/import 100+ URLs, script-src following, webpack
 *     chunk following (depth-1), scope monitor, CSV + HTML report export
 *   - FP mitigations: Angular/Vue directive filter, encoding alphabet filter,
 *     CC floating-point literal guard
 *   - Settings tab: scan tier, entropy threshold, PII toggle, CDN blocklist
 *   - Findings reported as AuditIssue in Dashboard > Issue Activity
 */
public class SecretScannerExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("SecretSifter");

        // 1. Settings model
        ScanSettings settings = new ScanSettings();

        // 2. Core scan engine
        SecretScanner scanner = new SecretScanner(settings, api.logging());

        // 3a. Passive scan check (Pro only)
        try {
            api.scanner().registerPassiveScanCheck(
                    new SecretScanCheck(scanner, settings, api), ScanCheckType.PER_REQUEST);
        } catch (Exception | Error ignored) {
            api.logging().logToOutput("[*] Scanner API unavailable (Community Edition) — passive scan check skipped.");
        }

        // 3b. Proxy handler
        SecretProxyHandler proxyHandler = new SecretProxyHandler(scanner, settings, api);
        api.proxy().registerResponseHandler(proxyHandler);

        // 4. Context menu
        SecretContextMenu contextMenu = new SecretContextMenu(scanner, settings, api);
        api.userInterface().registerContextMenuItemsProvider(contextMenu);

        // 4b. Inline response tab
        api.userInterface().registerHttpResponseEditorProvider(new SecretSifterTab(scanner));

        // 5. UI panels
        SettingsPanel settingsPanel = new SettingsPanel(settings, api);
        BulkScanPanel bulkPanel    = new BulkScanPanel(scanner, settings, api);

        JTabbedPane tabPane = new JTabbedPane();
        tabPane.addTab("Bulk Scan", bulkPanel.getPanel());
        tabPane.addTab("Settings",  settingsPanel.getPanel());
        api.userInterface().registerSuiteTab("Secret Sifter", tabPane);

        // 6. Load persisted settings
        settingsPanel.loadFromPreferences();
        bulkPanel.syncFromSettings();
        bulkPanel.syncHttpClient();

        api.logging().logToOutput("[*] Loaded:\tSecretSifter v1.0.1 (Store)");
        api.logging().logToOutput("[*] Author:\tHemanth Gorijala");
        api.logging().logToOutput("[*] Config:\tTier=" + settings.getTier() +
                "  Entropy≥" + settings.getEntropyThreshold() +
                "  PII=" + settings.isPiiEnabled());

        // 7. Sitemap sweep
        Thread sitemapSweep = new Thread(() -> {
            try { Thread.sleep(1500); } catch (InterruptedException ignored) { return; }
            if (!settings.isEnabled()) return;
            @SuppressWarnings("unchecked")
            List<HttpRequestResponse>[] ref = new List[]{List.of()};
            try {
                SwingUtilities.invokeAndWait(() -> ref[0] = api.siteMap().requestResponses());
            } catch (Exception ignored) { return; }
            for (HttpRequestResponse rr : ref[0]) {
                if (!settings.isEnabled()) break;
                if (rr == null || rr.request() == null || rr.response() == null) continue;
                String url = rr.request().url();
                if (url == null || settings.isExternalCdn(url)) continue;
                int status = rr.response().statusCode();
                if (status < 200 || status >= 400) continue;
                String body = rr.response().bodyToString();
                if (body == null || body.length() < 50) continue;
                String ct = rr.response().headerValue("Content-Type");
                try {
                    List<SecretFinding> findings = scanner.scanText(body, ct, url);
                    if (!findings.isEmpty()) {
                        Map<String, List<SecretFinding>> grouped = new LinkedHashMap<>();
                        for (SecretFinding f : findings)
                            grouped.computeIfAbsent(f.ruleName(), k -> new ArrayList<>()).add(f);
                        for (List<SecretFinding> group : grouped.values())
                            if (SitemapDeduplicator.shouldAdd(group))
                                api.siteMap().add(SecretFinding.toGroupedAuditIssue(group, rr));
                    }
                } catch (Exception ignored) {}
            }
        }, "SecretSifter-SitemapSweep");
        sitemapSweep.setDaemon(true);
        sitemapSweep.start();

        // 8. Clean unloading
        api.extension().registerUnloadingHandler(() -> {
            bulkPanel.shutdown();
            sitemapSweep.interrupt();
            proxyHandler.shutdown();
            contextMenu.shutdown();
            scanner.clearRequestDedup();
            SitemapDeduplicator.clear();
            ScopeMonitor.clearWatched();
            ScopeMonitor.setCrossOriginFollow(false);
        });
    }
}
