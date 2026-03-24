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

        // 1. Settings model (loaded from Burp preferences after SettingsPanel is wired)
        ScanSettings settings = new ScanSettings();

        // 2. Core scan engine (stateless — safe for concurrent passiveScan() calls)
        SecretScanner scanner = new SecretScanner(settings, api.logging());

        // 3a. Passive scan check — scope-aware; creates AuditIssues for Burp's Dashboard
        //     Scanner API is Pro-only; Community Edition throws UnsupportedOperationException.
        try {
            api.scanner().registerPassiveScanCheck(
                    new SecretScanCheck(scanner, settings, api), ScanCheckType.PER_REQUEST);
        } catch (Exception | Error ignored) {
            api.logging().logToOutput("[*] Scanner API unavailable (Community Edition) — passive scan check skipped.");
        }

        // 3b. Proxy handler — fires for ALL traffic (not scope-limited); routes cross-origin
        //     findings (api.example.com called from app.example.com) to the Bulk Scan panel
        //     via ScopeMonitor using the request Referer/Origin headers.
        SecretProxyHandler proxyHandler = new SecretProxyHandler(scanner, settings, api);
        api.proxy().registerResponseHandler(proxyHandler);

        // 4. Context menu — right-click "Rescan for Secrets" in Proxy History / Repeater
        SecretContextMenu contextMenu = new SecretContextMenu(scanner, settings, api);
        api.userInterface().registerContextMenuItemsProvider(contextMenu);

        // 5. Settings panel + Bulk Scan panel — merged into a single suite tab
        SettingsPanel settingsPanel = new SettingsPanel(settings, api);
        BulkScanPanel bulkPanel    = new BulkScanPanel(scanner, settings, api);

        // Single top-level tab with two sub-tabs to keep Burp's tab bar uncluttered
        JTabbedPane tabPane = new JTabbedPane();
        tabPane.addTab("Bulk Scan", bulkPanel.getPanel());
        tabPane.addTab("Settings",  settingsPanel.getPanel());
        api.userInterface().registerSuiteTab("Secret Sifter", tabPane);

        // 6. Load persisted settings (must happen after panels are registered so UI syncs)
        settingsPanel.loadFromPreferences();
        bulkPanel.syncFromSettings();   // restore saved scan tier into the BulkScan combo
        bulkPanel.syncHttpClient();     // rebuild HTTP_CLIENT now that allowInsecureSsl pref is loaded

        // 7. Sitemap sweep — scan responses already recorded in Burp's sitemap so that
        //    findings appear immediately on load, just like JSMiner's passive scan check
        //    retroactively covers existing traffic.  Runs on a daemon background thread;
        //    only response bodies are scanned (request-header scanning uses the proxy
        //    handler for live traffic to avoid seenRequestValues cross-contamination).
        //    Burp's site-map model is Swing-backed on macOS — snapshot must be fetched
        //    on the EDT, then processing continues on the background thread.
        Thread sitemapSweep = new Thread(() -> {
            try { Thread.sleep(1500); } catch (InterruptedException ignored) { return; }
            if (!settings.isEnabled()) return;
            // Use a single-element array as a mutable EDT→background carrier.
            // The unchecked cast is unavoidable with Java generic arrays; suppressed here.
            @SuppressWarnings("unchecked")
            List<HttpRequestResponse>[] ref = new List[]{List.of()};
            try {
                SwingUtilities.invokeAndWait(
                        () -> ref[0] = api.siteMap().requestResponses());
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

        // 8. Unloading handler — terminates background threads when extension is removed/reloaded.
        //    Required by BApp Store acceptance criteria (criterion #6: Clean Unloading).
        api.extension().registerUnloadingHandler(() -> {
            bulkPanel.shutdown();          // stops scan, interrupts siteMapSweepThread, releases index
            sitemapSweep.interrupt();      // stop the startup sitemap sweep if still running
            proxyHandler.shutdown();
            contextMenu.shutdown();
            scanner.clearRequestDedup();   // free proxy-handler dedup set
            SitemapDeduplicator.clear();
            ScopeMonitor.clearWatched();
            ScopeMonitor.setCrossOriginFollow(false);
        });

        api.logging().logToOutput("[*] Loaded:\tSecretSifter v1.0.0");
        api.logging().logToOutput("[*] Author:\tHemanth Gorijala");
        api.logging().logToOutput("[*] Config:\tTier=" + settings.getTier() +
                "  Entropy≥" + settings.getEntropyThreshold() +
                "  PII=" + settings.isPiiEnabled());
    }
}
