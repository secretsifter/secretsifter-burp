package com.secretscanner;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.scancheck.ScanCheckType;

/**
 * SecretSifter — Burp Suite Extension (Montoya API)
 *
 * Detects exposed secrets, credentials, API keys, and PII in HTTP traffic.
 * Designed for BApp Store submission.
 *
 * Features:
 *   - Passive secret detection via a registered PassiveScanCheck (217 detection rules: anchored
 *     vendor tokens, entropy, KV, URL creds, DB connection strings, SSR state blobs, JSON walking, PII).
 *     Burp drives the check for every in-scope exchange it audits; detection never runs on its own.
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

        // 3b. All HTTP secret detection runs exclusively through SecretScanCheck.doCheck()
        //     (registered above). There is deliberately no proxy-level response handler and no
        //     background site-map sweep: the extension never scans traffic the user has not
        //     submitted to Burp's scanner. Existing site-map entries are (re)scanned only on
        //     demand — via the Bulk Scan tab or the right-click "Rescan for Secrets" action.

        // 4. Context menu
        SecretContextMenu contextMenu = new SecretContextMenu(scanner, settings, api);
        api.userInterface().registerContextMenuItemsProvider(contextMenu);

        // 4b. Inline response tab
        api.userInterface().registerHttpResponseEditorProvider(new SecretSifterTab(scanner, api.logging()));

        // 5. UI panels.
        //    Configuration is registered in Burp's native Settings dialog (registerSettingsPanel),
        //    keeping the suite tab focused on operational content — the Bulk Scan dashboard.
        SettingsPanel settingsPanel = new SettingsPanel(settings, api);
        BulkScanPanel bulkPanel     = new BulkScanPanel(scanner, settings, api);

        api.userInterface().registerSettingsPanel(settingsPanel);
        api.userInterface().registerSuiteTab("Secret Sifter", bulkPanel.getPanel());

        // 6. Load persisted settings
        settingsPanel.loadFromPreferences();
        bulkPanel.syncFromSettings();

        api.logging().logToOutput("[*] Loaded:\tSecretSifter v1.0.6 (Store)");
        api.logging().logToOutput("[*] Author:\tHemanth Gorijala");
        api.logging().logToOutput("[*] Config:\tTier=" + settings.getTier() +
                "  Entropy≥" + settings.getEntropyThreshold() +
                "  PII=" + settings.isPiiEnabled());

        // 7. Clean unloading
        api.extension().registerUnloadingHandler(() -> {
            bulkPanel.shutdown();
            contextMenu.shutdown();
            scanner.clearRequestDedup();
            SitemapDeduplicator.clear();
            ScopeMonitor.clearWatched();
            ScopeMonitor.setCrossOriginFollow(false);
        });
    }
}
