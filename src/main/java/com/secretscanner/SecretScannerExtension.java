package com.secretscanner;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.scancheck.ScanCheckType;

/**
 * SecretSifter — Burp Suite Extension (Montoya API)
 *
 * Detects exposed secrets, credentials, API keys, and PII in HTTP traffic.
 *
 * Features:
 *   - Passive secret detection via a registered PassiveScanCheck (YAML vendor rules, entropy, KV,
 *     URL creds, DB connection strings, SSR state blobs, JSON walking, PII; inline &lt;script&gt;
 *     extraction). Burp drives the check for every exchange it audits; detection never runs on its own.
 *   - WebSocket text-frame scanning (Burp exposes no passive scan check for WebSocket messages).
 *   - Active rescan via the right-click context menu; inline response-editor tab.
 *   - Bulk Scan tab: paste/import URLs, &lt;script src&gt; + webpack-chunk following, scope monitor,
 *     CSV / HTML / SARIF / JSON report export.
 *   - Configuration lives in Burp's native Settings dialog; findings reported as AuditIssue.
 */
public class SecretScannerExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(Branding.NAME);

        // 0. Permanent issue IDs (SS-102426-7K4M2Q), stable across scans and restarts
        BurpIssueStore.install(api);

        // 1. Settings model
        ScanSettings settings = new ScanSettings();

        // 2. Core scan engine
        SecretScanner scanner = new SecretScanner(settings, api.logging());

        // 3a. Passive scan check (Pro only) — the single HTTP secret-detection path.
        try {
            api.scanner().registerPassiveScanCheck(
                    new SecretScanCheck(scanner, settings, api), ScanCheckType.PER_REQUEST);
        } catch (Exception | Error ignored) {
            api.logging().logToOutput("[*] Scanner API unavailable (Community Edition) — passive scan check skipped.");
        }

        // 3b. WebSocket text frames — Burp exposes no PassiveScanCheck for WebSocket messages, so this
        //     handler is the only channel for them. All HTTP secret detection is performed exclusively
        //     by SecretScanCheck.doCheck(): there is deliberately no proxy-level HTTP response handler
        //     and no background site-map sweep, so the extension never scans traffic the user has not
        //     submitted to Burp's scanner. Existing site-map entries are (re)scanned only on demand,
        //     via the Bulk Scan tab or the right-click "Rescan for Secrets" action.
        SecretWebSocketHandler wsHandler = new SecretWebSocketHandler(scanner, settings, api);
        try {
            api.proxy().registerWebSocketCreationHandler(wsHandler);
        } catch (RuntimeException e) {
            api.logging().logToError("[SecretSifter] WebSocket scanning unavailable: " + e);
        }

        // 4. Context menu
        SecretContextMenu contextMenu = new SecretContextMenu(scanner, settings, api);
        api.userInterface().registerContextMenuItemsProvider(contextMenu);

        // 4b. Inline response tab
        api.userInterface().registerHttpResponseEditorProvider(new SecretSifterTab(scanner, api.logging()));

        // 5. UI: Bulk Scan dashboard is the suite tab; configuration goes to Burp's native Settings
        //     dialog (registerSettingsPanel), keeping the suite tab focused on operational content.
        SettingsPanel settingsPanel = new SettingsPanel(settings, api);
        BulkScanPanel bulkPanel     = new BulkScanPanel(scanner, settings, api);
        api.userInterface().registerSettingsPanel(settingsPanel);
        api.userInterface().registerSuiteTab(Branding.NAME, bulkPanel.getPanel());

        // 6. Load persisted settings
        settingsPanel.loadFromPreferences();
        bulkPanel.syncFromSettings();

        api.logging().logToOutput(Branding.banner("BApp edition"));
        api.logging().logToOutput("[*] Loaded:\t" + Branding.NAME + " v" + SecretSifterVersion.VALUE + " (Store)");
        api.logging().logToOutput("[*] Author:\tHemanth Gorijala");
        api.logging().logToOutput("[*] Config:\tTier=" + settings.getTier() +
                "  Entropy≥" + settings.getEntropyThreshold() +
                "  PII=" + settings.isPiiEnabled());

        // 7. Clean unloading
        api.extension().registerUnloadingHandler(() -> {
            bulkPanel.shutdown();
            wsHandler.shutdown();
            contextMenu.shutdown();
            scanner.clearRequestDedup();
            SitemapDeduplicator.clear();
            ScopeMonitor.clearWatched();
            ScopeMonitor.setCrossOriginFollow(false);
        });
    }
}
