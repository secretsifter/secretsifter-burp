package com.secretscanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Passive scan check — called by Burp for every HTTP exchange flowing through
 * the proxy, repeater, or scanner.
 */
public class SecretScanCheck implements PassiveScanCheck {

    private final SecretScanner scanner;
    private final ScanSettings  settings;
    private final MontoyaApi    api;

    public SecretScanCheck(SecretScanner scanner, ScanSettings settings, MontoyaApi api) {
        this.scanner  = scanner;
        this.settings = settings;
        this.api      = api;
    }

    @Override
    public String checkName() {
        return "SecretSifter";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse requestResponse) {
        if (!settings.isEnabled()) return AuditResult.auditResult(List.of());
        try {
            List<SecretFinding> findings = scanner.scanRequestResponse(requestResponse);
            // Route to Bulk Scan panel immediately — Burp's scanner thread runs doCheck()
            // faster than SecretProxyHandler's 2-thread executor pool, so routing here closes
            // the gap between "site map shows findings" and "bulk scan table shows findings".
            // seenFindings dedup in appendFinding prevents any double-counting.
            if (ScopeMonitor.isActive() && !findings.isEmpty()
                    && requestResponse.request() != null) {
                String url = requestResponse.request().url();
                if (url != null) {
                    for (SecretFinding f : findings) {
                        ScopeMonitor.notify(f, url);
                    }
                }
            }
            // Group by ruleName → one AuditIssue per (URL, rule) for a clean sitemap
            Map<String, List<SecretFinding>> grouped = new LinkedHashMap<>();
            for (SecretFinding f : findings)
                grouped.computeIfAbsent(f.ruleName(), k -> new ArrayList<>()).add(f);
            List<AuditIssue> issues = new ArrayList<>();
            for (List<SecretFinding> group : grouped.values())
                if (SitemapDeduplicator.shouldAdd(group))
                    issues.add(SecretFinding.toGroupedAuditIssue(group, requestResponse));
            return AuditResult.auditResult(issues);
        } catch (Exception e) {
            if (api != null)
                api.logging().logToError("SecretScanCheck.doCheck: " + e.toString());
            return AuditResult.auditResult(List.of());
        }
    }

    /**
     * Deduplication strategy:
     * - Same name + URL + detail → true duplicate (e.g. JS file re-scanned) → KEEP_EXISTING.
     * - Same name + URL but different detail → different secrets (e.g. two distinct apiKey
     *   values in the same file) → KEEP_BOTH so both are reported.
     * - Different name or URL → KEEP_BOTH.
     */
    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        if (existingIssue.name().equals(newIssue.name()) &&
            existingIssue.baseUrl().equals(newIssue.baseUrl()) &&
            Objects.equals(existingIssue.detail(), newIssue.detail())) {
            return ConsolidationAction.KEEP_EXISTING;
        }
        return ConsolidationAction.KEEP_BOTH;
    }
}
