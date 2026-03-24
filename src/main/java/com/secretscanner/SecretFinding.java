package com.secretscanner;

import burp.api.montoya.core.Marker;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Immutable record representing a single secret finding.
 * Carries all data needed to construct a Montoya AuditIssue.
 */
public record SecretFinding(
        String ruleId,
        String ruleName,
        String keyName,
        String matchedValue,
        String severity,    // "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATION"
        String confidence,  // "CERTAIN", "FIRM", "TENTATIVE"
        int    lineNumber,
        String context,
        String sourceUrl
) {
    /** Convenience factory */
    public static SecretFinding of(String ruleId, String ruleName,
            String key, String value, String severity, String confidence,
            int line, String context, String url) {
        return new SecretFinding(ruleId, ruleName, key, value,
                severity, confidence, line, context, url);
    }

    /**
     * Convert this finding to a Montoya AuditIssue.
     * @param requestResponse the originating request/response (may be null for injected issues)
     */
    public AuditIssue toAuditIssue(HttpRequestResponse requestResponse) {
        AuditIssueSeverity sev = switch (severity.toUpperCase()) {
            case "CRITICAL"    -> AuditIssueSeverity.HIGH;  // Montoya has no CRITICAL; report as HIGH
            case "HIGH"        -> AuditIssueSeverity.HIGH;
            case "MEDIUM"      -> AuditIssueSeverity.MEDIUM;
            case "LOW"         -> AuditIssueSeverity.LOW;
            default            -> AuditIssueSeverity.INFORMATION;
        };
        AuditIssueConfidence conf = switch (confidence.toUpperCase()) {
            case "CERTAIN"  -> AuditIssueConfidence.CERTAIN;
            case "FIRM"     -> AuditIssueConfidence.FIRM;
            default         -> AuditIssueConfidence.TENTATIVE;
        };

        // Truncate long values to avoid UI flooding
        String displayValue = matchedValue.length() > 80
                ? matchedValue.substring(0, 77) + "..."
                : matchedValue;
        // Clean detail — no <code> tags (Swing HTMLEditorKit renders them inconsistently)
        String detail =
                "<b>" + escapeHtml(ruleName) + "</b> &nbsp;<i>(" + escapeHtml(ruleId) + ")</i><br><br>" +
                "<table cellpadding=\"3\">" +
                "<tr><td><b>Key&nbsp;/&nbsp;Field</b></td><td>" + escapeHtml(keyName) + "</td></tr>" +
                "<tr><td><b>Matched&nbsp;Value</b></td><td>" + escapeHtml(displayValue) + "</td></tr>" +
                "</table>";

        String background =
                "A secret, credential, or sensitive token was detected in HTTP traffic. " +
                "Secrets exposed in JavaScript files, API responses, or HTML source can be " +
                "harvested by any user with access to the application. " +
                "Rotate or revoke the identified credential immediately and review how it " +
                "was exposed (hardcoded value, SSR state blob, API response leakage, etc.).";

        String remediationDetail =
                "Remove the secret from client-accessible content. " +
                "Use server-side environment variables and never embed live credentials " +
                "in front-end assets or API responses.";

        // Strip #fragment and display suffixes from the baseUrl
        String issueBaseUrl = sourceUrl;
        if (issueBaseUrl != null) {
            int hashIdx = issueBaseUrl.indexOf('#');
            if (hashIdx >= 0) issueBaseUrl = issueBaseUrl.substring(0, hashIdx);
            if (issueBaseUrl.endsWith(" [HTML]"))
                issueBaseUrl = issueBaseUrl.substring(0, issueBaseUrl.length() - 7);
        }

        // Add response marker to highlight the matched value in Burp's Response tab
        HttpRequestResponse markedRr = addResponseMarkers(requestResponse, List.of(matchedValue));

        return AuditIssue.auditIssue(
                "[SecretSifter] " + ruleName,
                detail,
                background,
                issueBaseUrl,
                sev,
                conf,
                remediationDetail,
                null,
                sev,
                markedRr
        );
    }

    /**
     * Creates a single AuditIssue representing a group of findings that share the
     * same rule (ruleName) and source URL — Option A grouping for a clean sitemap.
     *
     * Instead of N separate sitemap entries for N occurrences of the same secret
     * type in one JS/JSON file, this produces ONE entry whose detail lists all N
     * key→value occurrences in a compact HTML table.
     *
     * Severity and confidence are set to the highest values observed in the group.
     *
     * @param group non-empty list of findings with the same ruleName and sourceUrl
     * @param rr    originating request/response (may be null)
     */
    public static AuditIssue toGroupedAuditIssue(List<SecretFinding> group,
                                                  HttpRequestResponse rr) {
        if (group == null || group.isEmpty())
            throw new IllegalArgumentException("finding group must not be empty");
        SecretFinding first = group.get(0);

        // Highest severity / confidence across the group
        AuditIssueSeverity  maxSev  = maxSeverity(group);
        AuditIssueConfidence maxConf = maxConfidence(group);

        // Detail: clean HTML table listing every (key, value, line, context).
        // No <code> tags — Swing HTMLEditorKit renders them inconsistently.
        StringBuilder detail = new StringBuilder();
        detail.append("<b>").append(group.size())
              .append(" instance(s) of <i>").append(escapeHtml(first.ruleName()))
              .append("</i> found:</b><br><br>");
        detail.append("<table border=\"1\" cellpadding=\"4\" cellspacing=\"0\">")
              .append("<tr>")
              .append("<td width=\"40\" align=\"center\"><b>&nbsp;#&nbsp;</b></td>")
              .append("<td><b>Key&nbsp;/&nbsp;Field</b></td>")
              .append("<td><b>Matched&nbsp;Value</b></td>")
              .append("</tr>");
        for (int i = 0; i < group.size(); i++) {
            SecretFinding f = group.get(i);
            String dv = f.matchedValue().length() > 80
                    ? f.matchedValue().substring(0, 77) + "..." : f.matchedValue();
            detail.append("<tr>")
                  .append("<td width=\"40\" align=\"center\">&nbsp;").append(i + 1).append("&nbsp;</td>")
                  .append("<td>").append(escapeHtml(f.keyName())).append("</td>")
                  .append("<td>").append(escapeHtml(dv)).append("</td>")
                  .append("</tr>");
        }
        detail.append("</table>");

        String background =
                "A secret, credential, or sensitive token was detected in HTTP traffic. " +
                "Secrets exposed in JavaScript files, API responses, or HTML source can be " +
                "harvested by any user with access to the application. " +
                "Rotate or revoke the identified credential immediately and review how it " +
                "was exposed (hardcoded value, SSR state blob, API response leakage, etc.).";

        String remediationDetail =
                "Remove the secret from client-accessible content. " +
                "Use server-side environment variables and never embed live credentials " +
                "in front-end assets or API responses.";

        // Clean URL — strip #fragment and display suffixes
        String issueBaseUrl = first.sourceUrl();
        if (issueBaseUrl != null) {
            int hashIdx = issueBaseUrl.indexOf('#');
            if (hashIdx >= 0) issueBaseUrl = issueBaseUrl.substring(0, hashIdx);
            if (issueBaseUrl.endsWith(" [HTML]"))
                issueBaseUrl = issueBaseUrl.substring(0, issueBaseUrl.length() - 7);
            if (issueBaseUrl.endsWith(" [JS]"))
                issueBaseUrl = issueBaseUrl.substring(0, issueBaseUrl.length() - 5);
            if (issueBaseUrl.endsWith(" [JSON]"))
                issueBaseUrl = issueBaseUrl.substring(0, issueBaseUrl.length() - 7);
            if (issueBaseUrl.endsWith(" [XML]"))
                issueBaseUrl = issueBaseUrl.substring(0, issueBaseUrl.length() - 6);
            if (issueBaseUrl.endsWith(" [REQ-HEADERS]"))
                issueBaseUrl = issueBaseUrl.substring(0, issueBaseUrl.length() - 14);
        }

        // Collect all matched values and add response markers so Burp highlights
        // them in the Response tab (same behaviour as JSMiner).
        List<String> vals = new ArrayList<>(group.size());
        for (SecretFinding f : group) vals.add(f.matchedValue());
        HttpRequestResponse markedRr = addResponseMarkers(rr, vals);

        return AuditIssue.auditIssue(
                "[SecretSifter] " + first.ruleName(),
                detail.toString(),
                background,
                issueBaseUrl,
                maxSev,
                maxConf,
                remediationDetail,
                null,
                maxSev,
                markedRr
        );
    }

    // -------------------------------------------------------------------------
    // Response highlighting
    // -------------------------------------------------------------------------

    /**
     * Returns a copy of {@code rr} with response markers added at every byte
     * position where any of {@code values} occurs in the raw HTTP response.
     * Returns the original {@code rr} unchanged if highlighting is not possible
     * (null rr, no response, response too large, or any exception).
     *
     * Markers cause Burp to highlight the matched bytes in the Response tab,
     * mirroring the behaviour of JSMiner.
     */
    private static HttpRequestResponse addResponseMarkers(HttpRequestResponse rr,
                                                           List<String> values) {
        if (rr == null || rr.response() == null) return rr;
        try {
            // Use the full raw response (status-line + headers + body) as bytes.
            // withResponseMarkers() offsets are into this byte array.
            byte[] respBytes = rr.response().toString()
                    .getBytes(StandardCharsets.UTF_8);
            if (respBytes.length > 4 * 1024 * 1024) return rr; // skip if > 4 MB

            List<Marker> markers = new ArrayList<>();
            for (String val : values) {
                if (val == null || val.length() < 4) continue;
                byte[] valBytes = val.getBytes(StandardCharsets.UTF_8);
                int limit = respBytes.length - valBytes.length;
                outer:
                for (int i = 0; i <= limit; i++) {
                    for (int j = 0; j < valBytes.length; j++) {
                        if (respBytes[i + j] != valBytes[j]) continue outer;
                    }
                    markers.add(Marker.marker(Range.range(i, i + valBytes.length)));
                    i += valBytes.length - 1;
                    if (markers.size() >= 50) break; // cap total markers per issue
                }
            }
            if (!markers.isEmpty()) return rr.withResponseMarkers(markers);
        } catch (Exception ignored) {}
        return rr;
    }

    // -------------------------------------------------------------------------
    // Severity / confidence helpers
    // -------------------------------------------------------------------------

    private static int severityRank(String s) {
        return switch (s == null ? "" : s.toUpperCase()) {
            case "CRITICAL" -> 4;
            case "HIGH"     -> 3;
            case "MEDIUM"   -> 2;
            case "LOW"      -> 1;
            default         -> 0;
        };
    }

    private static int confidenceRank(String c) {
        return switch (c == null ? "" : c.toUpperCase()) {
            case "CERTAIN"  -> 2;
            case "FIRM"     -> 1;
            default         -> 0;
        };
    }

    private static AuditIssueSeverity maxSeverity(List<SecretFinding> group) {
        String best = group.stream()
                .max((a, b) -> severityRank(a.severity()) - severityRank(b.severity()))
                .map(SecretFinding::severity).orElse("INFORMATION");
        return switch (best.toUpperCase()) {
            case "CRITICAL" -> AuditIssueSeverity.HIGH;  // Montoya has no CRITICAL; report as HIGH
            case "HIGH"     -> AuditIssueSeverity.HIGH;
            case "MEDIUM"   -> AuditIssueSeverity.MEDIUM;
            case "LOW"      -> AuditIssueSeverity.LOW;
            default         -> AuditIssueSeverity.INFORMATION;
        };
    }

    private static AuditIssueConfidence maxConfidence(List<SecretFinding> group) {
        String best = group.stream()
                .max((a, b) -> confidenceRank(a.confidence()) - confidenceRank(b.confidence()))
                .map(SecretFinding::confidence).orElse("TENTATIVE");
        return switch (best.toUpperCase()) {
            case "CERTAIN" -> AuditIssueConfidence.CERTAIN;
            case "FIRM"    -> AuditIssueConfidence.FIRM;
            default        -> AuditIssueConfidence.TENTATIVE;
        };
    }

    private static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}
