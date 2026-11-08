package com.secretscanner;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * SARIF 2.1.0 export for CI pipelines, code-scanning dashboards and DefectDojo-style importers.
 * Values are always redacted; each result carries the permanent issue ID, the occurrence
 * reference and the keyed fingerprint (as a partial fingerprint) so tools can deduplicate.
 */
final class SarifWriter {

    private SarifWriter() {}

    static String write(List<SecretFinding> findings, String toolVersion) {
        JsonObject driver = new JsonObject();
        driver.addProperty("name", "SecretSifter");          // stable: code-scanning tools match alerts on it
        driver.addProperty("fullName", Branding.NAME);
        driver.addProperty("informationUri", Branding.PROJECT_URL);
        if (toolVersion != null) driver.addProperty("version", toolVersion);

        Map<String, JsonObject> rules = new LinkedHashMap<>();
        JsonArray results = new JsonArray();
        for (SecretFinding f : findings) {
            String ruleId = f.ruleId() == null ? "UNKNOWN" : f.ruleId();
            rules.computeIfAbsent(ruleId, id -> {
                JsonObject r = new JsonObject();
                r.addProperty("id", id);
                r.addProperty("name", f.ruleName() == null ? id : f.ruleName().replaceAll("[^A-Za-z0-9]+", ""));
                JsonObject sd = new JsonObject();
                sd.addProperty("text", f.ruleName() == null ? id : f.ruleName());
                r.add("shortDescription", sd);
                JsonObject props = new JsonObject();
                JsonArray tags = new JsonArray();
                tags.add("security");
                tags.add("secret");
                props.add("tags", tags);
                r.add("properties", props);
                return r;
            });

            JsonObject res = new JsonObject();
            res.addProperty("ruleId", ruleId);
            res.addProperty("level", level(f.severity()));
            JsonObject msg = new JsonObject();
            msg.addProperty("text", f.issueId() + " " + (f.ruleName() == null ? ruleId : f.ruleName())
                    + ": " + nvl(f.keyName()) + " = " + f.redactedValue());
            res.add("message", msg);

            JsonObject region = new JsonObject();
            if (f.lineNumber() > 0) region.addProperty("startLine", f.lineNumber());
            JsonObject artifact = new JsonObject();
            artifact.addProperty("uri", cleanUri(f.sourceUrl()));
            JsonObject physical = new JsonObject();
            physical.add("artifactLocation", artifact);
            if (region.size() > 0) physical.add("region", region);
            JsonObject loc = new JsonObject();
            loc.add("physicalLocation", physical);
            JsonArray locs = new JsonArray();
            locs.add(loc);
            res.add("locations", locs);

            JsonObject pf = new JsonObject();
            pf.addProperty("secretFingerprint/v1", f.fingerprint());
            res.add("partialFingerprints", pf);

            JsonObject props = new JsonObject();
            props.addProperty("issueId", f.issueId());
            props.addProperty("occurrence", f.occurrenceRef());
            props.addProperty("severity", nvl(f.severity()));
            props.addProperty("confidence", nvl(f.confidence()));
            props.addProperty("security-severity", securitySeverity(f.severity()));
            if (f.targetUrl() != null && !f.targetUrl().isBlank()) props.addProperty("target", f.targetUrl());
            res.add("properties", props);
            results.add(res);
        }
        JsonArray ruleArr = new JsonArray();
        rules.values().forEach(ruleArr::add);
        driver.add("rules", ruleArr);

        JsonObject tool = new JsonObject();
        tool.add("driver", driver);
        JsonObject run = new JsonObject();
        run.add("tool", tool);
        run.add("results", results);
        JsonArray runs = new JsonArray();
        runs.add(run);
        JsonObject root = new JsonObject();
        root.addProperty("$schema", "https://json.schemastore.org/sarif-2.1.0.json");
        root.addProperty("version", "2.1.0");
        root.add("runs", runs);
        return new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(root);
    }

    static String level(String sev) {
        switch (nvl(sev).toUpperCase()) {
            case "CRITICAL": case "HIGH": return "error";
            case "MEDIUM":                return "warning";
            default:                      return "note";
        }
    }

    static String securitySeverity(String sev) {
        switch (nvl(sev).toUpperCase()) {
            case "CRITICAL": return "9.5";
            case "HIGH":     return "8.0";
            case "MEDIUM":   return "5.0";
            case "LOW":      return "3.0";
            default:         return "1.0";
        }
    }

    /** The URL without the scanner's " [JS]" labels, sub-scan fragments or query string. */
    static String cleanUri(String url) {
        String u = nvl(url).replaceFirst(" \\[[^\\]]*\\]$", "");
        u = u.replaceFirst("(?:#inline-js|#json-script|::[a-z\\-]+)$", "");
        int q = u.indexOf('?');
        return q >= 0 ? u.substring(0, q) : u;
    }

    private static String nvl(String s) { return s == null ? "" : s; }
}
