package com.secretscanner;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Generates a self-contained, sortable HTML report from a list of SecretFindings.
 *
 * Features:
 *   - Summary cards (HIGH / MEDIUM / LOW / INFO counts)
 *   - Severity filter buttons + domain / rule dropdowns + free-text search
 *   - Sortable columns (click header)
 *   - Color-coded severity badges
 *   - HIGH-severity values partially masked (first 4 + last 4 chars shown)
 *   - Full clickable URLs (open in new tab, copy from tooltip)
 *   - CSV + JSON export buttons (reads embedded data, no round-trip to Burp needed)
 *   - No external dependencies — all CSS and JS embedded inline
 */
public final class HtmlReportGenerator {

    private HtmlReportGenerator() {}

    public static String generate(List<SecretFinding> findings, String target, String mode) {
        Map<String, Long> counts = findings.stream()
                .collect(Collectors.groupingBy(
                        f -> f.severity().toUpperCase(), Collectors.counting()));

        long critCount   = counts.getOrDefault("CRITICAL", 0L);
        long highCount   = counts.getOrDefault("HIGH",   0L);
        long medCount    = counts.getOrDefault("MEDIUM", 0L);
        long lowCount    = counts.getOrDefault("LOW",    0L);
        long infoCount   = counts.getOrDefault("INFORMATION", 0L) + counts.getOrDefault("INFO", 0L);

        String timestamp = LocalDateTime.now()
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        StringBuilder rows    = new StringBuilder();
        StringBuilder jsonArr = new StringBuilder("[");

        for (int i = 0; i < findings.size(); i++) {
            SecretFinding f = findings.get(i);
            if (i > 0) jsonArr.append(",");

            String sev       = esc(f.severity().toUpperCase());
            String sevLower  = f.severity().toLowerCase();
            String conf      = esc(f.confidence());
            String confLower = f.confidence().toLowerCase();
            String dispVal   = maskValue(f.matchedValue());
            String ctxRaw    = f.context() != null ? trunc(f.context(), 120) : "";
            String ctx       = maskContext(ctxRaw, f.matchedValue());
            String urlFull   = f.sourceUrl() != null ? f.sourceUrl() : "";
            String domain    = extractDomain(urlFull);

            // ── Table row ──────────────────────────────────────────────────
            rows.append("<tr data-sev=\"").append(sev)
                .append("\" data-domain=\"").append(esc(domain))
                .append("\" data-rule=\"").append(esc(f.ruleId()))
                .append("\">\n");
            rows.append("  <td>").append(i + 1).append("</td>\n");
            rows.append("  <td><span class=\"badge sev-").append(sevLower).append("\">")
                .append(sev).append("</span></td>\n");
            rows.append("  <td><span class=\"badge conf-").append(confLower).append("\">")
                .append(conf).append("</span></td>\n");
            rows.append("  <td><code>").append(esc(f.ruleId())).append("</code></td>\n");
            rows.append("  <td><code>").append(esc(f.keyName())).append("</code></td>\n");
            String rawEsc    = esc(f.matchedValue() != null ? f.matchedValue() : "");
            String maskedEsc = esc(dispVal);
            rows.append("  <td class=\"val-cell\" data-raw=\"").append(rawEsc)
                .append("\" data-masked=\"").append(maskedEsc)
                .append("\"><code>").append(maskedEsc).append("</code></td>\n");
            // Full URL as clickable link — display starts masked; href always full
            String urlMasked = maskUrl(urlFull);
            rows.append("  <td class=\"url-cell\" data-raw=\"").append(esc(urlFull))
                .append("\" data-masked=\"").append(esc(urlMasked)).append("\">")
                .append("<a href=\"").append(esc(urlFull))
                .append("\" target=\"_blank\" title=\"").append(esc(urlFull)).append("\">")
                .append(esc(urlMasked)).append("</a></td>\n");
            rows.append("  <td>").append(f.lineNumber()).append("</td>\n");
            rows.append("  <td class=\"ctx-cell\" data-raw=\"").append(esc(ctxRaw))
                .append("\" data-masked=\"").append(esc(ctx))
                .append("\"><code>").append(esc(ctx)).append("</code></td>\n");
            rows.append("</tr>\n");

            // ── JSON entry (embedded for client-side export) ───────────────
            jsonArr.append("{")
                .append("\"severity\":\"").append(jsonEsc(f.severity())).append("\",")
                .append("\"confidence\":\"").append(jsonEsc(f.confidence())).append("\",")
                .append("\"ruleId\":\"").append(jsonEsc(f.ruleId())).append("\",")
                .append("\"ruleName\":\"").append(jsonEsc(f.ruleName())).append("\",")
                .append("\"keyName\":\"").append(jsonEsc(f.keyName())).append("\",")
                .append("\"matchedValue\":\"").append(jsonEsc(f.matchedValue())).append("\",")
                .append("\"domain\":\"").append(jsonEsc(domain)).append("\",")
                .append("\"sourceUrl\":\"").append(jsonEsc(urlFull)).append("\",")
                .append("\"lineNumber\":").append(f.lineNumber()).append(",")
                .append("\"context\":\"").append(jsonEsc(f.context())).append("\"")
                .append("}");
        }
        jsonArr.append("]");

        String targetSegment = (target != null && !target.isBlank())
                ? " &nbsp;|&nbsp; Target: " + esc(target)
                : "";
        return TEMPLATE
                .replace("{{TIMESTAMP}}",      esc(timestamp))
                .replace("{{TARGET_SEGMENT}}", targetSegment)
                .replace("{{MODE}}",           esc(mode != null ? mode : "—"))
                .replace("{{TOTAL}}",     String.valueOf(findings.size()))
                .replace("{{CRITICAL}}",  String.valueOf(critCount))
                .replace("{{HIGH}}",      String.valueOf(highCount))
                .replace("{{MEDIUM}}",    String.valueOf(medCount))
                .replace("{{LOW}}",       String.valueOf(lowCount))
                .replace("{{INFO}}",      String.valueOf(infoCount))
                .replace("{{ROWS}}",      rows.toString())
                .replace("{{JSON_DATA}}", jsonArr.toString());
    }

    /**
     * Groups findings by full hostname and returns one HTML string per host.
     * Key   = full hostname (e.g. "myinc.abc.com" or "unknown_domain").
     * Value = full self-contained HTML report for that host's findings.
     *
     * Findings whose sourceUrl cannot be parsed are grouped under "unknown_domain".
     * Insertion order is preserved so the ZIP entries appear alphabetically.
     */
    public static Map<String, String> generatePerDomain(List<SecretFinding> findings, String mode) {
        // Group by base domain preserving insertion order
        Map<String, List<SecretFinding>> grouped = new LinkedHashMap<>();
        for (SecretFinding f : findings) {
            String domain = extractBaseDomain(f.sourceUrl());
            grouped.computeIfAbsent(domain, k -> new ArrayList<>()).add(f);
        }
        // Generate one HTML per domain group
        Map<String, String> result = new LinkedHashMap<>();
        for (Map.Entry<String, List<SecretFinding>> entry : grouped.entrySet()) {
            String domain = entry.getKey();
            result.put(domain, generate(entry.getValue(), domain, mode));
        }
        return result;
    }

    /**
     * Extracts the full hostname from a URL for per-domain grouping.
     * Preserves subdomains so each distinct host gets its own report.
     * Examples:
     *   https://myinc.abc.com/v1/config.js    →  myinc.abc.com
     *   https://portal.clientB.com/app.js     →  portal.clientB.com
     *   https://10.0.0.5/test.js              →  10.0.0.5
     *   null / blank / unparseable            →  unknown_domain
     */
    private static String extractBaseDomain(String url) {
        if (url == null || url.isBlank()) return "unknown_domain";
        // Strip display suffixes added by BulkScanPanel
        String clean = url;
        int hash = clean.indexOf('#');
        if (hash >= 0) clean = clean.substring(0, hash);
        if (clean.endsWith(" [HTML]")) clean = clean.substring(0, clean.length() - 7);
        String host;
        try {
            host = new java.net.URL(clean).getHost();
        } catch (Exception e) {
            return "unknown_domain";
        }
        if (host == null || host.isBlank()) return "unknown_domain";
        // Return full hostname — subdomains preserved for distinct per-target reports
        return host.toLowerCase();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static String maskValue(String val) {
        if (val == null) return "";
        if (val.length() > 10) {
            return val.substring(0, 4) + "••••••••" + val.substring(val.length() - 4);
        }
        return val;
    }

    /** Mask a URL completely — returns a fixed placeholder so no domain is visible. */
    private static String maskUrl(String url) {
        if (url == null || url.isBlank()) return "";
        return "••••••••••••";
    }

    /** Mask context snippet: show first 6 + last 6 chars with bullets in between. */
    private static String maskContext(String ctx, String matchedValue) {
        if (ctx == null) return "";
        if (ctx.length() > 14) {
            return ctx.substring(0, 6) + "••••••••••••" + ctx.substring(ctx.length() - 6);
        }
        return ctx;
    }

    private static String trunc(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max - 3) + "…" : s;
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }

    /** JSON-safe escaping — also prevents </script> injection via \u003c. */
    private static String jsonEsc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t")
                .replace("<",  "\\u003c")
                .replace(">",  "\\u003e");
    }

    /** Extract the hostname from a URL; strips display suffixes added by BulkScanPanel. */
    private static String extractDomain(String url) {
        if (url == null || url.isBlank()) return "";
        String clean = url;
        int hash = clean.indexOf('#');
        if (hash >= 0) clean = clean.substring(0, hash);
        if (clean.endsWith(" [HTML]")) clean = clean.substring(0, clean.length() - 7);
        try {
            return new java.net.URL(clean).getHost();
        } catch (Exception e) {
            return "";
        }
    }

    // -------------------------------------------------------------------------
    // HTML template — fully self-contained (no CDN deps)
    // -------------------------------------------------------------------------

    private static final String TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secret Sifter Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
     background:#f0f2f5;color:#333;font-size:13px}

/* ── Header ─────────────────────────────────────────────────────────────── */
.hdr{background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);
     color:#fff;padding:18px 28px;display:flex;align-items:center;gap:16px}
.hdr-icon{width:48px;height:48px;flex-shrink:0}
.hdr h1{font-size:20px;font-weight:700;letter-spacing:.3px}
.hdr p{font-size:11px;opacity:.65;margin-top:4px}
.hdr-stats{display:flex;gap:6px;margin-left:auto;align-items:center}
.hdr-sep{width:1px;height:40px;background:rgba(255,255,255,.15);margin-right:10px}
.hdr-stat{text-align:center;min-width:52px;padding:6px 10px;border-radius:8px;
          background:rgba(255,255,255,.07)}
.hdr-stat .num{font-size:22px;font-weight:800;line-height:1}
.hdr-stat .lbl{font-size:10px;opacity:.6;letter-spacing:.5px;text-transform:uppercase;margin-top:2px}
.hdr-stat.c .num{color:#d6bcfa}
.hdr-stat.h .num{color:#fc8181}
.hdr-stat.m .num{color:#f6ad55}
.hdr-stat.l .num{color:#f6e05e}
.hdr-stat.i .num{color:#63b3ed}

/* ── Filter bars ─────────────────────────────────────────────────────────── */
.filters{padding:10px 28px;background:#fff;border-bottom:1px solid #e0e0e0;
         display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.filters .lbl{font-size:11px;color:#888}
.fbtn{padding:4px 14px;border-radius:20px;border:none;cursor:pointer;
      font-size:12px;font-weight:600;letter-spacing:.3px;transition:opacity .15s}
.fbtn:hover{opacity:.8}
.fbtn.all{background:#eee;color:#333}
.fbtn.c{background:#e9d8fd;color:#553c9a}
.fbtn.h{background:#fed7d7;color:#c53030}
.fbtn.m{background:#feebc8;color:#c05621}
.fbtn.l{background:#fefcbf;color:#b7791f}
.fbtn.i{background:#bee3f8;color:#2b6cb0}
.fbtn.active{box-shadow:0 0 0 2px #333}
.fbtn.mask{background:#e9d8fd;color:#553c9a}
#maskBtn{margin-left:auto}
.fbtn.mask.unmasked{background:#553c9a;color:#fff}
.fbtn.exp{background:#c6f6d5;color:#276749;border-radius:6px;padding:4px 12px;margin-left:4px}
.fbtn.exp:hover{background:#9ae6b4}
/* Dropdowns + search input */
.fsel{padding:4px 8px;border:1px solid #ddd;border-radius:6px;
      font-size:12px;background:#fafafa;color:#333;cursor:pointer;max-width:180px}
.fsel:focus{outline:none;border-color:#a0aec0}
.fsearch{padding:4px 10px;border:1px solid #ddd;border-radius:6px;
         font-size:12px;background:#fafafa;color:#333;width:240px}
.fsearch:focus{outline:none;border-color:#a0aec0}
.fsearch::placeholder{color:#bbb}

/* ── Table ───────────────────────────────────────────────────────────────── */
.wrap{padding:16px 28px}
table{width:100%;border-collapse:collapse;background:#fff;
      border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08)}
thead{background:#1a1a2e;color:#fff}
th{padding:10px 12px;text-align:left;font-size:12px;font-weight:600;
   letter-spacing:.4px;cursor:pointer;user-select:none;white-space:nowrap}
th:hover{background:#2d2d4e}
th.sort-asc::after{content:" ▲";font-size:9px}
th.sort-desc::after{content:" ▼";font-size:9px}
td{padding:8px 12px;border-bottom:1px solid #f0f0f0;vertical-align:top;
   max-width:320px;word-break:break-word}
td:nth-child(1),td:nth-child(2),td:nth-child(3),td:nth-child(8){white-space:nowrap;max-width:none}
tr:last-child td{border-bottom:none}
tr:hover td{background:#f7faff}
tr[data-sev="CRITICAL"]    td:first-child{border-left:3px solid #805ad5}
tr[data-sev="HIGH"]        td:first-child{border-left:3px solid #e53e3e}
tr[data-sev="MEDIUM"]      td:first-child{border-left:3px solid #dd6b20}
tr[data-sev="LOW"]         td:first-child{border-left:3px solid #d69e2e}
tr[data-sev="INFORMATION"] td:first-child{border-left:3px solid #3182ce}
code{background:#f4f4f4;padding:1px 5px;border-radius:3px;
     font-family:'Cascadia Code','Fira Code','Courier New',monospace;font-size:12px}
/* URL cell — full link, ellipsis on overflow, click opens in new tab */
.url-cell{font-size:11px;max-width:240px}
.url-cell a{color:#2b6cb0;text-decoration:none;display:block;
            white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:240px}
.url-cell a:hover{text-decoration:underline;color:#1a365d}
.ctx-cell{font-size:11px;max-width:280px}
.val-cell code{word-break:break-all}
/* No-results banner */
#no-results{display:none;padding:28px;text-align:center;color:#888;font-size:13px;
            background:#fff;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.08)}

/* ── Badges ──────────────────────────────────────────────────────────────── */
.badge{display:inline-block;padding:2px 9px;border-radius:12px;
       font-size:10px;font-weight:700;letter-spacing:.4px;white-space:nowrap}
.sev-critical{background:#e9d8fd;color:#553c9a}
.sev-high{background:#fed7d7;color:#c53030}
.sev-medium{background:#feebc8;color:#c05621}
.sev-low{background:#fefcbf;color:#b7791f}
.sev-information,.sev-info{background:#bee3f8;color:#2b6cb0}
.conf-certain{background:#c6f6d5;color:#276749}
.conf-firm{background:#e9d8fd;color:#553c9a}
.conf-tentative{background:#e2e8f0;color:#4a5568}

/* ── Sticky filter bar ───────────────────────────────────────────────────── */
.sticky-bar{position:sticky;top:0;z-index:100;box-shadow:0 2px 6px rgba(0,0,0,.07)}
.sticky-bar .filters:last-child{border-bottom:1px solid #e0e0e0}

/* ── Remediation modal ───────────────────────────────────────────────────── */
.fbtn.rem{background:#fff3cd;color:#92400e;border:1px solid #f6c453;border-radius:6px;padding:4px 12px;margin-left:4px}
.fbtn.rem:hover{background:#ffe8a0}
.rem-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:1000;
             align-items:flex-start;justify-content:center;padding-top:80px}
.rem-overlay.open{display:flex}
.rem-modal{background:#fff;border-radius:10px;box-shadow:0 8px 32px rgba(0,0,0,.28);
           width:640px;max-width:90vw;overflow:hidden;animation:slideDown .2s ease}
@keyframes slideDown{from{opacity:0;transform:translateY(-18px)}to{opacity:1;transform:translateY(0)}}
.rem-modal-hdr{display:flex;align-items:center;gap:10px;background:#fff8f0;
               border-bottom:1px solid #ffe0b0;padding:14px 18px}
.rem-modal-title{font-weight:700;font-size:14px;color:#b45309;flex:1}
.rem-close{background:none;border:none;font-size:20px;color:#b45309;cursor:pointer;
           line-height:1;padding:0 2px}
.rem-close:hover{color:#7c2d12}
.rem-modal-body{padding:18px 22px 20px}
.rem-modal-body ul{padding-left:18px;display:flex;flex-direction:column;gap:10px}
.rem-modal-body li{font-size:12.5px;line-height:1.55;color:#444}
.rem-modal-body li strong{color:#1a1a2e}
.rem-modal-note{margin-top:14px;font-size:11px;color:#999;border-top:1px solid #f0f0f0;padding-top:10px}

/* ── Footer ──────────────────────────────────────────────────────────────── */
.footer{text-align:center;padding:20px;font-size:11px;color:#aaa}
</style>
</head>
<body>

<div class="hdr">
  <img class="hdr-icon" src="data:image/png;base64,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" alt="SecretSifter">
  <div>
    <h1>Secret Sifter — Findings Report</h1>
    <p>Generated: {{TIMESTAMP}}{{TARGET_SEGMENT}}
       &nbsp;|&nbsp; Mode: {{MODE}} &nbsp;|&nbsp; Total findings: {{TOTAL}}</p>
  </div>
  <div class="hdr-stats">
    <div class="hdr-sep"></div>
    <div class="hdr-stat c"><div class="num">{{CRITICAL}}</div><div class="lbl">Critical</div></div>
    <div class="hdr-stat h"><div class="num">{{HIGH}}</div><div class="lbl">High</div></div>
    <div class="hdr-stat m"><div class="num">{{MEDIUM}}</div><div class="lbl">Medium</div></div>
    <div class="hdr-stat l"><div class="num">{{LOW}}</div><div class="lbl">Low</div></div>
    <div class="hdr-stat i"><div class="num">{{INFO}}</div><div class="lbl">Info</div></div>
  </div>
</div>

<!-- Remediation modal -->
<div class="rem-overlay" id="remOverlay" onclick="closeRemIfOutside(event)">
  <div class="rem-modal">
    <div class="rem-modal-hdr">
      <span style="font-size:18px">⚠️</span>
      <span class="rem-modal-title">Remediation Guidance</span>
      <button class="rem-close" onclick="closeRem()" title="Close">✕</button>
    </div>
    <div class="rem-modal-body">
      <ul>
        <li><strong>Rotate or revoke all identified credentials immediately</strong> — treat every exposed secret as compromised, even if no misuse has been observed yet.</li>
        <li><strong>Remove secrets from client-accessible assets</strong> — JavaScript files, HTML source, and API responses are readable by any user. Move credentials to server-side environment variables or a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault).</li>
        <li><strong>Audit git history</strong> — run <code>git log -S &lt;secret&gt;</code> to check whether the credential was ever committed. If so, rotate it and consider the entire history compromised.</li>
        <li><strong>Review how the secret was exposed</strong> — hardcoded value, SSR state blob, API response leakage, or webpack bundle inclusion each require a different fix at the source.</li>
        <li><strong>Notify affected service owners</strong> — check platform audit logs for any unauthorised access that may have already occurred using the exposed credential.</li>
      </ul>
      <div class="rem-modal-note">This guidance applies to all findings in this report. Rotate credentials before closing any associated tickets.</div>
    </div>
  </div>
</div>

<div class="sticky-bar">
<!-- Row 1: severity filter + unmask -->
<div class="filters">
  <span class="lbl">Filter:</span>
  <button class="fbtn all active" onclick="setSev('ALL')">All</button>
  <button class="fbtn c" onclick="setSev('CRITICAL')">Critical</button>
  <button class="fbtn h" onclick="setSev('HIGH')">High</button>
  <button class="fbtn m" onclick="setSev('MEDIUM')">Medium</button>
  <button class="fbtn l" onclick="setSev('LOW')">Low</button>
  <button class="fbtn i" onclick="setSev('INFORMATION')">Info</button>
  <button id="maskBtn"    class="fbtn mask" onclick="toggleMask()"    title="Show or hide secret values"><span style="text-decoration:line-through;text-decoration-thickness:2px">&#128065;</span> Value</button>
  <button id="urlMaskBtn" class="fbtn mask" onclick="toggleUrlMask()" title="Show or hide full URLs"><span style="text-decoration:line-through;text-decoration-thickness:2px">&#128065;</span> URL</button>
  <button id="ctxMaskBtn" class="fbtn mask" onclick="toggleCtxMask()" title="Show or hide context snippets"><span style="text-decoration:line-through;text-decoration-thickness:2px">&#128065;</span> Context</button>
</div>

<!-- Row 2: domain, rule, search, export -->
<div class="filters">
  <span class="lbl">Domain:</span>
  <select id="domainSel" class="fsel" onchange="applyAll()"><option value="">All domains</option></select>
  <span class="lbl">Rule:</span>
  <select id="ruleSel" class="fsel" onchange="applyAll()"><option value="">All rules</option></select>
  <input id="search" class="fsearch" type="text" placeholder="Search key / value / URL&#8230;" oninput="applyAll()">
  <button class="fbtn exp" onclick="exportCSV()">&#8595; CSV</button>
  <button class="fbtn exp" onclick="exportJSON()">&#8595; JSON</button>
  <button class="fbtn rem" onclick="openRem()">⚠️ Remediation</button>
</div>
</div>

<div class="wrap">
<div id="no-results">No findings match the current filter.</div>
<table id="tbl">
<thead>
<tr>
  <th onclick="sortBy(0)">#</th>
  <th onclick="sortBy(1)">Severity</th>
  <th onclick="sortBy(2)">Confidence</th>
  <th onclick="sortBy(3)">Rule ID</th>
  <th onclick="sortBy(4)">Key</th>
  <th>Value</th>
  <th onclick="sortBy(6)">URL</th>
  <th onclick="sortBy(7)">Line</th>
  <th>Context</th>
</tr>
</thead>
<tbody id="tbody">
{{ROWS}}
</tbody>
</table>
</div>

<div class="footer">
  Secret Sifter — Burp Suite Extension &nbsp;|&nbsp; Report generated {{TIMESTAMP}}
</div>

<!-- Embedded findings data for client-side CSV / JSON export -->
<script id="findings-data" type="application/json">{{JSON_DATA}}</script>

<script>
var currentSev = 'ALL';
var sortCol = -1, sortAsc = true;
var valsMasked = true;
var urlsMasked = true;

// ── Severity filter buttons ───────────────────────────────────────────────
function setSev(sev) {
  currentSev = sev;
  document.querySelectorAll('.fbtn').forEach(function(b) { b.classList.remove('active'); });
  event.target.classList.add('active');
  applyAll();
}

// ── Combined filter (severity + domain + rule + search) ───────────────────
function applyAll() {
  var domain = document.getElementById('domainSel').value;
  var rule   = document.getElementById('ruleSel').value;
  var q      = document.getElementById('search').value.toLowerCase();
  var visible = 0;
  document.querySelectorAll('#tbody tr').forEach(function(r) {
    var sevOk    = currentSev === 'ALL' || r.dataset.sev === currentSev;
    var domainOk = !domain || r.dataset.domain === domain;
    var ruleOk   = !rule   || r.dataset.rule   === rule;
    var qOk      = !q || r.textContent.toLowerCase().indexOf(q) !== -1;
    var show     = sevOk && domainOk && ruleOk && qOk;
    r.style.display = show ? '' : 'none';
    if (show) visible++;
  });
  document.getElementById('no-results').style.display = visible === 0 ? 'block' : 'none';
  document.getElementById('tbl').style.display        = visible === 0 ? 'none'  : '';
}

// ── Populate domain + rule dropdowns from embedded row data ───────────────
function populateDropdowns() {
  var domains = [], rules = [];
  document.querySelectorAll('#tbody tr').forEach(function(r) {
    if (r.dataset.domain && domains.indexOf(r.dataset.domain) === -1) domains.push(r.dataset.domain);
    if (r.dataset.rule   && rules.indexOf(r.dataset.rule)     === -1) rules.push(r.dataset.rule);
  });
  domains.sort();
  rules.sort();
  var dSel = document.getElementById('domainSel');
  domains.forEach(function(d) {
    var o = document.createElement('option'); o.value = d; o.textContent = d; dSel.appendChild(o);
  });
  var rSel = document.getElementById('ruleSel');
  rules.forEach(function(r) {
    var o = document.createElement('option'); o.value = r; o.textContent = r; rSel.appendChild(o);
  });
}

// ── Mask / Unmask ─────────────────────────────────────────────────────────
function toggleMask() {
  valsMasked = !valsMasked;
  document.querySelectorAll('.val-cell').forEach(function(td) {
    var code = td.querySelector('code');
    if (code) code.textContent = valsMasked ? (td.dataset.masked || '') : (td.dataset.raw || '');
  });
  var btn = document.getElementById('maskBtn');
  btn.innerHTML = valsMasked
    ? '<span style="text-decoration:line-through;text-decoration-thickness:2px">&#128065;</span> Value'
    : '&#128065; Value';
  btn.classList.toggle('unmasked', !valsMasked);
}

function toggleUrlMask() {
  urlsMasked = !urlsMasked;
  document.querySelectorAll('.url-cell').forEach(function(td) {
    var a = td.querySelector('a');
    if (a) a.textContent = urlsMasked ? (td.dataset.masked || '') : (td.dataset.raw || '');
  });
  var btn = document.getElementById('urlMaskBtn');
  btn.innerHTML = urlsMasked
    ? '<span style="text-decoration:line-through;text-decoration-thickness:2px">&#128065;</span> URL'
    : '&#128065; URL';
  btn.classList.toggle('unmasked', !urlsMasked);
}

var ctxMasked = true;
function toggleCtxMask() {
  ctxMasked = !ctxMasked;
  document.querySelectorAll('.ctx-cell').forEach(function(td) {
    var code = td.querySelector('code');
    if (code) code.textContent = ctxMasked ? (td.dataset.masked || '') : (td.dataset.raw || '');
  });
  var btn = document.getElementById('ctxMaskBtn');
  btn.innerHTML = ctxMasked
    ? '<span style="text-decoration:line-through;text-decoration-thickness:2px">&#128065;</span> Context'
    : '&#128065; Context';
  btn.classList.toggle('unmasked', !ctxMasked);
}

function openRem()  { document.getElementById('remOverlay').classList.add('open'); }
function closeRem() { document.getElementById('remOverlay').classList.remove('open'); }
function closeRemIfOutside(e) { if (e.target === document.getElementById('remOverlay')) closeRem(); }
document.addEventListener('keydown', function(e) { if (e.key === 'Escape') closeRem(); });

// ── Column sort ───────────────────────────────────────────────────────────
function sortBy(col) {
  var ths = document.querySelectorAll('thead th');
  ths.forEach(function(th) { th.classList.remove('sort-asc','sort-desc'); });
  if (sortCol === col) { sortAsc = !sortAsc; } else { sortCol = col; sortAsc = true; }
  ths[col].classList.add(sortAsc ? 'sort-asc' : 'sort-desc');
  var tbody = document.getElementById('tbody');
  var rows  = Array.from(tbody.querySelectorAll('tr'));
  rows.sort(function(a, b) {
    var av = a.cells[col] ? a.cells[col].innerText.trim() : '';
    var bv = b.cells[col] ? b.cells[col].innerText.trim() : '';
    if (!isNaN(av) && !isNaN(bv)) { av = +av; bv = +bv; }
    if (av < bv) return sortAsc ? -1 : 1;
    if (av > bv) return sortAsc ?  1 : -1;
    return 0;
  });
  rows.forEach(function(r) { tbody.appendChild(r); });
}

// ── Export ────────────────────────────────────────────────────────────────
function exportJSON() {
  var data = document.getElementById('findings-data').textContent;
  trigger(new Blob([data], {type: 'application/json'}), 'secret-findings-' + Date.now() + '.json');
}

function exportCSV() {
  var data   = JSON.parse(document.getElementById('findings-data').textContent);
  var fields = ['severity','confidence','ruleId','ruleName','keyName','matchedValue','domain','sourceUrl','lineNumber','context'];
  var lines  = [fields.join(',')];
  data.forEach(function(f) {
    lines.push(fields.map(function(k) {
      return '"' + String(f[k] == null ? '' : f[k]).replace(/"/g, '""') + '"';
    }).join(','));
  });
  trigger(new Blob([lines.join('\\n')], {type: 'text/csv'}), 'secret-findings-' + Date.now() + '.csv');
}

function trigger(blob, filename) {
  var url = URL.createObjectURL(blob);
  var a   = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  setTimeout(function() { URL.revokeObjectURL(url); }, 1000);
}

document.addEventListener('DOMContentLoaded', populateDropdowns);
</script>
</body>
</html>
""";
}
