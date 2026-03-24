package com.secretscanner;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.net.URL;
import java.util.*;
import java.util.regex.Matcher;

/**
 * Core scanning engine — stateless (no shared mutable state in scan paths).
 * All pattern constants live in {@link Patterns}; settings are read via
 * the injected {@link ScanSettings} reference (volatile reads, thread-safe).
 *
 * Scan tiers:
 *   FAST  — anchored vendor tokens + URL credentials
 *   LIGHT — FAST + DB connection strings
 *   FULL  — LIGHT + generic KV + SSR state blobs + JSON deep walk + PII
 */
public class SecretScanner {

    private static final int JSON_MAX_DEPTH    = 20;
    private static final int JSON_MAX_FINDINGS = 50;

    private final ScanSettings settings;
    private final Logging       logging;

    /**
     * JWT pattern: three dot-separated base64url segments starting with "ey".
     * Matches Bearer tokens produced by every standard JWT library — they are
     * expected in every authenticated request and must never be reported as findings.
     */
    private static final java.util.regex.Pattern JWT_PAT =
            java.util.regex.Pattern.compile(
                    "^ey[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*$");

    /**
     * Values already reported from request scanning.
     * Prevents duplicate findings when the same hardcoded API key appears in
     * every request (e.g. mobile app sends X-API-Key on every call).
     */
    private final java.util.Set<String> seenRequestValues =
            java.util.Collections.synchronizedSet(new HashSet<>());

    /**
     * Secret-domain prefix words: when a compound identifier (e.g., api_key, auth_token)
     * contains one of these as a segment AND contains "key"/"token"/"secret"/"subscription"
     * as another segment, the compound name is treated as a semantic secret key.
     *
     * This prevents bare "key", "alertKey", "interactionStatusKey", etc. from matching
     * while still catching "api_key", "x_api_key", "ocp_apim_subscription_key", etc.
     */
    private static final Set<String> SECRET_KEY_PREFIXES = Set.of(
            "api", "app", "auth", "access", "secret", "private", "signing",
            "master", "resource", "storage", "subscription", "client",
            "service", "account", "application", "apim", "ocp", "bearer",
            "payment", "jwt", "session", "refresh", "x", "app2",
            "instrumentation", "connection", "tenant", "workspace", "org",
            // Added to cover OAuth 1.0 (consumerKey/consumerSecret) and SSH/crypto keys
            "consumer", "encrypt", "decrypt", "ssh", "admin", "db", "database", "root", "slack",
            "user"   // Azure AD User Object ID (userId, user_id, User ID) is sensitive in config blobs
    );

    // Headers that never carry credentials — skip early to reduce noise
    private static final Set<String> SKIP_HEADERS = Set.of(
            "host", "accept", "accept-encoding", "accept-language",
            "connection", "content-length", "content-type", "cache-control",
            "user-agent", "referer", "origin", "cookie", "pragma",
            "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
            "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
            "if-none-match", "if-modified-since", "upgrade-insecure-requests",
            "te", "trailer", "transfer-encoding"
    );

    // Well-known credential-carrying headers — flagged regardless of semantic check
    private static final Set<String> KNOWN_SECRET_HEADERS = Set.of(
            "x-api-key", "api-key", "x-auth-token", "x-access-token",
            "ocp-apim-subscription-key", "x-client-auth-token",
            "x-service-account-token", "x-app-key", "x-application-key",
            "app-key", "app_key",
            "resource", "x-resource", "authorization",
            "x-amz-security-token", "x-goog-api-key"
    );

    public SecretScanner(ScanSettings settings, Logging logging) {
        this.settings = settings;
        this.logging  = logging;
    }

    // =========================================================================
    // Public entry points
    // =========================================================================

    public List<SecretFinding> scanRequestResponse(HttpRequestResponse reqRes) {
        return scanRequestResponse(reqRes, null, null);
    }

    /**
     * Overload called by {@link SecretProxyHandler} with eagerly extracted response body
     * and Content-Type header.
     *
     * <p>Burp's Montoya API {@code HttpRequestResponse.httpRequestResponse(req, interceptedResponse)}
     * may hold a <em>reference</em> to the live {@code InterceptedResponse} rather than copying
     * its body bytes.  After {@code continueWith()} returns, Burp can recycle the proxy buffer,
     * causing a background-thread call to {@code response.bodyToString()} to return an empty string.
     * Extracting the body <em>synchronously</em> on the proxy thread and passing it here via
     * {@code responseBodyHint} prevents that race and ensures the response body is always scanned.
     */
    public List<SecretFinding> scanRequestResponse(HttpRequestResponse reqRes,
                                                    String responseBodyHint,
                                                    String responseCtHint) {
        if (!settings.isEnabled()) return List.of();
        try {
            var request = reqRes.request();
            String url = request.url();
            if (isExternalCdn(url)) return List.of();

            List<SecretFinding> all = new ArrayList<>();

            // Detect if the request carries credential headers with non-JWT values.
            // When true, a JWT appearing in the response is a freshly issued token
            // (e.g. /oauth/token, /auth/login) and should be rated HIGH.
            boolean requestHasCredentialHeaders = false;
            // Detect if the request already carries a JWT Bearer token.
            // When true, JWT findings in the response are suppressed — the endpoint
            // is a normal authenticated call, not a token-issuance endpoint, so
            // reporting the response JWT would produce noise for every authenticated API call.
            boolean requestHasBearerJwt = false;
            for (var hdr : request.headers()) {
                String hdrNameLc = hdr.name().toLowerCase();
                if (SKIP_HEADERS.contains(hdrNameLc)) continue;
                String hdrVal = hdr.value();
                if (hdrVal == null || hdrVal.isBlank()) continue;
                boolean isKnown    = KNOWN_SECRET_HEADERS.contains(hdrNameLc);
                boolean isSemantic = isSemanticSecretKey(hdr.name());
                if (!isKnown && !isSemantic) continue;
                String stripped = hdr.name().equalsIgnoreCase("authorization")
                        ? stripAuthScheme(hdrVal) : hdrVal.trim();
                if (stripped == null || stripped.length() < 10) continue;
                if (isJwt(stripped)) {
                    requestHasBearerJwt = true;
                } else {
                    requestHasCredentialHeaders = true;
                    break;
                }
            }

            // --- Scan response body ---
            // Use pre-extracted body/CT when provided (proxy-handler path); fall back to
            // the snapshot object when called from passiveAudit or context-menu paths.
            var response = reqRes.response();
            if (response != null || responseBodyHint != null) {
                String contentType = responseCtHint   != null ? responseCtHint   :
                                     response         != null ? response.headerValue("Content-Type") : null;
                String body        = responseBodyHint != null ? responseBodyHint :
                                     response         != null ? response.bodyToString()              : null;
                if (body != null && !body.isBlank()) {
                    List<SecretFinding> respFindings = scanText(body, contentType, url);
                    if (requestHasCredentialHeaders) {
                        // Token-endpoint pattern: non-JWT credentials in request → JWT in response.
                        // Upgrade JWT findings to HIGH — this is a freshly issued token.
                        for (SecretFinding f : respFindings) {
                            if ("JWT_TOKEN_001".equals(f.ruleId())) {
                                all.add(SecretFinding.of(f.ruleId(), f.ruleName(), f.keyName(),
                                        f.matchedValue(), "HIGH", f.confidence(),
                                        f.lineNumber(), f.context(), f.sourceUrl()));
                            } else {
                                all.add(f);
                            }
                        }
                    } else if (requestHasBearerJwt) {
                        // Authenticated call: request already carries a JWT Bearer token.
                        // Suppress generic JWT_TOKEN_001 to avoid noise on every authenticated
                        // API endpoint — BUT always keep OAuth token-field findings (access_token,
                        // refresh_token, id_token) since those are token-issuance endpoints.
                        for (SecretFinding f : respFindings) {
                            boolean isOauthTokenField = "JSON_WALK".equals(f.ruleId()) &&
                                    OAUTH_TOKEN_KEYS.contains(f.keyName().toLowerCase().replace("_","").replace("-",""));
                            if (!"JWT_TOKEN_001".equals(f.ruleId()) || isOauthTokenField) {
                                all.add(f);
                            }
                        }
                    } else {
                        all.addAll(respFindings);
                    }
                }
            }

            // --- Scan request headers + body (guarded by setting) ---
            // Strategy:
            //   • Only anchored vendor patterns on request scope (no generic entropy on bodies)
            //   • JWT Bearer tokens are skipped — they appear in every authenticated request
            //   • Already-seen request values are deduplicated across requests in this session
            if (settings.isScanRequestsEnabled()) {
                List<SecretFinding> reqFindings = new ArrayList<>();

                // Pass 1 (named check): flag KNOWN_SECRET_HEADERS + semantic key names
                // Pass 2 (blob scan): anchored vendor tokens on ALL non-skip headers as a blob
                StringBuilder hdrBlob = new StringBuilder();
                for (var hdr : request.headers()) {
                    String hdrName = hdr.name();
                    String hdrVal  = hdr.value();
                    if (hdrVal == null || hdrVal.isBlank()) continue;
                    String hdrNameLc = hdrName.toLowerCase();
                    if (SKIP_HEADERS.contains(hdrNameLc)) continue;

                    // Build blob for pass 2
                    hdrBlob.append(hdrName).append(": ").append(hdrVal).append("\n");

                    // Pass 1: named credential check
                    boolean isKnown    = KNOWN_SECRET_HEADERS.contains(hdrNameLc);
                    boolean isSemantic = isSemanticSecretKey(hdrName);
                    if (!isKnown && !isSemantic) continue;
                    // CSRF/XSRF tokens are public anti-forgery placeholders — skip
                    if (isForcedNoiseKey(hdrNameLc)) continue;

                    // Extract credential past the auth scheme ("Bearer ", "Basic ", etc.)
                    String val = hdrName.equalsIgnoreCase("authorization")
                            ? stripAuthScheme(hdrVal) : hdrVal.trim();
                    if (val == null || val.length() < 10 || isPlaceholder(val)) continue;

                    // JWT skip: every authenticated request carries a JWT — not a finding
                    if (isJwt(val)) continue;

                    String display = val.length() > 80 ? val.substring(0, 77) + "..." : val;
                    String sev     = isKnown ? "HIGH" : scoreSeverity(hdrName, val);
                    reqFindings.add(SecretFinding.of(
                            "REQ_HEADER", "Secret in Request Header",
                            hdrName, val, sev, "CERTAIN",
                            0, hdrName + ": " + display, url));
                }

                // Pass 2: vendor-token scan on the full headers blob
                if (hdrBlob.length() > 0) {
                    String blobUrl = url + " [req-headers]";
                    reqFindings.addAll(scanAnchoredTokens(hdrBlob.toString(), blobUrl));
                    if (settings.getTier() == ScanSettings.ScanTier.FULL) {
                        reqFindings.addAll(scanHighEntropyValues(hdrBlob.toString(), blobUrl));
                    }
                }

                // Request body: anchored tokens + URL creds + (LIGHT+) DB strings
                // Entropy/KV/JSON walk only at FULL tier — guards against login-form password noise
                String reqBody = request.bodyToString();
                if (reqBody != null && !reqBody.isBlank() && reqBody.length() > 20) {
                    String reqCt = request.headerValue("Content-Type");
                    reqFindings.addAll(scanAnchoredTokens(reqBody, url + " [req]"));
                    reqFindings.addAll(scanUrlCredentials(reqBody, url + " [req]"));
                    if (settings.getTier() != ScanSettings.ScanTier.FAST) {
                        reqFindings.addAll(scanDbConnectionStrings(reqBody, url + " [req]"));
                    }
                    if (settings.getTier() == ScanSettings.ScanTier.FULL) {
                        reqFindings.addAll(scanGenericKV(reqBody, url + " [req]"));
                        reqFindings.addAll(scanHighEntropyValues(reqBody, url + " [req]"));
                        boolean reqJson = reqCt != null &&
                                (reqCt.contains("application/json") || reqCt.contains("+json"));
                        if (reqJson) reqFindings.addAll(walkJsonBody(reqBody, url + " [req]"));
                    }
                }

                // Filter JWTs + cross-request dedup before adding to findings
                all.addAll(filterRequestFindings(reqFindings));
            }

            return filterAndDeduplicate(all);
        } catch (Exception e) {
            if (logging != null)
                logging.logToError("SecretScanner.scanRequestResponse: " + e.toString());
            return List.of();
        }
    }

    /**
     * Scan arbitrary text content. Used both from the passive HTTP handler
     * and from the context-menu rescan path.
     */
    public List<SecretFinding> scanText(String text, String contentType, String url) {
        if (text == null || text.isBlank()) return List.of();
        String ct   = contentType != null ? contentType.toLowerCase() : "";
        boolean isJson = ct.contains("application/json") || ct.contains("+json");
        boolean isHtml = ct.contains("text/html") || ct.contains("application/xhtml");
        boolean isXml  = ct.contains("text/xml")  || ct.contains("application/xml") || ct.contains("+xml");
        boolean isJs   = ct.contains("javascript") || ct.contains("ecmascript") ||
                         url.toLowerCase().endsWith(".js") || url.toLowerCase().endsWith(".mjs") ||
                         url.toLowerCase().endsWith(".jsx") || url.toLowerCase().endsWith(".ts") ||
                         url.toLowerCase().endsWith(".tsx");
        // OAuth 2.0 token endpoints (e.g. /oauth/token, /enterprise.operations.authorization)
        // may return responses as application/x-www-form-urlencoded instead of JSON.
        boolean isFormEncoded = ct.contains("application/x-www-form-urlencoded");
        ScanSettings.ScanTier tier = settings.getTier();

        List<SecretFinding> all = new ArrayList<>();

        // --- Form-encoded pre-pass: parse key=value pairs ---
        // Handles OAuth 2.0 token responses like:
        //   access_token=eyJ...&token_type=Bearer&expires_in=3600&resource=<uuid>
        if (isFormEncoded) {
            for (String param : text.split("&")) {
                int eq = param.indexOf('=');
                if (eq <= 0) continue;
                String key;
                String val;
                try {
                    key = java.net.URLDecoder.decode(param.substring(0, eq).trim(),
                            java.nio.charset.StandardCharsets.UTF_8);
                    val = java.net.URLDecoder.decode(param.substring(eq + 1).trim(),
                            java.nio.charset.StandardCharsets.UTF_8);
                } catch (Exception ignored) {
                    key = param.substring(0, eq).trim();
                    val = param.substring(eq + 1).trim();
                }
                if (key.isBlank() || val.isBlank() || val.length() < 8) continue;
                if (!isSemanticSecretKey(key) && !isApiOverrideKey(key)) continue;
                if (!isProbableSecretValue(val)) continue;
                String sev  = scoreSeverity(key, val);
                String conf = hasHighEntropy(val) ? "CERTAIN" : "FIRM";
                all.add(SecretFinding.of("GENERIC_KV", "Secret in Key-Value Pair",
                        key, val, sev, conf, 1,
                        key + "=" + (val.length() > 50 ? val.substring(0, 50) + "…" : val), url));
            }
        }

        // --- HTML pre-pass: extract and scan inline <script> blocks ---
        // This catches secrets embedded directly in HTML pages (SPAs especially)
        if (isHtml) {
            // 1. Inline <script> blocks (no src attribute) — JS config, bootstrappers, etc.
            Matcher sm = Patterns.INLINE_SCRIPT.matcher(text);
            while (sm.find()) {
                String block = sm.group(1);
                if (block != null && !block.isBlank() && block.length() > 20) {
                    // Recurse with JS content type — avoids re-triggering HTML path
                    all.addAll(scanText(block, "application/javascript", url + "#inline-js"));
                }
            }
            // 2. <script type="application/json"> blocks — Next.js __NEXT_DATA__ etc.
            Matcher jm = Patterns.JSON_SCRIPT_TAG.matcher(text);
            while (jm.find()) {
                String block = jm.group(1);
                if (block != null && !block.isBlank() && block.length() > 20) {
                    all.addAll(scanText(block.trim(), "application/json", url + "#json-script"));
                }
            }
        }

        // --- Headers-blob pre-pass: named credential check ---
        // When BulkScanPanel / sweepSiteMapForHosts calls scanText() with a "Name: Value\n"
        // headers blob (URL ends in "[REQ-HEADERS]"), apply the same KNOWN_SECRET_HEADERS +
        // semantic-key check that scanRequestResponse() uses for individual / passive scans.
        // Without this, x-api-key, Authorization, ocp-apim-subscription-key, etc. are silently
        // missed in bulk scan because scanAnchoredTokens only catches vendor-specific patterns.
        boolean isHeadersBlob = url != null && url.contains("[REQ-HEADERS]");

        // Respect the "Scan request headers/body" setting for bulk-scan headers blobs too.
        if (isHeadersBlob && !settings.isScanRequestsEnabled()) {
            return List.of();
        }

        if (isHeadersBlob) {
            List<SecretFinding> hdrFindings = new ArrayList<>();
            for (String line : text.split("\n")) {
                int colon = line.indexOf(':');
                if (colon <= 0) continue;
                String name  = line.substring(0, colon).trim();
                String val   = line.substring(colon + 1).trim();
                if (name.isBlank() || val.isBlank()) continue;
                String nameLc = name.toLowerCase();
                if (SKIP_HEADERS.contains(nameLc)) continue;
                boolean isKnown    = KNOWN_SECRET_HEADERS.contains(nameLc);
                boolean isSemantic = isSemanticSecretKey(name);
                if (!isKnown && !isSemantic) continue;
                // CSRF/XSRF tokens are public anti-forgery placeholders — always INFORMATION
                if (isForcedNoiseKey(nameLc)) continue;
                String credential = name.equalsIgnoreCase("authorization") ? stripAuthScheme(val) : val;
                if (credential == null || credential.length() < 10 || isPlaceholder(credential)) continue;
                // JWT skip: Bearer tokens in every request are not findings
                if (isJwt(credential)) continue;
                String display = credential.length() > 80 ? credential.substring(0, 77) + "..." : credential;
                String sev = isKnown ? "HIGH" : scoreSeverity(name, credential);
                hdrFindings.add(SecretFinding.of(
                        "REQ_HEADER", "Secret in Request Header",
                        name, credential, sev, "CERTAIN",
                        0, name + ": " + display, url));
            }
            // Do NOT call filterRequestFindings() here — that method adds values to the
            // shared seenRequestValues set, which would silently suppress the same credentials
            // from being reported later by the proxy handler (scanRequestResponse path).
            // Bulk Scan is a one-shot operation; it doesn't need cross-request dedup.
            // JWT filter is already applied inline above; just add directly.
            all.addAll(hdrFindings);
        }

        // --- Phase 1: anchored vendor tokens (all tiers) ---
        all.addAll(scanAnchoredTokens(text, url));

        // --- Phase 2: URL credentials (all tiers) ---
        all.addAll(scanUrlCredentials(text, url));

        if (tier == ScanSettings.ScanTier.FAST) {
            return filterAndDeduplicate(all);
        }

        // --- Phase 3: DB connection strings + context-gated rules (LIGHT + FULL) ---
        all.addAll(scanDbConnectionStrings(text, url));
        all.addAll(scanContextGatedRules(text, url));

        if (tier == ScanSettings.ScanTier.LIGHT) {
            return filterAndDeduplicate(all);
        }

        // --- FULL tier only ---
        // Cap very large JS bodies to prevent indefinite hangs on minified webpack bundles.
        // Phases 1–3 (anchored tokens, URL credentials, DB strings) already ran on the full
        // text above. Only the expensive FULL-tier phases below are affected by the cap.
        // Mirrors Python's range-based sampling: first 1 MB (runtime/config) + last 512 KB (app).
        if (isJs && text.length() > 1_500_000) {
            text = text.substring(0, 1_000_000) + "\n" + text.substring(text.length() - 500_000);
        }
        // For HTML, scanGenericKV was already applied to each inline <script> block above.
        // Running it again on the full HTML text would double-report the same findings at
        // different (absolute vs block-relative) line numbers once line-number dedup is in use.
        if (!isHtml) {
            all.addAll(scanGenericKV(text, url));
        }
        all.addAll(scanSsrStateBlobs(text, url));
        all.addAll(scanHighEntropyValues(text, url));

        if (isJs) {
            all.addAll(scanGetterFunctions(text, url));
        }

        if (isJson) {
            all.addAll(walkJsonBody(text, url));
        }

        if (isXml) {
            all.addAll(scanXmlLeaves(text, url));
        }

        if (settings.isPiiEnabled()) {
            all.addAll(scanPiiSsn(text, url));
            all.addAll(scanPiiCreditCard(text, url));
        }

        return filterAndDeduplicate(all);
    }

    // =========================================================================
    // Scan methods
    // =========================================================================

    /** Iterate every AnchoredRule; emit a finding per unique (ruleId, value) match. */
    private List<SecretFinding> scanAnchoredTokens(String text, String url) {
        List<SecretFinding> findings = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        for (Patterns.AnchoredRule rule : Patterns.ANCHORED_RULES) {
            Matcher m = rule.pattern().matcher(text);
            while (m.find()) {
                String val = m.group(0).trim();
                // Skip obvious placeholders
                if (isPlaceholder(val)) continue;
                String dedupe = rule.ruleId() + ":" + val;
                if (!seen.add(dedupe)) continue;
                int    line = countLines(text, m.start());
                String ctx  = extractContext(text, m.start(), m.end());
                findings.add(SecretFinding.of(
                        rule.ruleId(), rule.ruleName(), rule.keyName(), val,
                        rule.severity(), "CERTAIN", line, ctx, url));
            }
        }
        return findings;
    }

    /** Detect https://user:pass@host patterns. */
    private List<SecretFinding> scanUrlCredentials(String text, String url) {
        List<SecretFinding> findings = new ArrayList<>();
        Matcher m = Patterns.URL_WITH_CREDS.matcher(text);
        while (m.find()) {
            String user = m.group(1);
            String pass = m.group(2);
            String host = m.group(3);
            if (pass == null || pass.length() < 4) continue;
            if (pass.equalsIgnoreCase("password") || pass.equalsIgnoreCase("secret")) continue;
            if (isExternalCdn("https://" + host)) continue;
            String ctx = extractContext(text, m.start(), m.end());
            findings.add(SecretFinding.of(
                    "URL_CREDS", "URL with Embedded Credentials",
                    "password", pass, "HIGH", "CERTAIN",
                    countLines(text, m.start()), ctx, url));
        }
        return findings;
    }

    /** Detect DB/broker connection strings with embedded credentials. */
    private List<SecretFinding> scanDbConnectionStrings(String text, String url) {
        List<SecretFinding> findings = new ArrayList<>();
        Matcher m = Patterns.DB_CONN_STRING.matcher(text);
        while (m.find()) {
            String pass = m.group(3);
            if (pass == null || pass.length() < 4) continue;
            if (isPlaceholder(pass)) continue;
            String scheme = m.group(1);
            String ctx    = extractContext(text, m.start(), m.end());
            findings.add(SecretFinding.of(
                    "DB_CONN", "Database/Broker Connection String (" + scheme + ")",
                    "db_password", pass, "HIGH", "CERTAIN",
                    countLines(text, m.start()), ctx, url));
        }

        // Also scan for ADO.NET / SQL Server / MySQL connection strings that use
        // semicolon-delimited key=value format rather than URL scheme (e.g.
        // "Data Source=host;Initial Catalog=db;Password=secret").
        Set<String> seenDotnet = new HashSet<>();
        Matcher m2 = Patterns.DOTNET_CONN_STR.matcher(text);
        while (m2.find()) {
            String pass = m2.group(1);
            if (pass == null || pass.length() < 4) continue;
            if (isPlaceholder(pass)) continue;
            if (!seenDotnet.add(pass)) continue;
            String ctx = extractContext(text, m2.start(), m2.end());
            findings.add(SecretFinding.of(
                    "DB_CONN_DOTNET", "ADO.NET/SQL Server Connection String",
                    "db_password", pass, "HIGH", "CERTAIN",
                    countLines(text, m2.start()), ctx, url));
        }
        return findings;
    }

    /**
     * Generic key=value scanner.
     * Gates: forced-noise key → skip; semantic key required; probable secret value required.
     */
    private List<SecretFinding> scanGenericKV(String text, String url) {
        List<SecretFinding> findings = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        Matcher m = Patterns.GENERIC_KV.matcher(text);
        while (m.find()) {
            // GENERIC_KV has 3 groups: 1=quoted-key (may have spaces), 2=unquoted-key, 3=value
            String key = m.group(1) != null ? m.group(1).trim() : m.group(2);
            String val = m.group(3);
            if (key == null || val == null) continue;
            // FP fix [4a]: skip Angular/Vue/Alpine directive attributes (ng-keyup, v-on:click, etc.)
            if (isFrameworkAttributeKey(key)) continue;
            // FP fix [4a]: skip template expression values ($event, {{ x }}, ${var})
            if (Patterns.TEMPLATE_EXPR.matcher(val.trim()).find()) continue;
            if (isForcedNoiseKey(key)) continue;
            if (Patterns.NOISE_KEYNAMES.matcher(key).matches()) continue;
            boolean forceInclude = settings.isKeyAllowlisted(key);
            if (!forceInclude && !isSemanticSecretKey(key)) continue;
            if (!forceInclude && !isProbableSecretValue(val)) continue;
            // Hard-reject all-alpha values even for allowlisted keys — these are schema field
            // names / identifiers (e.g. "apiKey":"FirstName"), never real credential values.
            if (val.trim().matches("[A-Za-z_]+")) continue;
            // Blockchain hash false-positive guard
            if (Patterns.BLOCKCHAIN_HASH_KEY.matcher(key).find()) continue;
            // Include line number so the same key+value on different lines (e.g., different
            // environment config blocks) produces a separate finding for each occurrence.
            int lineNum = countLines(text, m.start());
            String dedupe = key.toLowerCase() + ":" + val + ":" + lineNum;
            if (!seen.add(dedupe)) continue;
            String sev  = scoreSeverity(key, val);
            String conf = hasHighEntropy(val) ? "CERTAIN" : "FIRM";
            findings.add(SecretFinding.of(
                    "GENERIC_KV", "Secret in Key-Value Pair",
                    key, val, sev, conf,
                    lineNum,
                    extractContext(text, m.start(), m.end()), url));
        }
        return findings;
    }

    /**
     * Detect SSR/SPA framework state blobs and recursively scan the embedded JSON.
     *
     * Handles:
     *   - Standard Next/Redux dunders: window.__NEXT_DATA__, window.__REDUX_STATE__, etc.
     *   - Generic SPA config dunders: window.__CONFIG__, window.appConfig, window._env_, etc.
     *   - JSON script tags: &lt;script type="application/json"&gt;...&lt;/script&gt;
     *     (used by Next.js for __NEXT_DATA__ and by Nuxt/SvelteKit for server state)
     */
    private List<SecretFinding> scanSsrStateBlobs(String text, String url) {
        List<SecretFinding> findings = new ArrayList<>();
        Set<String> seenBlobs = new HashSet<>();

        // 1. Standard Next/Redux window.* dunders (NEXT_DATA pattern)
        scanSsrPattern(Patterns.NEXT_DATA, text, url, "::ssr-state", findings, seenBlobs);

        // 2. Extended SPA config patterns (window.__CONFIG__, window.appConfig, etc.)
        scanSsrPattern(Patterns.GENERIC_WINDOW_CONFIG, text, url, "::spa-config", findings, seenBlobs);

        // 3. <script type="application/json"> tags — Next.js __NEXT_DATA__ and similar
        Matcher jm = Patterns.JSON_SCRIPT_TAG.matcher(text);
        while (jm.find()) {
            String blob = jm.group(1);
            if (blob == null) continue;
            blob = blob.trim();
            if (blob.length() < 20) continue;
            if (!seenBlobs.add(blob.substring(0, Math.min(64, blob.length())))) continue;
            if (blob.length() > 500_000) blob = blob.substring(0, 500_000);
            findings.addAll(walkJsonBody(blob, url + "::json-script-tag"));
        }

        return findings;
    }

    /** Helper: apply a single SSR state pattern and walk each matched JSON blob. */
    private void scanSsrPattern(java.util.regex.Pattern pattern, String text, String url,
                                String suffix, List<SecretFinding> findings, Set<String> seenBlobs) {
        Matcher m = pattern.matcher(text);
        while (m.find()) {
            String blob = m.group(1);
            if (blob == null || blob.length() < 20) continue;
            if (!seenBlobs.add(blob.substring(0, Math.min(64, blob.length())))) continue;
            if (blob.length() > 500_000) blob = blob.substring(0, 500_000);
            findings.addAll(walkJsonBody(blob, url + suffix));
        }
    }

    /**
     * Finds any quoted string ≥ 20 chars composed of token-safe characters
     * that has high Shannon entropy AND appears within 80 chars of a semantic
     * context keyword (api_key, subscription_key, client_secret, etc.).
     *
     * This is the Java equivalent of Python's GENERIC_SECRET_REGEX scan —
     * it catches proprietary / vendor-unknown API keys that have no fixed prefix
     * and that the key-value scanner might miss because of unusual key names.
     */
    private List<SecretFinding> scanHighEntropyValues(String text, String url) {
        List<SecretFinding> findings = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        Matcher m = Patterns.QUOTED_LONG_VALUE.matcher(text);
        while (m.find()) {
            String val = m.group(1);
            if (val == null || val.length() < 20 || isPlaceholder(val)) continue;
            // Reject all-lowercase underscore-delimited identifiers
            // e.g., null_or_empty_id_token, acquire_token_start, interaction_status_key
            if (val.matches("[a-z][a-z0-9]*(_[a-z][a-z0-9]*)+")) continue;
            // Reject dotted/colon namespace constants
            if (val.matches("[a-zA-Z][a-zA-Z0-9]*([:._][a-zA-Z][a-zA-Z0-9]*)+")) continue;
            // Reject OID / dotted-decimal values: "1.2.840.113549.1.1.1"
            // These pass the digit-ratio gate (14/20 = 70%) but are not secrets.
            if (val.matches("[0-9]+(\\.[0-9]+){3,}")) continue;
            // Reject JS strict-equality / optional-chain fragments: "===n.foo?", "!==x.bar"
            if (val.contains("===") || val.contains("!==")) continue;
            // Reject URL query-parameter strings: "&redirect_uri=...", "&response_type=id_token"
            if (val.contains("&") && val.contains("=")) continue;
            // Reject HTTP header names and lowercase hyphen-compound identifiers with ≤1 digit.
            // e.g., "x-adb2c-access-token", "x-api-version", "accept-encoding"
            // These are header names / BEM segments, not secrets. Real secrets have more digits.
            if (val.matches("[a-z][a-z0-9]*(-[a-z0-9]+)+")) {
                long digs = val.chars().filter(Character::isDigit).count();
                if (digs <= 1) continue;
            }
            if (!hasHighEntropy(val)) continue;
            // Reject values with no digits and no strong symbols (CSS class names, word identifiers).
            // Real secrets almost always contain at least one digit or strong punctuation.
            if (!isProbableSecretValue(val)) continue;
            // Require a semantic context keyword in the text SURROUNDING the value —
            // excluding the matched value span itself.  Without this exclusion, values like
            // "crux-password-strength__rule--checked" or "x-adb2c-access-token" trigger
            // their own ENTROPY_CONTEXT_KW match via "password" / "access-token" embedded
            // inside them, producing false positives.
            int winStart  = Math.max(0, m.start() - 80);
            String preCtx  = text.substring(winStart, m.start());
            int postEnd   = Math.min(text.length(), m.end() + 20);
            String postCtx = text.substring(m.end(), postEnd);
            // Try to recover a key name from the same line — done here so we can use it
            // both for noise filtering and as an alternative to ENTROPY_CONTEXT_KW.
            // ENTROPY_CONTEXT_KW uses \b which fails for compound names like
            // Ocp_Apim_Subscription_Key where '_' precedes 'subscription' (both \w chars).
            String keyName = extractNearbyKeyName(text, m.start());
            // Skip findings where the recovered key is a known UI/layout noise key
            // (e.g. "class", "style", "label") — these are filtered in scanGenericKV
            // but the entropy scanner needs its own guard.
            if (keyName != null && Patterns.NOISE_KEYNAMES.matcher(keyName).matches()) continue;
            boolean hasContextKw = Patterns.ENTROPY_CONTEXT_KW.matcher(preCtx).find() ||
                                   Patterns.ENTROPY_CONTEXT_KW.matcher(postCtx).find();
            boolean keyIsSecret  = keyName != null && isSemanticSecretKey(keyName);
            if (!hasContextKw && !keyIsSecret) continue;
            String dedupe = "ENTROPY:" + val;
            if (!seen.add(dedupe)) continue;
            String sev = keyName != null ? scoreSeverity(keyName, val) : "MEDIUM";
            String ctx = extractContext(text, m.start(), m.end());
            findings.add(SecretFinding.of(
                    "ENTROPY_TOKEN", "High-Entropy Secret Token",
                    keyName != null ? keyName : "token", val,
                    sev, "FIRM", countLines(text, m.start()), ctx, url));
        }
        return findings;
    }

    /**
     * Detects secrets returned from getter functions in JavaScript.
     * Catches runtime-assembled keys visible only in function return values — not as bare
     * string literals — making them invisible to the anchored-token and generic KV scanners.
     * Only called at FULL tier on JS content.
     *
     * Requires: semantic key name in the variable name OR 60+ char high-entropy value
     * (catches getAppId / getClientId patterns where the name lacks a secret keyword).
     */
    private List<SecretFinding> scanGetterFunctions(String text, String url) {
        List<SecretFinding> findings = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        java.util.regex.Pattern[] patterns = {
            Patterns.GETTER_ARROW_SHORT,
            Patterns.GETTER_FUNC_RETURN
        };
        for (java.util.regex.Pattern pat : patterns) {
            Matcher m = pat.matcher(text);
            while (m.find()) {
                String name = m.group(1);
                String val  = m.group(2);
                if (val == null || val.length() < 20 || isPlaceholder(val)) continue;
                if (!isProbableSecretValue(val)) continue;
                // Gate: semantic key name OR long high-entropy value (base64 getter, 60+ chars)
                boolean nameSemantic = isSemanticSecretKey(name) || isApiOverrideKey(name);
                if (!nameSemantic && (val.length() < 60 || !hasHighEntropy(val))) continue;
                String dedupe = "GETTER:" + val;
                if (!seen.add(dedupe)) continue;
                String sev = nameSemantic ? scoreSeverity(name, val) : "MEDIUM";
                findings.add(SecretFinding.of(
                        "GETTER_FUNC", "Secret Returned from Getter Function",
                        name, val, sev, "FIRM",
                        countLines(text, m.start()),
                        extractContext(text, m.start(), m.end()), url));
            }
        }
        return findings;
    }

    /** Scans backwards on the same line to find the key name before a quoted value. */
    private static String extractNearbyKeyName(String text, int valueStart) {
        int lineStart = text.lastIndexOf('\n', valueStart - 1) + 1;
        if (lineStart < 0) lineStart = 0;
        // Cap to last 200 chars — prevents O(n²) hang on minified JS with no newlines,
        // where the "line" would otherwise be the entire file up to this point.
        int prefixStart = Math.max(lineStart, valueStart - 200);
        String linePrefix = text.substring(prefixStart, valueStart);
        Matcher km = Patterns.KEY_BEFORE_VALUE.matcher(linePrefix.stripTrailing());
        String last = null;
        while (km.find()) last = km.group(1);
        return last;
    }

    /**
     * Recursive JSON body walker — uses Gson (Apache 2.0).
     * depth cap: 20, findings cap: 50.
     */
    private List<SecretFinding> walkJsonBody(String body, String url) {
        if (body == null || body.isBlank()) return List.of();
        try {
            JsonElement root = JsonParser.parseString(body);
            List<SecretFinding> findings = new ArrayList<>();
            Set<String> seen = new HashSet<>();
            walkJsonNode(root, "", findings, seen, url, 0);
            return findings;
        } catch (Exception e) {
            return List.of(); // malformed JSON — regex pass already ran
        }
    }

    private void walkJsonNode(JsonElement node, String path, List<SecretFinding> findings,
                              Set<String> seen, String url, int depth) {
        if (depth > JSON_MAX_DEPTH || findings.size() >= JSON_MAX_FINDINGS) return;

        if (node instanceof JsonObject obj) {
            for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
                if (findings.size() >= JSON_MAX_FINDINGS) return;
                String key = entry.getKey();
                JsonElement val = entry.getValue();
                if (val == null || val.isJsonNull()) continue;
                String childPath = path.isEmpty() ? key : path + "." + key;
                if (val.isJsonPrimitive() && val.getAsJsonPrimitive().isString()) {
                    checkJsonLeaf(key, val.getAsString(), childPath, findings, seen, url);
                } else if (val.isJsonObject() || val.isJsonArray()) {
                    walkJsonNode(val, childPath, findings, seen, url, depth + 1);
                }
            }
        } else if (node instanceof JsonArray arr) {
            for (int i = 0; i < arr.size(); i++) {
                if (findings.size() >= JSON_MAX_FINDINGS) return;
                JsonElement item = arr.get(i);
                if (item == null || item.isJsonNull()) continue;
                String childPath = path + "[" + i + "]";
                if (item.isJsonObject() || item.isJsonArray()) {
                    walkJsonNode(item, childPath, findings, seen, url, depth + 1);
                } else if (item.isJsonPrimitive() && item.getAsJsonPrimitive().isString()) {
                    // Array string element — anchored patterns only (no key context)
                    checkAnchoredOnValue(item.getAsString(), childPath, findings, seen, url);
                }
            }
        }
    }

    // OAuth 2.0 / OIDC token response fields that always carry sensitive tokens.
    // Fast-path: bypass entropy/probability gates and always emit HIGH CERTAIN.
    private static final java.util.Set<String> OAUTH_TOKEN_KEYS = java.util.Set.of(
            "access_token", "accesstoken",
            "refresh_token", "refreshtoken",
            "id_token", "idtoken"
    );

    private void checkJsonLeaf(String key, String val, String path,
                               List<SecretFinding> findings, Set<String> seen, String url) {
        if (val == null || val.length() < 4) return;
        if (isForcedNoiseKey(key)) return;
        if (Patterns.NOISE_KEYNAMES.matcher(key).matches()) return;

        // Fast-path: OAuth token response fields — always HIGH CERTAIN, no entropy gate.
        // Catches access_token / refresh_token / id_token in any JSON response regardless
        // of request state or scan tier. Anchored patterns still run below for ruleId accuracy.
        String keyLc = key.toLowerCase().replace("_", "").replace("-", "");
        if (OAUTH_TOKEN_KEYS.contains(key.toLowerCase()) || OAUTH_TOKEN_KEYS.contains(keyLc)) {
            if (val.length() >= 20 && !isPlaceholder(val)) {
                String dedupeFast = "OAUTH_FAST:" + key.toLowerCase() + ":" + val;
                if (seen.add(dedupeFast)) {
                    findings.add(SecretFinding.of(
                            "JSON_WALK", "OAuth Token in Response (" + path + ")",
                            key, val, "HIGH", "CERTAIN", 0, path, url));
                }
            }
        }

        // Try anchored patterns first (no key-name dependency, highest confidence)
        checkAnchoredOnValue(val, path, findings, seen, url);

        // Semantic gate
        if (!isSemanticSecretKey(key) && !isApiOverrideKey(key)) {
            // Special case: bare "token" or "secret" field name in structured JSON —
            // the most common field names in API token/OAuth responses.
            // Require high entropy so CSRF tokens, pagination cursors, and nonces
            // (which have low entropy or short length) are not reported.
            String kl = key.toLowerCase();
            if ((kl.equals("token") || kl.equals("secret"))
                    && hasHighEntropy(val) && isProbableSecretValue(val)) {
                // Allow fall-through to report this finding
            } else {
                return;
            }
        } else if (!isProbableSecretValue(val)) {
            return;
        }
        if (Patterns.BLOCKCHAIN_HASH_KEY.matcher(key).find()) return;

        String dedupe = key.toLowerCase() + ":" + val;
        if (!seen.add(dedupe)) return;

        String sev  = scoreSeverity(key, val);
        String conf = hasHighEntropy(val) ? "CERTAIN" : "FIRM";
        findings.add(SecretFinding.of(
                "JSON_WALK", "JSON Deep Secret (" + path + ")",
                key, val, sev, conf, 0, path, url));
    }

    private void checkAnchoredOnValue(String val, String path,
                                      List<SecretFinding> findings, Set<String> seen, String url) {
        for (Patterns.AnchoredRule rule : Patterns.ANCHORED_RULES) {
            Matcher m = rule.pattern().matcher(val);
            if (m.find()) {
                String matched = m.group(0).trim();
                String dedupe  = rule.ruleId() + ":" + matched;
                if (!seen.add(dedupe)) continue;
                findings.add(SecretFinding.of(
                        rule.ruleId(), rule.ruleName(), rule.keyName(), matched,
                        rule.severity(), "CERTAIN", 0, path, url));
            }
        }
    }

    /**
     * Extract secrets from XML element text content.
     * Handles API responses like {@code <token>eyJ...</token>} and
     * {@code <resource_key>abc123</resource_key>}.
     * Uses the same semantic + entropy gates as checkJsonLeaf.
     */
    private List<SecretFinding> scanXmlLeaves(String text, String url) {
        List<SecretFinding> findings = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        Matcher m = Patterns.XML_ELEMENT.matcher(text);
        while (m.find()) {
            String key = m.group(1);
            String val = m.group(2).trim();
            if (val.length() < 4) continue;
            checkJsonLeaf(key, val, key, findings, seen, url);
        }
        return findings;
    }

    /** SSN dual-guard: format match + key context in surrounding lines. */
    private List<SecretFinding> scanPiiSsn(String text, String url) {
        List<SecretFinding> findings = new ArrayList<>();
        Matcher m = Patterns.SSN.matcher(text);
        while (m.find()) {
            String window = extractWindow(text, m.start(), 3);
            if (!Patterns.SSN_CONTEXT.matcher(window).find()) continue;
            findings.add(SecretFinding.of(
                    "SSN_PII", "Social Security Number (PII)",
                    "ssn", m.group(0), "MEDIUM", "FIRM",
                    countLines(text, m.start()),
                    extractContext(text, m.start(), m.end()), url));
        }
        return findings;
    }

    /** Credit card: format match + Luhn validation + context checks. */
    private List<SecretFinding> scanPiiCreditCard(String text, String url) {
        List<SecretFinding> findings = new ArrayList<>();
        Matcher m = Patterns.CC_CANDIDATE.matcher(text);
        while (m.find()) {
            String candidate = m.group(0);
            if (!luhnValid(candidate)) continue;
            // FP fix [4c]: reject floating-point literals like .5522847498307935
            if (m.start() > 0 && text.charAt(m.start() - 1) == '.') continue;
            // FP fix [4c]: reject if digit immediately precedes (part of a larger number)
            if (m.start() > 0 && Character.isDigit(text.charAt(m.start() - 1))) continue;
            // FP fix [4c]: reject if followed immediately by a digit
            if (m.end() < text.length() && Character.isDigit(text.charAt(m.end()))) continue;
            // Context check: reject if in a clear math/code expression context
            int ctxStart = Math.max(0, m.start() - 30);
            String before = text.substring(ctxStart, m.start());
            if (before.matches(".*[=,+\\-*/(]\\s*[\\d.]*$")) {
                // Looks like a numeric expression — ensure it's quoted or in data context
                if (!before.matches(".*[\"']\\s*$")) continue;
            }
            findings.add(SecretFinding.of(
                    "CC_PII", "Credit Card Number (PII)",
                    "credit_card", candidate, "HIGH", "FIRM",
                    countLines(text, m.start()),
                    extractContext(text, m.start(), m.end()), url));
        }
        return findings;
    }

    // =========================================================================
    // Utility — crypto / math
    // =========================================================================

    /** Shannon entropy in bits/char. */
    public static double shannonEntropy(String s) {
        if (s == null || s.isEmpty()) return 0.0;
        Map<Character, Integer> counts = new HashMap<>();
        for (char ch : s.toCharArray())
            counts.merge(ch, 1, Integer::sum);
        int    n       = s.length();
        double entropy = 0.0;
        for (int c : counts.values()) {
            double p = (double) c / n;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    /** Luhn algorithm — eliminates ~90% of accidental CC-format false positives. */
    public static boolean luhnValid(String number) {
        String digits = number.replaceAll("\\D", "");
        if (digits.length() < 13 || digits.length() > 19) return false;
        int     total     = 0;
        boolean alternate = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int d = digits.charAt(i) - '0';
            if (alternate) {
                d *= 2;
                if (d > 9) d -= 9;
            }
            total += d;
            alternate = !alternate;
        }
        return total % 10 == 0;
    }

    // =========================================================================
    // Utility — value / key classification
    // =========================================================================

    private boolean isExternalCdn(String url) {
        try {
            String host = new URL(url).getHost();
            return settings.isExternalCdn(host);
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean isForcedNoiseKey(String key) {
        if (key == null) return false;
        return Patterns.FORCED_NOISE_KEYS.contains(key.trim().toLowerCase());
    }

    private static boolean isSemanticSecretKey(String name) {
        if (name == null || name.length() <= 2) return false;
        String lower = name.toLowerCase();
        // Keys ending in _endpoint / _url / _uri / _host always point to URLs, never secrets
        if (lower.endsWith("_endpoint") || lower.endsWith("_url") ||
                lower.endsWith("_uri") || lower.endsWith("_host")) return false;
        // data- attributes: only allow known secret variants
        if (lower.startsWith("data-") &&
                !lower.matches("data-(?:api[_-]?key|auth[_-]?token|secret|access[_-]?token|client[_-]?secret)"))
            return false;
        // Bare single-word secret/password keys — segmented prefix check requires ≥2 parts
        // so these single-word keys need an explicit guard.
        if (lower.equals("password") || lower.equals("passwd") ||
                lower.equals("pass") || lower.equals("pwd") ||
                lower.equals("secret") || lower.equals("resource")) return true;
        // REAL_SECRET_KEYNAME regex: specific anchored compound patterns (highest precision)
        if (Patterns.REAL_SECRET_KEYNAME.matcher(lower).find()) return true;

        // Word-boundary segment check:
        // Split by underscores/hyphens/spaces and camelCase boundaries, then look for a
        // recognized secret-component segment PAIRED WITH a recognized domain-prefix segment.
        //
        // camelCase normalization inserts '_' before uppercase-after-lowercase transitions so
        // "userId" → "user_Id" → lowercase → "user_id" → ["user","id"] — this means compound
        // camelCase names like userId, applicationId, subscriptionId, workspaceId are handled
        // identically to their underscore-separated equivalents (user_id, application_id, …).
        // Space is also a separator so JSON keys like "User ID" are handled correctly.
        //
        // This avoids: alertKey (→ "alertKey" → "alert_key" → parts=["alert","key"] but
        //              "alert" ∉ SECRET_KEY_PREFIXES → excluded),
        //              INTERACTION_STATUS_KEY (none of its parts ∈ SECRET_KEY_PREFIXES → excluded).
        // Allows: api_key (["api","key"], "api" ∈ prefixes → ✓),
        //         userId (["user","id"], "user" ∈ prefixes, "id" ∈ targets → ✓),
        //         "User ID" (space-separated JSON key → ["user","id"] → ✓),
        //         applicationId (["application","id"], "application" ∈ prefixes → ✓).
        String normalized = name.replaceAll("([a-z])([A-Z])", "$1_$2").toLowerCase();
        String[] parts = normalized.split("[_\\-\\s]+");
        if (parts.length >= 2) {
            // Reject UI display-label field names: last segment is "label", "hint", or "placeholder"
            // e.g. UserIdLabel, apiKeyHint, passwordPlaceholder — these hold UI text, not secrets.
            // True credential fields (userId, apiKey) are not affected since their last segment
            // is "id" / "key", not "label".
            String lastPart = parts[parts.length - 1];
            if (lastPart.equals("label") || lastPart.equals("hint") || lastPart.equals("placeholder")) {
                return false;
            }
            boolean hasSecretPrefix = false;
            for (String p : parts) {
                if (SECRET_KEY_PREFIXES.contains(p)) { hasSecretPrefix = true; break; }
            }
            for (String part : parts) {
                // These require a recognized domain prefix to be meaningful
                if ((part.equals("key") || part.equals("token") ||
                     part.equals("secret") || part.equals("subscription") ||
                     part.equals("id")) && hasSecretPrefix) {    // "id" covers userId, user_id, applicationId, …
                    return true;
                }
                // Password-family words are always a secret signal
                if (part.equals("credential") || part.equals("credentials") ||
                    part.equals("password") || part.equals("pass") || part.equals("pwd")) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Strips the scheme prefix from an Authorization header value ("Bearer ...", "Basic ..."). */
    private static String stripAuthScheme(String authHeader) {
        if (authHeader == null) return null;
        String v = authHeader.trim();
        int spaceIdx = v.indexOf(' ');
        return spaceIdx > 0 ? v.substring(spaceIdx + 1).trim() : v;
    }

    /**
     * Returns true if {@code val} is a JWT (three dot-separated base64url segments
     * starting with "ey").  JWTs appear in every authenticated request and must
     * never be reported as secret findings.
     */
    private static boolean isJwt(String val) {
        return val != null && JWT_PAT.matcher(val.trim()).matches();
    }

    /**
     * Filters request-scope findings:
     *   1. Removes JWT Bearer tokens (expected in every authenticated request).
     *   2. Removes values already reported from a previous request in this session
     *      (cross-request deduplication — prevents noise when the same hardcoded
     *      API key appears in X-API-Key on every call).
     * Response findings are NOT passed through here.
     */
    private List<SecretFinding> filterRequestFindings(List<SecretFinding> findings) {
        List<SecretFinding> result = new ArrayList<>();
        for (SecretFinding f : findings) {
            if (isJwt(f.matchedValue())) continue;
            if (!seenRequestValues.add(f.matchedValue())) continue;
            result.add(f);
        }
        return result;
    }

    /** Clears the cross-request deduplication cache (call between scan sessions). */
    public void clearRequestDedup() {
        seenRequestValues.clear();
    }

    /** High-confidence override keys — emit finding even without entropy check. */
    private static boolean isApiOverrideKey(String key) {
        if (key == null) return false;
        String k = key.toLowerCase().replaceAll("[_\\-]", "");
        return k.contains("apikey") || k.contains("apitoken") || k.contains("apisecret") ||
               k.contains("appkey") || k.contains("appsecret") ||
               k.contains("subscriptionkey") || k.contains("secretkey") ||
               k.contains("apimkey") || k.contains("accesstoken") ||
               k.contains("authtoken") || k.contains("clientsecret") ||
               k.contains("consumersecret") || k.contains("consumerkey") ||
               k.contains("awssecret") || k.contains("sshkey") ||
               k.contains("encryptionkey") || k.contains("encryptkey") ||
               k.contains("decryptionkey") || k.contains("decryptkey");
    }

    private boolean isProbableSecretValue(String val) {
        if (val == null || val.length() < 12) return false;
        String v = val.trim();
        // Reject URLs and paths
        if (v.startsWith("http://") || v.startsWith("https://") ||
            v.startsWith("urn:") ||
            v.startsWith("/") || v.startsWith("#") || v.startsWith("./")) return false;
        // Reject values with whitespace (likely prose text)
        if (v.chars().anyMatch(Character::isWhitespace)) return false;
        // Identifiers and schema field names — variable names, PascalCase class/field names,
        // camelCase config keys, snake_case constants.  Real credential values always carry
        // at least one digit or special character.  Two sub-rules:
        //   (a) all-alpha strings (no digits at all) are NEVER credentials regardless of length
        //       — catches FirstName, PortalNotifications, AddressLine, etc.
        //   (b) short alphanumeric identifiers (camelCase / PascalCase / snake_case, ≤ 32 chars)
        //       are very likely schema field names or enum values, not real secrets.
        //       Cap raised to 32 to cover patterns like SystemNotificationEvents123 (29 chars).
        if (v.matches("[A-Za-z_]+")) return false;   // (a) all alpha / underscore, any length
        if (v.matches("[A-Za-z_][A-Za-z0-9_]*") && v.length() <= 32) return false;  // (b)
        // Reject SCREAMING_SNAKE_CASE enum/constant values
        // e.g., PENDING_UNABLE_POSTPONE_PAYMENT_12_DAYS_CHANGE_KEY, INTERACTION_STATUS_KEY
        if (v.matches("[A-Z][A-Z0-9_]+") && v.length() <= 80) return false;
        // Reject dotted/colon namespace identifier patterns (library constants, URNs, event names)
        // e.g., adal.idtoken, msal:acquireTokenStart, interaction.status, oauth2:scope:read
        if (v.matches("[a-zA-Z][a-zA-Z0-9]*([:._][a-zA-Z][a-zA-Z0-9]*)+")) return false;
        // Reject Azure AD B2C policy/user-flow name format: B2C_1_Name or B2C_1A_Name
        // These are framework policy identifiers, never credential values.
        if (v.matches("(?i)B2C_1[A-Z0-9]?_[A-Za-z0-9_]+")) return false;
        // Reject JS/code fragment values (minified JS operator patterns)
        // e.g., "+i):r&&f.push(", "this.apiKey),this.channel&&(e+="
        if (v.contains("&&") || v.contains("||") || v.contains("=>") || v.contains("?.")) return false;
        if (v.contains(".push(") || v.contains(".call(") || v.contains(".apply(")) return false;
        // Reject React/DOM code fragments embedded in minified JS key-value matches
        if (v.contains(".render(") || v.contains("document.getElementById") ||
                v.contains("document.querySelector")) return false;
        // FP fix [4b]: reject encoding alphabet constants (Base64 charset, hex charsets)
        if (isEncodingAlphabet(v)) return false;
        // Reject error/status message patterns — reduces FPs from error response bodies.
        // Only applied to short values; long token strings are never error messages.
        if (v.length() <= 80) {
            String vl = v.toLowerCase();
            if (vl.endsWith("_error") || vl.endsWith("_exception") || vl.endsWith("_failed") ||
                vl.startsWith("error_") || vl.startsWith("err_") ||
                vl.equals("undefined") || vl.equals("null")) {
                return false;
            }
        }
        // Must contain at least a digit or a strong punctuation symbol
        boolean hasDigit  = v.chars().anyMatch(Character::isDigit);
        String  strongSym = "~`!@#$%^&*+=|?.:,;";
        boolean hasSym    = v.chars().anyMatch(c -> strongSym.indexOf(c) >= 0);
        return hasDigit || hasSym;
    }

    /**
     * Returns true if the value looks like an encoding alphabet constant —
     * a long run of consecutive ASCII characters (≥10 sequential chars).
     * Catches BASE64 charset ("ABCDEFGHIJ...abc...0123456789+/="),
     * hex alphabet, base58, and similar encoder initialisation strings.
     * FP fix [4b].
     */
    private static boolean isEncodingAlphabet(String val) {
        if (val == null || val.length() < 30) return false;
        int maxRun = 0, run = 1;
        for (int i = 1; i < val.length(); i++) {
            if (val.charAt(i) == val.charAt(i - 1) + 1) {
                run++;
                if (run > maxRun) maxRun = run;
            } else {
                run = 1;
            }
        }
        return maxRun >= 10;
    }

    /**
     * Returns true if the key looks like a UI framework directive attribute.
     * Catches: ng-keyup, v-on:click, @submit, :class, data-ng-model, etc.
     * FP fix [4a].
     */
    private static boolean isFrameworkAttributeKey(String key) {
        if (key == null || key.isEmpty()) return false;
        String lower = key.toLowerCase();
        for (String prefix : Patterns.FRAMEWORK_ATTR_PREFIXES) {
            if (lower.startsWith(prefix)) return true;
        }
        // Vue/React/DOM event handlers: onClick, onChange, onKeyUp, onMouseOver, etc.
        if (lower.matches("on[a-z]{2,}")) return true;
        return false;
    }

    private boolean hasHighEntropy(String val) {
        if (val == null || val.length() < 16 || val.length() > 512) return false;
        // Reject URL paths and file paths, but allow base64 values that legitimately
        // contain '/' (standard base64 alphabet). A value is path-like only if it
        // starts with '/' or contains '://' (looks like a full URL).
        if (val.startsWith("/") || val.contains("://") || val.contains("\\")) return false;
        // Reject real UUIDs
        if (val.matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}" +
                        "-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")) return false;
        // Reject blockchain-style 0x hashes
        if (val.matches("0x[0-9a-fA-F]{40,}")) return false;
        int n       = val.length();
        int digits  = (int) val.chars().filter(Character::isDigit).count();
        int letters = (int) val.chars().filter(Character::isLetter).count();
        // Reject alphabet-dominant short strings
        if (letters >= n * 0.85 && digits <= 2) return false;
        // Reject repetitive strings
        if (val.chars().distinct().count() <= 3) return false;
        // Strong signals
        if ((double) digits / n >= 0.45) return true;
        int symbols = n - digits - letters;
        if ((double) symbols / n >= 0.20) return true;
        if (n >= 20 && digits >= 6 && letters >= 6) return true;
        if (n >= 28 && val.matches("[a-z0-9]+") && digits >= 6) return true;
        if (val.toLowerCase().matches("[a-f0-9]{32,}")) return true;
        return shannonEntropy(val) >= settings.getEntropyThreshold();
    }

    private static boolean isPlaceholder(String val) {
        if (val == null) return true;
        String v = val.toLowerCase();
        if (v.matches(".*([xX]{6,}|placeholder|example|your[_\\-]?token|" +
                      "<[^>]+>|\\$\\{[^}]+\\}|%[a-z_]+%|dummy|test_?key|" +
                      "changeme|replace_?me|insert_?here).*")) return true;
        // Monotone string: same character repeated 20+ times (e.g. Twitter public bearer AAAA...)
        if (val.length() >= 20 && val.chars().distinct().count() == 1) return true;
        return false;
    }

    // =========================================================================
    // Severity scoring
    // =========================================================================

    private String scoreSeverity(String key, String val) {
        if (key == null) return "LOW";
        if (!isProbableSecretValue(val)) return "LOW";
        String k = key.toLowerCase().replaceAll("[_\\-]", "");
        if (k.contains("encryptedenv") || k.contains("cryptojskey") || k.contains("cryptokey")) return "HIGH";
        if (k.contains("subscriptionkey") || k.contains("subkey") || k.contains("ocpapim")) return "HIGH";
        if (k.contains("apimkey"))         return "HIGH";
        if (k.contains("appkey") || k.contains("applicationkey")) return "HIGH";
        if (k.equals("secret") || k.equals("resource")) return "HIGH";   // bare "secret"/"resource" field in config/JSON
        if (k.contains("secretkey") || k.contains("signingkey") || k.contains("masterkey")) return "HIGH";
        if (k.contains("apikey") || k.contains("xapikey"))       return "HIGH";
        if (k.contains("resourcekey") || k.contains("storagekey")) return "HIGH";
        if (k.contains("privatekey") || k.contains("pemkey"))     return "HIGH";
        if (k.contains("clientsecret"))    return "HIGH";
        if (k.contains("refreshtoken") || k.contains("accesstoken") ||
            k.contains("authtoken") || k.contains("sessiontoken")) return "HIGH";
        if (k.equals("password") || k.equals("passwd") || k.equals("pass") || k.equals("pwd") ||
            k.equals("credentials") || k.equals("credential"))     return "HIGH";
        // Public identifiers — OAuth client IDs, app IDs, tenant/org IDs, telemetry keys,
        // reCAPTCHA site keys, and LaunchDarkly-style client-side IDs are all intended
        // to be embedded in frontend JS.  They carry no standalone credential risk.
        if (k.contains("clientid") || k.contains("clientsideid")) return "INFORMATION";
        if (k.contains("tenantid"))                               return "INFORMATION";
        if (k.contains("instrumentationkey") || k.contains("insightsikey") || k.endsWith("ikey")) return "INFORMATION";
        if (k.contains("appid") || k.contains("applicationid"))   return "INFORMATION";
        if (k.contains("orgid") || k.contains("accountid") || k.contains("workspaceid")) return "INFORMATION";
        if (k.contains("sitekey"))                                return "INFORMATION";
        if (k.contains("userid"))                                 return "LOW";
        if (isSemanticSecretKey(key))      return "MEDIUM";
        return "LOW";
    }

    // =========================================================================
    // Deduplication
    // =========================================================================

    private static List<SecretFinding> deduplicate(List<SecretFinding> raw) {
        Set<String> seenRuleValue = new LinkedHashSet<>();
        Set<String> seenValue     = new LinkedHashSet<>();   // values seen by specific rules
        List<SecretFinding> result = new ArrayList<>();
        for (SecretFinding f : raw) {
            // For context-sensitive rules (GENERIC_KV, JSON_WALK, REQ_HEADER*) the key name
            // is extracted from the surrounding text and carries semantic meaning.
            // The same secret value assigned to two different variable/field names represents
            // two distinct findings — e.g., Ocp_Apim_Subscription_Key = "k" and
            // Ocp_Apim_Subscription_Key_static_content = "k" are two API credentials even if
            // they share the same actual key value.  Include keyName in the dedup key so both
            // are kept.
            boolean contextSensitive = f.ruleId().equals("GENERIC_KV")
                    || f.ruleId().equals("JSON_WALK")
                    || f.ruleId().startsWith("REQ_HEADER");
            // For GENERIC_KV: include line number so the same key+value at different lines
            // (e.g., different environment config blocks in the same HTML page) each produce
            // a separate finding.  JSON_WALK and REQ_HEADER keep value-level dedup because
            // their "line" is less meaningful across heterogeneous JSON structures.
            String dedupeKey = f.ruleId().equals("GENERIC_KV")
                    ? f.ruleId() + ":" + f.keyName() + ":" + f.matchedValue() + ":" + f.lineNumber()
                    : contextSensitive
                        ? f.ruleId() + ":" + f.keyName() + ":" + f.matchedValue()
                        : f.ruleId() + ":" + f.matchedValue();
            if (!seenRuleValue.add(dedupeKey)) continue;

            if (contextSensitive) {
                // Context-sensitive finding passed the rule+key+value dedup — always keep it.
                // Still register the value so ENTROPY_TOKEN for the same value is suppressed.
                seenValue.add(f.matchedValue());
            } else {
                // For ENTROPY_TOKEN: suppress if this value was already caught by a more
                // specific rule (anchored vendor token, GENERIC_KV, JSON_WALK, REQ_HEADER).
                // For all other rules: register the value for ENTROPY_TOKEN suppression.
                if (f.ruleId().equals("ENTROPY_TOKEN")) {
                    if (!seenValue.add(f.matchedValue())) continue;
                } else {
                    seenValue.add(f.matchedValue());
                }
            }
            result.add(f);
        }
        return result;
    }

    /**
     * Applies key-name blocklist/allowlist from ScanSettings, then deduplicates.
     * - Allowlist wins: if keyName matches any allowlist entry, finding is always kept.
     * - Blocklist: if keyName matches any blocklist entry (and not allowlisted), finding is dropped.
     * Called at every public scan exit point so both scanText() and scanRequestResponse() honour the lists.
     */
    private List<SecretFinding> filterAndDeduplicate(List<SecretFinding> raw) {
        List<SecretFinding> filtered = new ArrayList<>(raw.size());
        for (SecretFinding f : raw) {
            // Drop any finding whose value is blank — belt-and-suspenders guard
            if (f.matchedValue() == null || f.matchedValue().isBlank()) continue;
            if (settings.isKeyAllowlisted(f.keyName())) {
                filtered.add(f);          // allowlist always wins
            } else if (!settings.isKeyBlocked(f.keyName())) {
                filtered.add(f);          // not blocked — normal path
            }
            // else: blocked and not allowlisted → silently dropped
        }
        return deduplicate(filtered);
    }

    // =========================================================================
    // Public helpers for BulkScanPanel — HTML extraction utilities
    // =========================================================================

    /**
     * Extracts the content of all inline &lt;script&gt; blocks (no src attribute)
     * from the given HTML. Used by BulkScanPanel to scan each block independently.
     */
    public static List<String> extractInlineScripts(String html) {
        if (html == null || html.isBlank()) return List.of();
        List<String> blocks = new ArrayList<>();
        Matcher m = Patterns.INLINE_SCRIPT.matcher(html);
        while (m.find()) {
            String body = m.group(1);
            if (body != null && !body.isBlank() && body.length() > 20) {
                blocks.add(body);
            }
        }
        return blocks;
    }

    /**
     * Extracts all &lt;script src="..."&gt; URLs from HTML and resolves them against
     * the given base URL. Returns absolute URL strings.
     */
    public static List<String> extractScriptSrcs(String html, String baseUrl) {
        if (html == null || html.isBlank()) return List.of();
        List<String> urls = new ArrayList<>();
        Set<String>  seen = new HashSet<>();
        Matcher m = Patterns.SCRIPT_SRC.matcher(html);
        while (m.find()) {
            String src = m.group(1);
            if (src == null || src.isBlank()) continue;
            String abs = resolveUrl(baseUrl, src);
            if (abs != null && seen.add(abs)) urls.add(abs);
        }
        return urls;
    }

    /**
     * Extracts all {@code <frame src="...">} and {@code <iframe src="...">} URLs from HTML
     * and resolves them against the given base URL.  Returns absolute URL strings.
     *
     * Needed for legacy frameset-based apps where the root page is a thin shell that
     * delegates all content (and its {@code <script src>} references) to child frames.
     */
    public static List<String> extractFrameSrcs(String html, String baseUrl) {
        if (html == null || html.isBlank()) return List.of();
        List<String> urls = new ArrayList<>();
        Set<String>  seen = new HashSet<>();
        Matcher m = Patterns.FRAME_SRC.matcher(html);
        while (m.find()) {
            String src = m.group(1);
            if (src == null || src.isBlank()) continue;
            String abs = resolveUrl(baseUrl, src);
            if (abs != null && seen.add(abs)) urls.add(abs);
        }
        return urls;
    }

    /**
     * Extracts JS-based redirect target URLs from an HTML page:
     * {@code window.location.href = "..."}, {@code location.replace("...")} and
     * {@code <meta http-equiv="refresh" content="0; url=...">}.
     *
     * Used when the root page navigates via JavaScript rather than {@code <frame src>}
     * or {@code <a href>}, so static frame/script parsing finds nothing.
     */
    public static List<String> extractJsRedirects(String html, String baseUrl) {
        if (html == null || html.isBlank()) return List.of();
        List<String> urls = new ArrayList<>();
        Set<String>  seen = new HashSet<>();
        Matcher m = Patterns.JS_REDIRECT.matcher(html);
        while (m.find()) {
            String raw = m.group(1);
            if (raw == null || raw.isBlank()) continue;
            String abs = resolveUrl(baseUrl, raw);
            if (abs != null && seen.add(abs)) urls.add(abs);
        }
        Matcher m2 = Patterns.META_REFRESH.matcher(html);
        while (m2.find()) {
            String raw = m2.group(1).trim();
            if (raw.isBlank()) continue;
            String abs = resolveUrl(baseUrl, raw);
            if (abs != null && seen.add(abs)) urls.add(abs);
        }
        // Handle: location.href = 'https://' + location.hostname + '/path'
        // Extract the path and resolve it against the same host as baseUrl.
        Matcher m3 = Patterns.JS_REDIRECT_HOSTNAME.matcher(html);
        while (m3.find()) {
            String path = m3.group(1);
            if (path == null || path.isBlank()) continue;
            String abs = resolveUrl(baseUrl, path);
            if (abs != null && seen.add(abs)) urls.add(abs);
        }
        return urls;
    }

    /**
     * Scans a JS bundle for webpack / Next.js chunk file references and returns
     * resolved absolute URLs. Depth-1 chunk following.
     */
    public static List<String> extractWebpackChunkUrls(String jsContent, String baseUrl) {
        if (jsContent == null || jsContent.isBlank()) return List.of();
        List<String> urls = new ArrayList<>();
        Set<String>  seen = new HashSet<>();
        Matcher m = Patterns.WEBPACK_CHUNK_REF.matcher(jsContent);
        while (m.find()) {
            String ref = m.group(1);
            if (ref == null || ref.isBlank()) continue;
            String abs = resolveUrl(baseUrl, ref);
            if (abs != null && seen.add(abs)) urls.add(abs);
        }
        return urls;
    }

    /**
     * Extracts &lt;link rel="preload" as="script" href="..."&gt; URLs from HTML.
     * SPAs eagerly preload all JS chunks via preload hints; following these discovers
     * more JS files than script-src alone.
     */
    public static List<String> extractPreloadLinks(String html, String baseUrl) {
        if (html == null || html.isBlank()) return List.of();
        List<String> urls = new ArrayList<>();
        Set<String>  seen = new HashSet<>();
        Matcher m = Patterns.PRELOAD_JS_LINK.matcher(html);
        while (m.find()) {
            String src = m.group(1);
            if (src == null || src.isBlank()) continue;
            String abs = resolveUrl(baseUrl, src);
            if (abs != null && seen.add(abs)) urls.add(abs);
        }
        return urls;
    }

    /**
     * Extracts JS file paths from a webpack/Vite/CRA asset manifest JSON
     * (asset-manifest.json, chunk-manifest.json, etc.) and resolves them
     * to absolute URLs. Used for manifest-following in the bulk scanner.
     */
    public static List<String> extractAssetManifestUrls(String manifestBody, String baseUrl) {
        if (manifestBody == null || manifestBody.isBlank()) return List.of();
        List<String> urls = new ArrayList<>();
        Set<String>  seen = new HashSet<>();
        // Match quoted values that end in .js (handles CRA, Next, Vite manifest formats)
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(
                "[\"'](/[^\"'*$?\\s]*?\\.(?:chunk\\.js|bundle\\.js|min\\.js|js))[\"']"
        ).matcher(manifestBody);
        while (m.find()) {
            String path = m.group(1);
            if (path == null || path.isBlank()) continue;
            String abs = resolveUrl(baseUrl, path);
            if (abs != null && seen.add(abs)) urls.add(abs);
        }
        return urls;
    }

    /** Resolves a potentially relative URL against a base URL. Returns null on failure. */
    public static String resolveUrl(String baseUrl, String ref) {
        if (ref == null || ref.isBlank()) return null;
        if (ref.startsWith("http://") || ref.startsWith("https://")) return ref;
        if (ref.startsWith("//")) {
            try {
                String scheme = new java.net.URL(baseUrl).getProtocol();
                return scheme + ":" + ref;
            } catch (Exception e) { return "https:" + ref; }
        }
        try {
            java.net.URL base     = new java.net.URL(baseUrl);
            java.net.URL resolved = new java.net.URL(base, ref);
            return resolved.toString();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Context-gated rules: pattern must include a keyword near the value.
     * Handles AWS Secret Access Key, Azure DevOps PAT, Snowflake, Jira, Salesforce.
     */
    private List<SecretFinding> scanContextGatedRules(String text, String url) {
        List<SecretFinding> findings = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (Patterns.CtxRule rule : Patterns.CONTEXT_GATED_RULES) {
            Matcher m = rule.pattern().matcher(text);
            while (m.find()) {
                String val = m.group(rule.captureGroup());
                if (val == null || val.isBlank() || val.length() < 8) continue;
                if (isPlaceholder(val)) continue;
                String dedupe = rule.ruleId() + ":" + val;
                if (!seen.add(dedupe)) continue;
                int    line    = countLines(text, m.start());
                String ctx     = extractContext(text, m.start(), m.end());
                String keyName   = rule.keyName();
                String severity  = rule.severity();
                try {
                    String k = m.group("key");
                    if (k != null && !k.isBlank()) {
                        keyName  = k.replaceAll("[\"']", "").trim();
                        severity = scoreSeverity(keyName, val);   // re-score using actual key name
                    }
                } catch (IllegalArgumentException ignored) {}
                findings.add(SecretFinding.of(
                        rule.ruleId(), rule.ruleName(), keyName, val,
                        severity, "FIRM", line, ctx, url));
            }
        }
        return findings;
    }

    // =========================================================================
    // Text utilities
    // =========================================================================

    private static int countLines(String text, int offset) {
        int count = 1;
        int limit = Math.min(offset, text.length());
        for (int i = 0; i < limit; i++)
            if (text.charAt(i) == '\n') count++;
        return count;
    }

    private static String extractContext(String text, int start, int end) {
        int s = Math.max(0, start - 40);
        int e = Math.min(text.length(), end + 40);
        return text.substring(s, e).replace("\n", " ").replace("\r", "");
    }

    /** Extract ±lineRadius lines around the character at {@code offset}. */
    private static String extractWindow(String text, int offset, int lineRadius) {
        String[] lines  = text.split("\n", -1);
        int      lineNo = countLines(text, offset) - 1;
        int      from   = Math.max(0, lineNo - lineRadius);
        int      to     = Math.min(lines.length - 1, lineNo + lineRadius);
        StringBuilder sb = new StringBuilder();
        for (int i = from; i <= to; i++) sb.append(lines[i]).append('\n');
        return sb.toString();
    }
}
