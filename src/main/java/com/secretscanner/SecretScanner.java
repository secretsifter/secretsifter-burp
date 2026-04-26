package com.secretscanner;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.net.URL;
import java.nio.charset.StandardCharsets;
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
     * Single suppressed-finding entry collected during a debug scan.
     * Captured when a candidate value passes the initial match but is dropped by a
     * suppression gate (hex guard, entropy gate, no-context-keyword, blocklist, etc.).
     */
    public record DebugEntry(
            String ruleId,   // rule or scan-step that suppressed the value
            String keyName,  // key name (best-effort; may be empty)
            String value,    // raw matched value (truncated to 120 chars)
            String reason,   // suppression reason code
            String url       // source URL
    ) {}

    /** Null-safe helper — appends an entry only when the accumulator is non-null. */
    private static void dbgAdd(List<DebugEntry> dbg, DebugEntry e) {
        if (dbg != null) dbg.add(e);
    }

    /** Truncate a value for debug display — avoids multi-KB blobs in the CSV. */
    private static String dbgVal(String v) {
        if (v == null) return "";
        return v.length() > 120 ? v.substring(0, 117) + "..." : v;
    }

    /**
     * JWT pattern: three dot-separated base64url segments starting with "ey".
     * Matches Bearer tokens produced by every standard JWT library — they are
     * expected in every authenticated request and must never be reported as findings.
     */
    private static final java.util.regex.Pattern JWT_PAT =
            java.util.regex.Pattern.compile(
                    "^ey[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*$");

    /**
     * Known vendor token prefixes that appear as Authorization: Bearer values.
     * Opaque Bearer tokens with none of these prefixes are dynamic session/OAuth
     * tokens and are suppressed from request-header findings to avoid per-request
     * noise in authenticated apps.
     */
    private static final Set<String> BEARER_VENDOR_PREFIXES = Set.of(
            "ghp_", "gho_", "ghs_", "ghr_", "github_pat_",   // GitHub
            "glpat-",                                           // GitLab PAT
            "sk-", "sk-proj-", "sk-ant-",                      // OpenAI / Anthropic
            "sk_live_", "sk_test_",                            // Stripe / Braintree / Paystack
            "rk_live_", "rk_test_",                            // Stripe restricted
            "SG.",                                              // SendGrid
            "shpat_", "shpca_", "shpss_", "shpua_",           // Shopify
            "pat-",                                             // HubSpot
            "dapi",                                             // Databricks
            "hvs.",                                             // HashiCorp Vault
            "lin_api_",                                         // Linear
            "nfp_",                                             // Netlify
            "pk.eyJ",                                           // Mapbox
            "grsk_",                                            // Groq
            "r8_",                                              // Replicate
            "xai-",                                             // xAI / Grok
            "bkua_",                                            // Buildkite
            "tskey-",                                           // Tailscale
            "fo1_",                                             // Fly.io
            "tfc_",                                             // Terraform Cloud
            "PMAK-",                                            // Postman
            "pul_",                                             // Pulumi
            "pypi-",                                            // PyPI
            "ops_",                                             // 1Password service account
            "aio_",                                             // Adafruit IO
            "dp.pt.",                                           // DeepSeek
            "sntrys_",                                          // Sentry
            "figd_",                                            // Figma
            "hrn_pat_"                                          // Harness
    );

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
            "consumer", "encrypt", "encryption", "decrypt", "decryption",
            "cipher", "aes", "hmac", "ssh", "admin", "db", "database", "root", "slack",
            "user",  // Azure AD User Object ID (userId, user_id, User ID) is sensitive in config blobs
            "vapid", "push"  // Web Push VAPID keys (vapidKey, pushPublicKey, applicationVapidKey)
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
            // In raw custom-rules-only mode, skip all built-in request-side scanners (header
            // KV, anchored tokens, entropy, DB strings, JSON walk on request bodies). Custom
            // rules are applied to the response body via scanText/scanTextCore which already
            // honors the raw-mode branch. Request-body custom-rule scanning is intentionally
            // omitted here because the dispatcher in scanTextCore is keyed on the response.
            if (!settings.isCustomRulesOnly() && settings.isScanRequestsEnabled()) {
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

                    // Opaque Bearer suppression: Authorization: Bearer with no known vendor prefix
                    // is a dynamic session/OAuth token — suppress to avoid per-request noise.
                    if (hdrName.equalsIgnoreCase("authorization") && isBearerScheme(hdrVal) && !hasBearerVendorPrefix(val)) continue;

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
        return scanTextCore(text, contentType, url, null);
    }

    /**
     * Debug variant of {@link #scanText} — same scan logic but also populates
     * {@code dbg} with every candidate that was suppressed (hex guard, entropy gate,
     * no-context-keyword, blocklist, etc.). Used by BulkScanPanel to build the
     * "Export Debug CSV" report.
     *
     * @param dbg non-null list to receive suppression entries; caller owns it
     */
    public List<SecretFinding> scanTextDebug(String text, String contentType, String url,
                                              List<DebugEntry> dbg) {
        return scanTextCore(text, contentType, url, dbg);
    }

    /** Core scan implementation — {@code dbg} may be null (no suppression logging). */
    private List<SecretFinding> scanTextCore(String text, String contentType, String url,
                                              List<DebugEntry> dbg) {
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
                    all.addAll(scanTextCore(block, "application/javascript", url + "#inline-js", dbg));
                }
            }
            // 2. <script type="application/json"> blocks — Next.js __NEXT_DATA__ etc.
            Matcher jm = Patterns.JSON_SCRIPT_TAG.matcher(text);
            while (jm.find()) {
                String block = jm.group(1);
                if (block != null && !block.isBlank() && block.length() > 20) {
                    all.addAll(scanTextCore(block.trim(), "application/json", url + "#json-script", dbg));
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
                // Reject non-secret values: all-alpha company/org names (e.g. "BackblazeInc"),
                // version strings, and other identifiers that carry no credential risk.
                if (!isProbableSecretValue(credential)) continue;
                // Opaque Bearer suppression (same logic as scanRequestResponse Pass 1)
                if (name.equalsIgnoreCase("authorization") && isBearerScheme(val) && !hasBearerVendorPrefix(credential)) continue;
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

        // Raw custom-rules-only mode: skip every built-in scanner and run only the user's
        // regex rules, with FP gates bypassed inside scanCustomRules. Allowlist/blocklist/CDN
        // checks still apply (they're enforced inside the custom-rules loop and at call sites).
        // Burp's audit integration (SecretScanCheck) is NOT affected — it runs the full scan.
        if (settings.isCustomRulesOnly()) {
            all.addAll(scanCustomRules(text, url, dbg));
            return filterAndDeduplicate(all, dbg);
        }

        // --- Phase 1: anchored vendor tokens (all tiers) ---
        all.addAll(scanAnchoredTokens(text, url, dbg));

        // --- Phase 2: URL credentials (all tiers) ---
        all.addAll(scanUrlCredentials(text, url));

        // Custom user-defined rules — run on all tiers, purely additive
        all.addAll(scanCustomRules(text, url, dbg));
        // Commented-out GUIDs adjacent to credential keys — run on all tiers
        all.addAll(scanCommentedGuids(text, url));
        // CryptoJS/sjcl AES hardcoded passphrases — run on all tiers
        all.addAll(scanCryptoJsPassphrases(text, url));

        if (tier == ScanSettings.ScanTier.FAST) {
            return filterAndDeduplicate(all, dbg);
        }

        // --- Phase 3: DB connection strings + context-gated rules (LIGHT + FULL) ---
        all.addAll(scanDbConnectionStrings(text, url));
        all.addAll(scanContextGatedRules(text, url));

        if (tier == ScanSettings.ScanTier.LIGHT) {
            return filterAndDeduplicate(all, dbg);
        }

        // --- FULL tier only ---
        // No JS body size cap — modern webpack bundles are routinely 2–5 MB and a 1.5 MB cap
        // was silently dropping config variables in the middle section.  Pattern matching on
        // multi-MB strings completes in a few seconds; missing a secret is worse than a slower scan.
        // For HTML, scanGenericKV was already applied to each inline <script> block above.
        // Running it again on the full HTML text would double-report the same findings at
        // different (absolute vs block-relative) line numbers once line-number dedup is in use.
        if (!isHtml) {
            all.addAll(scanGenericKV(text, url, dbg));
            all.addAll(scanComputedPropObjects(text, url));
        }
        all.addAll(scanSsrStateBlobs(text, url));
        all.addAll(scanBase64Blobs(text, url));
        all.addAll(scanHighEntropyValues(text, url, dbg));

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


        return filterAndDeduplicate(all, dbg);
    }

    // =========================================================================
    // Scan methods
    // =========================================================================

    /** Iterate every AnchoredRule; emit a finding per unique (ruleId, value) match. */
    /** Proxy/request scan path — no debug accumulator. */
    private List<SecretFinding> scanAnchoredTokens(String text, String url) {
        return scanAnchoredTokens(text, url, null);
    }

    private List<SecretFinding> scanAnchoredTokens(String text, String url, List<DebugEntry> dbg) {
        List<SecretFinding> findings = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        for (Patterns.AnchoredRule rule : Patterns.ANCHORED_RULES) {
            Matcher m = rule.pattern().matcher(text);
            while (m.find()) {
                String val = m.group(0).trim();
                // Skip obvious placeholders
                if (isPlaceholder(val)) {
                    dbgAdd(dbg, new DebugEntry(rule.ruleId(), rule.keyName(), dbgVal(val), "placeholder", url));
                    continue;
                }
                // DISCORD_TOKEN_001 FP guard: real Discord bot tokens are base64url-encoded
                // in all three segments — each segment must contain at least one digit.
                // JS dotted property chains (e.g. "actions_1.default.fetchSuccess") match
                // the structural 28.7.27 pattern but their middle segment ("default",
                // "prototype", etc.) is a plain English word with no digits.
                if ("DISCORD_TOKEN_001".equals(rule.ruleId())) {
                    int d1 = val.indexOf('.');
                    int d2 = d1 >= 0 ? val.indexOf('.', d1 + 1) : -1;
                    if (d1 > 0 && d2 > d1) {
                        String seg2 = val.substring(d1 + 1, d2);
                        String seg3 = val.substring(d2 + 1);
                        if (seg2.chars().noneMatch(Character::isDigit)
                                || seg3.chars().noneMatch(Character::isDigit)) {
                            dbgAdd(dbg, new DebugEntry(rule.ruleId(), rule.keyName(), dbgVal(val), "discord_non_numeric_segment", url));
                            continue;
                        }
                    }
                }
                // ALGOLIA_KEY_001 FP guard: the pattern uses (?i) so its 10-char [A-Z0-9] capture
                // group also matches lowercase.  Real Algolia App IDs are UPPERCASE alphanumeric
                // (e.g. JRFR1I7G8S).  PascalCase / camelCase JS variable names (e.g. TbBrandAlg,
                // from react-icons' TbBrandAlgolia component) are false positives.
                if ("ALGOLIA_KEY_001".equals(rule.ruleId())) {
                    if (!val.equals(val.toUpperCase())) {
                        dbgAdd(dbg, new DebugEntry(rule.ruleId(), rule.keyName(), dbgVal(val), "algolia_lowercase_guard", url));
                        continue;
                    }
                }
                // AZURE_CONN_001 FP guard: Azurite (Azure Storage Emulator) ships with a
                // well-known, universally-identical dev credential published in Microsoft docs.
                // AccountName=devstoreaccount1 is the canonical indicator.  Never a real secret.
                if ("AZURE_CONN_001".equals(rule.ruleId())) {
                    if (val.toLowerCase().contains("devstoreaccount1")) {
                        dbgAdd(dbg, new DebugEntry(rule.ruleId(), rule.keyName(), dbgVal(val), "azure_emulator_credential", url));
                        continue;
                    }
                }
                // GUID_TOKEN_001 FP guard: Adobe Target "propertyToken" and similar
                // platform-config UUIDs are public deployment identifiers — not secrets.
                // Signal: key group contains "property" before "token".
                if ("GUID_TOKEN_001".equals(rule.ruleId())) {
                    String keyGrp = m.groupCount() >= 1 ? m.group(1) : "";
                    if (keyGrp != null && keyGrp.toLowerCase().contains("property")) {
                        dbgAdd(dbg, new DebugEntry(rule.ruleId(), rule.keyName(), dbgVal(val), "guid_property_token", url));
                        continue;
                    }
                }
                // JWT_TOKEN_001 FP guard: Netlify RUM / Core Web Vitals tokens are server-rendered
                // per-request analytics tokens embedded as data-netlify-cwv-token attributes.
                // They are short-lived, scope-limited to telemetry, and not extractable secrets.
                // Signal: "netlify" appears within 60 chars before the match.
                if ("JWT_TOKEN_001".equals(rule.ruleId())) {
                    String pre60 = text.substring(Math.max(0, m.start() - 60), m.start());
                    if (pre60.toLowerCase().contains("netlify")) {
                        dbgAdd(dbg, new DebugEntry(rule.ruleId(), rule.keyName(), dbgVal(val), "jwt_netlify_analytics_token", url));
                        continue;
                    }
                }
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

    /** Detect https://user:pass@host and https://host?password=X URL credential patterns. */
    private List<SecretFinding> scanUrlCredentials(String text, String url) {
        List<SecretFinding> findings = new ArrayList<>();

        // Basic-auth style: https://user:pass@host
        Matcher m = Patterns.URL_WITH_CREDS.matcher(text);
        while (m.find()) {
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

        // Query-parameter style: https://host/path?username=X&password=Y
        Matcher qm = Patterns.URL_QUERY_CREDS.matcher(text);
        while (qm.find()) {
            String pass = qm.group(1);
            if (pass == null || pass.length() < 4) continue;
            if (isPlaceholder(pass)) continue;
            String ctx = extractContext(text, qm.start(), qm.end());
            findings.add(SecretFinding.of(
                    "URL_QUERY_CREDS", "URL with Password in Query Parameters",
                    "password", pass, "HIGH", "CERTAIN",
                    countLines(text, qm.start()), ctx, url));
        }

        // Relative-URL / HTML-attribute query credentials — no https:// prefix required.
        // Catches <frame src="path?password=X">, &amp;-separated params in HTML attributes, etc.
        Matcher bqm = Patterns.BARE_QUERY_CREDS.matcher(text);
        while (bqm.find()) {
            String pass = bqm.group(1);
            if (isPlaceholder(pass)) continue;
            String ctx = extractContext(text, bqm.start(), bqm.end());
            findings.add(SecretFinding.of(
                    "URL_QUERY_CREDS", "URL with Password in Query Parameters",
                    "password", pass, "HIGH", "CERTAIN",
                    countLines(text, bqm.start()), ctx, url));
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
            // Reject JS arithmetic expressions: obfuscated JS uses short variable names
            // (1–3 chars) joined by *, +, - operators, e.g. "N4*j4+q2+F3+TT".
            // The DOTNET_CONN_STR pattern fires because the obfuscated variable "pWD"
            // matches "pwd" case-insensitively, and the preceding "var=val;" assignments
            // satisfy the lead-in groups.  A real password never looks like arithmetic.
            if (pass.matches("[A-Za-z][A-Za-z0-9]{0,3}([*+\\-][A-Za-z][A-Za-z0-9]{0,3})+")) continue;
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
    /** Proxy/request scan path — no debug accumulator. */
    private List<SecretFinding> scanGenericKV(String text, String url) {
        return scanGenericKV(text, url, null);
    }

    private List<SecretFinding> scanGenericKV(String text, String url, List<DebugEntry> dbg) {
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
            // Hard-reject Angular/webpack bundle chunk manifest keys.
            // e.g. src_app_modules_news-resource-center_newsresourcecenter_module_ts → build hash
            if (key.toLowerCase().matches(".+[_-](module|component|service|directive|pipe|guard|resolver|interceptor|factory|effect|reducer)[_-](ts|js)")) continue;
            boolean forceInclude  = settings.isKeyAllowlisted(key);
            boolean apiOverride   = isApiOverrideKey(key);
            if (!forceInclude && !isSemanticSecretKey(key) && !apiOverride) continue;

            String trimmedVal = val.trim();
            // Reject JS string-concatenation fragments: a value that starts or ends with '+' is
            // an adjacent operand in a JS string-build expression, not a hardcoded credential.
            // e.g. "+t.userUniqId+" from "...&userUniqId="+t.userUniqId+"..."
            if (trimmedVal.startsWith("+") || trimmedVal.endsWith("+")) {
                dbgAdd(dbg, new DebugEntry("GENERIC_KV", key, dbgVal(trimmedVal), "js_concat_fragment", url));
                continue;
            }
            // Reject CSS event-namespace / Bootstrap selector constants (e.g. '.data-api', '.bs.modal')
            if (trimmedVal.startsWith(".") && trimmedVal.matches("\\.[A-Za-z][A-Za-z0-9._-]*")) {
                dbgAdd(dbg, new DebugEntry("GENERIC_KV", key, dbgVal(trimmedVal), "css_selector_value", url));
                continue;
            }
            // Reject CSS attribute selector values: e.g. password:"[type=password]", file:"[type=file]".
            // These are jQuery / React form-config input-type selector constants, not credentials.
            if (trimmedVal.startsWith("[") && trimmedVal.endsWith("]")) {
                dbgAdd(dbg, new DebugEntry("GENERIC_KV", key, dbgVal(trimmedVal), "css_attribute_selector", url));
                continue;
            }
            // Reject placeholder / fake-credential values early (e.g. "abcd-1234-5678-lala-xyz").
            // forceInclude (allowlist) still bypasses this gate.
            if (!forceInclude && isPlaceholder(trimmedVal)) {
                dbgAdd(dbg, new DebugEntry("GENERIC_KV", key, dbgVal(trimmedVal), "placeholder", url));
                continue;
            }
            boolean isGuid = isAzureGuid(trimmedVal);
            if (isGuid) {
                // UUID/GUID values: only report when the key explicitly identifies an Azure credential
                if (!isAzureCredentialKey(key)) {
                    dbgAdd(dbg, new DebugEntry("GENERIC_KV", key, dbgVal(trimmedVal), "guid_non_credential_key", url));
                    continue;
                }
            } else if (apiOverride && trimmedVal.length() >= 8 && trimmedVal.length() < 12) {
                // Relaxed minimum length for high-confidence API key names (e.g. inviteApiKey:"px34udyy99")
                if (trimmedVal.matches("[A-Za-z_]+") || trimmedVal.matches("[A-Za-z_][A-Za-z0-9_]*")) {
                    dbgAdd(dbg, new DebugEntry("GENERIC_KV", key, dbgVal(trimmedVal), "not_probable_secret_value", url));
                    continue;  // still reject pure-alpha identifiers
                }
                // Reject values with internal whitespace — UI phrases/labels like "Secret key:", not credentials
                if (trimmedVal.chars().anyMatch(Character::isWhitespace)) {
                    dbgAdd(dbg, new DebugEntry("GENERIC_KV", key, dbgVal(trimmedVal), "not_probable_secret_value", url));
                    continue;
                }
                String sym = "~`!@#$%^&*+=|?.:,;";
                boolean hasDigitOrSym = trimmedVal.chars().anyMatch(Character::isDigit)
                        || trimmedVal.chars().anyMatch(c -> sym.indexOf(c) >= 0);
                if (!hasDigitOrSym) {
                    dbgAdd(dbg, new DebugEntry("GENERIC_KV", key, dbgVal(trimmedVal), "not_probable_secret_value", url));
                    continue;
                }
            } else if (!forceInclude && !isProbableSecretValue(val)) {
                dbgAdd(dbg, new DebugEntry("GENERIC_KV", key, dbgVal(trimmedVal),
                        "not_probable_secret_value", url));
                continue;
            }
            // Hard-reject all-alpha values even for allowlisted keys — these are schema field
            // names / identifiers (e.g. "apiKey":"FirstName"), never real credential values.
            if (trimmedVal.matches("[A-Za-z_]+")) {
                dbgAdd(dbg, new DebugEntry("GENERIC_KV", key, dbgVal(trimmedVal), "all_alpha_identifier", url));
                continue;
            }
            // Reject pure-numeric values — these are database primary keys / object IDs
            // (e.g. Mendix sessionObjectId: "25614223090061799"), never credential values.
            if (trimmedVal.matches("\\d+")) {
                dbgAdd(dbg, new DebugEntry("GENERIC_KV", key, dbgVal(trimmedVal), "all_digits", url));
                continue;
            }
            // Reject OID / dotted-decimal numeric values — e.g. X.509 field OIDs such as
            // userId:"0.9.2342.19200300.100.1.1". These pass the digit gate but are not secrets.
            if (trimmedVal.matches("[0-9]+(\\.[0-9]+){3,}")) {
                dbgAdd(dbg, new DebugEntry("GENERIC_KV", key, dbgVal(trimmedVal), "oid_dotted_decimal", url));
                continue;
            }
            // Reject values containing '(' — JS expression fragments like ".concat(o)" or
            // function calls are never credential values.
            if (trimmedVal.contains("(")) {
                dbgAdd(dbg, new DebugEntry("GENERIC_KV", key, dbgVal(trimmedVal), "js_expression_fragment", url));
                continue;
            }
            // Reject relative URL path constants: values that look like "word/word/word" are
            // API endpoint path maps (e.g. "bv-api/v1/res-api/"), not secrets.
            if (trimmedVal.contains("/") && trimmedVal.matches("[a-z][a-z0-9.]*([/_][a-z][a-z0-9._-]*/?)+(/?)+")) {
                dbgAdd(dbg, new DebugEntry("GENERIC_KV", key, dbgVal(trimmedVal), "url_path_constant", url));
                continue;
            }
            // Reject Salesforce Org IDs: canonical format "00D" + 12–18 alphanumeric chars.
            // These are org-level CRM identifiers shown in every Salesforce admin UI — not secrets.
            if (trimmedVal.matches("00D[A-Za-z0-9]{12,18}")) {
                dbgAdd(dbg, new DebugEntry("GENERIC_KV", key, dbgVal(trimmedVal), "salesforce_org_id", url));
                continue;
            }
            // Suppress when key name contains "search": client-side search API keys
            // (Algolia, Elasticsearch, etc.) are intentionally public — they grant read-only
            // search access and are designed to be embedded in browser code.
            {
                String kl = key.toLowerCase().replaceAll("[_\\-]", "");
                if (kl.contains("search") && trimmedVal.matches("[A-Za-z0-9]{20,40}")) {
                    dbgAdd(dbg, new DebugEntry("GENERIC_KV", key, dbgVal(trimmedVal), "public_search_api_key", url));
                    continue;
                }
            }
            // Reject Coveo-style placeholder access tokens: Coveo's documentation and
            // sample apps use access tokens with an 'xx' prefix (e.g. xxb8b0cfe8-0c9b-...)
            // to indicate example/placeholder values.  Real Coveo tokens never start with 'xx'.
            if (trimmedVal.startsWith("xx") && trimmedVal.length() > 10) {
                dbgAdd(dbg, new DebugEntry("GENERIC_KV", key, dbgVal(trimmedVal), "placeholder", url));
                continue;
            }
            // Reject pipe-delimited template expressions: connector config fields like
            // userIdExpression use "provider|{object.field}|{object.field}" syntax to
            // define identity mapping templates — not credential values.
            if (trimmedVal.contains("{") && trimmedVal.contains("}")) {
                dbgAdd(dbg, new DebugEntry("GENERIC_KV", key, dbgVal(trimmedVal), "template_expression", url));
                continue;
            }
            // Reject CSS Modules / SVG class name values: Next.js / webpack CSS Modules emit
            // objects like {"resource-container":"ComponentName_element__Hash"}.  The
            // double-underscore suffix (3–8 alphanumeric chars) is the canonical CSS Modules /
            // Adobe Illustrator SVG export signature — not a credential value.
            if (trimmedVal.matches(".*__[A-Za-z0-9]{3,8}$")) {
                dbgAdd(dbg, new DebugEntry("GENERIC_KV", key, dbgVal(trimmedVal), "css_modules_class", url));
                continue;
            }
            // Reject Open Graph / meta-tag property name identifiers used as values:
            // e.g. fbAppId:"fb:app_id", ogAudioSecureUrl:"og:audio:secure_url",
            //      bookReleaseDate:"book:release_date".  These are colon-namespaced string
            // constants (property name strings in meta-tag config objects) — not secrets.
            if (trimmedVal.matches("[a-z][a-z0-9_]*:[a-z][a-z0-9_:]*")) {
                dbgAdd(dbg, new DebugEntry("GENERIC_KV", key, dbgVal(trimmedVal), "og_property_name", url));
                continue;
            }
            // Reject lowercase hex in the 16–40 char range: Amplitude/Mixpanel/Trustpilot/Pusher
            // public analytics/widget/channel IDs and webpack content hashes are always pure
            // lowercase hex at these lengths.  Real API secrets always contain uppercase letters.
            // Crypto context exception: AES-128 keys (32 chars) and AES-GCM IVs (24 chars) are
            // format-identical to analytics IDs.  When crypto operation keywords (encrypt, decrypt,
            // AES, HMAC, CryptoJS, cipher) appear within 200 chars, do not suppress — this is
            // likely a hardcoded crypto key that should be reported.
            if (trimmedVal.matches("[0-9a-f]{16,40}")) {
                // Bypass the crypto-proximity check only for key names that are unambiguously
                // crypto material.  Two bypass paths:
                //
                // Path A — crypto-prefixed *Hex keys: ivHex, kyHex, encryptHex, aesKeyHex, etc.
                //   The *Hex suffix signals hex-encoded bytes; the prefix segment confirms it is
                //   crypto material (not a color, theme value, or protocol constant).
                //   Rejected: colorHex, borderHex, hashHex, paddingHex, offsetHex.
                //
                // Path B — semantic secret key names that happen to hold hex values
                //   (encryptionKey, aesKey, cipherKey, etc. already handled via isSemanticSecretKey).
                //   These have a recognized prefix+target pair and do not need proximity checking.
                String kl = key.toLowerCase().replaceAll("[_\\-]", "");
                boolean isCryptoHexKey = kl.endsWith("hex") && (
                        kl.contains("encrypt") || kl.contains("decrypt") || kl.contains("cipher") ||
                        kl.contains("aes")     || kl.contains("hmac")    || kl.contains("iv")     ||
                        kl.startsWith("key")   || kl.contains("secret")  || kl.contains("token"));
                if (!isCryptoHexKey && !isSemanticSecretKey(key)) {
                    String hexCtx = text.substring(Math.max(0, m.start() - 200),
                            Math.min(text.length(), m.end() + 200));
                    if (!Patterns.CRYPTO_OP_PATTERN.matcher(hexCtx).find()) {
                        dbgAdd(dbg, new DebugEntry("GENERIC_KV", key, dbgVal(trimmedVal),
                                "hex_no_crypto_context", url));
                        continue;
                    }
                }
            }
            // Reject reCAPTCHA v3/v2 site keys: the '6L' prefix + base64url body is the
            // canonical Google reCAPTCHA public site key format — intentionally embedded in
            // every page for the challenge widget.
            if (trimmedVal.startsWith("6L") && trimmedVal.matches("6L[A-Za-z0-9_-]{36,42}")) {
                dbgAdd(dbg, new DebugEntry("GENERIC_KV", key, dbgVal(trimmedVal), "recaptcha_site_key", url));
                continue;
            }
            // Reject Boomerang/Akamai mPulse RUM API keys: intentionally embedded in every HTML
            // page by the BOOMR snippet, public by design (same category as Google Analytics IDs).
            {
                String kl = key.toLowerCase().replaceAll("[_\\-]", "");
                if (kl.contains("boomr")) {
                    dbgAdd(dbg, new DebugEntry("GENERIC_KV", key, dbgVal(trimmedVal), "public_rum_api_key", url));
                    continue;
                }
            }
            // Reject client-side SDK identifier UUIDs: Braze, Sendbird, and similar client-facing
            // SDKs use UUID App IDs embedded in every browser session — not extractable secrets.
            // Signal: value is a UUID AND the key name contains "sdk".
            if (isAzureGuid(trimmedVal)
                    && key.toLowerCase().replaceAll("[_\\-]", "").contains("sdk")) {
                dbgAdd(dbg, new DebugEntry("GENERIC_KV", key, dbgVal(trimmedVal), "sdk_uuid", url));
                continue;
            }
            // Reject Unicode-escaped slugs/identifiers: JS source sometimes stores service
            // name slugs with Unicode-escaped hyphens, e.g. 'helpx[backslash]u002Dweb...'
            // (U+002D = '-').  isProbableSecretValue fires because the literal digits "002D"
            // appear in the raw string.  Decode backslash-uXXXX sequences and re-test — if
            // the decoded form has no digits or strong symbols it is a plain identifier.
            if (trimmedVal.contains("\\u")) {
                try {
                    java.util.regex.Matcher uem =
                            java.util.regex.Pattern.compile("\\\\u([0-9A-Fa-f]{4})").matcher(trimmedVal);
                    StringBuffer decoded = new StringBuffer();
                    while (uem.find())
                        uem.appendReplacement(decoded,
                                String.valueOf((char) Integer.parseInt(uem.group(1), 16)));
                    uem.appendTail(decoded);
                    if (!isProbableSecretValue(decoded.toString())) {
                        dbgAdd(dbg, new DebugEntry("GENERIC_KV", key, dbgVal(trimmedVal), "unicode_slug", url));
                        continue;
                    }
                } catch (Exception ignored) {}
            }
            // JWT suppression: accessToken/idToken keys in JS source often hold mock JWTs
            // in test objects (e.g. Microsoft login page test fixtures). JWTs are short-lived
            // session tokens, not hardcoded secrets — suppress to avoid response-body noise.
            if (isJwt(trimmedVal)) {
                dbgAdd(dbg, new DebugEntry("GENERIC_KV", key, dbgVal(trimmedVal), "jwt_session_token", url));
                continue;
            }
            // Blockchain hash false-positive guard
            if (Patterns.BLOCKCHAIN_HASH_KEY.matcher(key).find()) {
                dbgAdd(dbg, new DebugEntry("GENERIC_KV", key, dbgVal(trimmedVal), "blockchain_hash_key", url));
                continue;
            }
            // Include both line number AND byte offset in the dedup key so that minified bundles —
            // where every match shares the same lineNumber because the file has no line breaks —
            // still produce one finding per occurrence rather than collapsing all matches to one row.
            int lineNum  = countLines(text, m.start());
            int offset   = m.start();
            String dedupe = key.toLowerCase() + ":" + val + ":" + lineNum + ":" + offset;
            if (!seen.add(dedupe)) continue;
            String sev  = scoreSeverity(key, val);
            String conf = hasHighEntropy(val) ? "CERTAIN" : "FIRM";
            findings.add(SecretFinding.of(
                    "GENERIC_KV", "Secret in Key-Value Pair",
                    key, val, sev, conf,
                    lineNum,
                    extractContext(text, m.start(), m.end()), url, offset));
        }
        return findings;
    }

    /**
     * Handles JS object literals with computed property keys, e.g.:
     *   resource:{[e.UJ]:"d0045bb5-9c1d-4f38-b67d-988c65a168d0"}
     *
     * GENERIC_KV cannot match these because [expr] keys are not valid unquoted
     * identifiers.  This pass uses the *parent* key (e.g. "resource") for
     * semantic classification and the inner quoted value for the credential check.
     *
     * Only applied on non-HTML FULL-tier scans (same gate as scanGenericKV).
     */
    private List<SecretFinding> scanComputedPropObjects(String text, String url) {
        List<SecretFinding> findings = new ArrayList<>();
        // Match: parentKey : { [anyExpr] : "value" }
        // Tolerates optional whitespace, single or double quotes around the value.
        java.util.regex.Pattern pat = java.util.regex.Pattern.compile(
                "(?i)([A-Za-z0-9_\\-]+)\\s*:\\s*\\{\\s*\\[[^\\]]{1,60}\\]\\s*:\\s*[\"']([^\"'\\r\\n]{6,300})[\"']");
        java.util.regex.Matcher m = pat.matcher(text);
        Set<String> seen = new HashSet<>();
        while (m.find()) {
            String parentKey = m.group(1);
            String val       = m.group(2);
            if (parentKey == null || val == null) continue;
            if (isForcedNoiseKey(parentKey)) continue;
            if (Patterns.NOISE_KEYNAMES.matcher(parentKey).matches()) continue;
            boolean forceInclude = settings.isKeyAllowlisted(parentKey);
            boolean apiOverride  = isApiOverrideKey(parentKey);
            if (!forceInclude && !isSemanticSecretKey(parentKey) && !apiOverride) continue;
            String trimmedVal = val.trim();
            if (trimmedVal.startsWith("+") || trimmedVal.endsWith("+")) continue;
            if (!forceInclude && isPlaceholder(trimmedVal)) continue;
            boolean isGuid = isAzureGuid(trimmedVal);
            if (isGuid) {
                if (!isAzureCredentialKey(parentKey)) continue;
            } else if (!forceInclude && !isProbableSecretValue(val)) {
                continue;
            }
            if (trimmedVal.matches("[A-Za-z_]+")) continue;
            if (isJwt(trimmedVal)) continue;
            int    offset  = m.start();
            String dedupe  = parentKey.toLowerCase() + ":" + trimmedVal + ":" + offset;
            if (!seen.add(dedupe)) continue;
            int    lineNum = countLines(text, offset);
            String sev     = scoreSeverity(parentKey, trimmedVal);
            String conf    = isGuid ? "FIRM" : (hasHighEntropy(trimmedVal) ? "CERTAIN" : "FIRM");
            findings.add(SecretFinding.of(
                    "GENERIC_KV", "Secret in Key-Value Pair",
                    parentKey, trimmedVal, sev, conf,
                    lineNum, extractContext(text, offset, m.end()), url, offset));
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
    /** Proxy/request scan path — no debug accumulator. */
    private List<SecretFinding> scanHighEntropyValues(String text, String url) {
        return scanHighEntropyValues(text, url, null);
    }

    private List<SecretFinding> scanHighEntropyValues(String text, String url, List<DebugEntry> dbg) {
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
            // Reject CSS selector strings: jQuery/querySelectorAll selectors start with '.'
            // and consist of class-name chars.  ENTROPY_CONTEXT_KW fires when "password"
            // appears in a nearby .attr("password-protected") call, but the value is a
            // selector, not a secret.  e.g. ".wpr-search-form-input"
            if (val.startsWith(".") && val.matches("\\.[a-z][a-z0-9_-]*")) continue;
            // Reject hostname/endpoint values: dotted names ending in a known TLD or
            // subdomain pattern (e.g. "cc-api-data-stage.adobe.io") are server addresses,
            // never secret tokens.  Signal: contains a dot, no uppercase, no digits, and
            // ends with 2–6 alphabetic chars after the last dot.
            if (val.contains(".") && val.matches("[a-z0-9][a-z0-9.\\-]*\\.[a-z]{2,6}")) continue;
            // Reject Adobe IMS Organization IDs: "AAB73BC75245B44A0A490D4D@AdobeOrg".
            // These are public identifiers intentionally embedded in Adobe Launch / DTM
            // configs shipped to every browser — not extractable secrets.
            if (val.endsWith("@AdobeOrg")) continue;
            // Reject 16 and 20-char lowercase hex unconditionally: these are webpack content
            // hash lengths ([contenthash:16] / [contenthash:20]) used for JS/CSS chunk naming
            // and CSS-in-JS injection tokens (styled-components, emotion).  They are NEVER
            // valid AES key sizes (AES-128 = 32 hex, AES-256 = 64 hex) or HMAC/IV lengths,
            // so the crypto-context bypass does not apply.  The entropy scanner default
            // keyName fallback "token" caused these to surface with MEDIUM/FIRM severity.
            if (val.matches("[0-9a-f]{16}") || val.matches("[0-9a-f]{20}")) {
                dbgAdd(dbg, new DebugEntry("ENTROPY_TOKEN", "",
                        dbgVal(val), "webpack_content_hash", url));
                continue;
            }
            // Reject lowercase hex in the 24–64 char range: covers Amplitude/Algolia analytics IDs
            // (24–40 chars), SHA-1 checksums (40 chars), and SHA-256 checksums (64 chars).
            // Crypto context exception: AES keys (32 or 64 hex chars) and AES-GCM IVs (24 hex
            // chars) are format-identical to analytics IDs and file hashes at these lengths.
            // The only reliable differentiator is CONTEXT — if crypto operation keywords
            // (encrypt, decrypt, AES, HMAC, CryptoJS, cipher) appear within 200 chars of the
            // value, do not suppress.  200 chars covers minified-JS packing where a hex literal
            // and its encrypt() call site may be 100+ chars apart.
            if (val.matches("[0-9a-f]{24,40}") || val.matches("[0-9a-f]{40}")
                    || val.matches("[0-9a-f]{64}")) {
                String hexCtx = text.substring(Math.max(0, m.start() - 200),
                        Math.min(text.length(), m.end() + 200));
                if (!Patterns.CRYPTO_OP_PATTERN.matcher(hexCtx).find()) {
                    dbgAdd(dbg, new DebugEntry("ENTROPY_TOKEN", "",
                            dbgVal(val), "hex_guard", url));
                    continue;
                }
            }
            // Webpack module-registry IDs: /***/ "0f025c284bc567debf3d": /***/ (function(...)
            // These 12–24-char lowercase hex strings are content-addressed module keys used
            // internally by webpack as dictionary keys in the module registry — not secrets.
            // They are 20 chars (shorter than the 24-char hex guard above) and appear in
            // vendors/chunk bundles alongside CryptoJS, which makes them pass the crypto-
            // context check.  Guard: pure lowercase hex AND immediately followed by the
            // webpack module-registry sentinel ": /***/ (".
            // Also suppress the __webpack_require__("hash") call-site form.
            if (val.matches("[0-9a-f]{12,24}")) {
                String postMatch = text.substring(m.end(), Math.min(text.length(), m.end() + 14));
                if (postMatch.startsWith(": /***/ (")) {
                    dbgAdd(dbg, new DebugEntry("ENTROPY_TOKEN", "",
                            dbgVal(val), "webpack_guard", url));
                    continue;
                }
                // __webpack_require__("hash") or webpackJsonp["hash"]
                String preMatch = text.substring(Math.max(0, m.start() - 22), m.start());
                if (preMatch.contains("__webpack_require__(") || preMatch.endsWith("webpackJsonp[")) {
                    dbgAdd(dbg, new DebugEntry("ENTROPY_TOKEN", "",
                            dbgVal(val), "webpack_guard", url));
                    continue;
                }
            }
            if (!hasHighEntropy(val)) {
                // Log ALL entropy misses with the entropy value and threshold.
                // Near-misses (within 0.5 bits) are the most actionable, but logging all
                // gives a complete picture of what the scanner considered and rejected.
                double ent = shannonEntropy(val);
                double threshold = settings.getEntropyThreshold();
                String entropyReason = (ent >= threshold - 0.5)
                        ? "entropy_near_miss(ent=" + String.format("%.2f", ent) + ",threshold=" + String.format("%.2f", threshold) + ")"
                        : "entropy_below_threshold(ent=" + String.format("%.2f", ent) + ",threshold=" + String.format("%.2f", threshold) + ")";
                dbgAdd(dbg, new DebugEntry("ENTROPY_TOKEN", "",
                        dbgVal(val), entropyReason, url));
                continue;
            }
            // Reject values with no digits and no strong symbols (CSS class names, word identifiers).
            // Real secrets almost always contain at least one digit or strong punctuation.
            if (!isProbableSecretValue(val)) {
                dbgAdd(dbg, new DebugEntry("ENTROPY_TOKEN", "",
                        dbgVal(val), "not_probable_secret_value", url));
                continue;
            }
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
            if (!hasContextKw && !keyIsSecret) {
                dbgAdd(dbg, new DebugEntry("ENTROPY_TOKEN",
                        keyName != null ? keyName : "",
                        dbgVal(val), "no_context_keyword", url));
                continue;
            }
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
        if (key.toLowerCase().matches(".+[_-](module|component|service|directive|pipe|guard|resolver|interceptor|factory|effect|reducer)[_-](ts|js)")) return;

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
            // UUID/GUID bypass: Azure App IDs, Tenant IDs, Resource IDs are real credentials
            if (!isAzureGuid(val) || !isAzureCredentialKey(key)) return;
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

    private static boolean isHexDigit(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

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
        // File system paths and URL paths are never credential key names.
        // e.g. Angular ngsw.json hashTable keys like "/assets/img/HK_password-policy.jpg"
        // contain words such as "password" inside a filename, not as a config key.
        if (name.startsWith("/") || name.startsWith("./")) return false;
        // Serialised JSON objects used as map keys are never credential field names.
        // e.g. Mendix runtime /xas/ endpoint stores microflow metadata as
        // {"a":[...],"p":["ForgotPassword_Extention.ForgotPasswordEmail"]} → token
        // The JSON key string contains "password" / "email" but is data, not a key name.
        if (name.startsWith("{")) return false;
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
                lower.equals("secret")) return true;
        // Hex-encoded crypto material naming convention: developers commonly suffix variables
        // with 'Hex' to signal hex encoding (e.g. kyHex, ivHex, keyHex, secretHex, tokenHex).
        // This is a structural naming pattern — not a specific key name — that reliably indicates
        // the variable holds raw crypto key/IV/nonce material rather than a display value.
        // Min length > 3 avoids matching the bare word "hex" alone.
        if (lower.endsWith("hex") && lower.length() > 3) return true;
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
            // Reject DOM-context keys: first segment "dom" always refers to Document Object
            // Model element references (e.g. domRootId, domContainerId), never credential fields.
            if (parts[0].equals("dom")) return false;
            // Reject Angular/webpack module manifest keys: file-path-derived keys that map to
            // build content hashes.  e.g. src_app_modules_news-resource-center_module_ts
            // These contain "app"/"resource" segments but are NOT credential fields.
            String lastPart2 = parts[parts.length - 1];
            String secondLast = parts.length >= 2 ? parts[parts.length - 2] : "";
            if ((lastPart2.equals("ts") || lastPart2.equals("js")) &&
                    (secondLast.equals("module") || secondLast.equals("component") ||
                     secondLast.equals("service") || secondLast.equals("directive") ||
                     secondLast.equals("pipe")    || secondLast.equals("guard")     ||
                     secondLast.equals("resolver") || secondLast.equals("interceptor") ||
                     secondLast.equals("factory") || secondLast.equals("effect")    ||
                     secondLast.equals("reducer"))) {
                return false;
            }
            // Reject UI display-label and component-registry field names.
            // e.g. UserIdLabel, apiKeyHint, passwordPlaceholder, resetPasswordConfirmationWidget
            // True credential fields (userId, apiKey) are not affected since their last segment
            // is "id" / "key", not one of these UI suffixes.
            String lastPart = parts[parts.length - 1];
            if (lastPart.equals("label") || lastPart.equals("hint") || lastPart.equals("placeholder")
                    || lastPart.equals("widget") || lastPart.equals("component")
                    || lastPart.equals("module")  || lastPart.equals("service")
                    || lastPart.equals("directive") || lastPart.equals("pipe")) {
                return false;
            }
            boolean hasSecretPrefix = false;
            for (String p : parts) {
                if (SECRET_KEY_PREFIXES.contains(p)) { hasSecretPrefix = true; break; }
            }
            for (String part : parts) {
                // These require a recognized domain prefix to be meaningful.
                // startsWith("key") catches compound suffixes like ENCRYPTION_KEYGCM → "keygcm",
                // aesKeyBytes → "keybytes", etc. Length cap avoids over-matching long words.
                boolean isKeyTarget = part.equals("key")
                        || (part.startsWith("key") && part.length() <= 12);
                if ((isKeyTarget || part.equals("token") ||
                     part.equals("secret") || part.equals("subscription") ||
                     part.equals("id") || part.equals("resource") ||
                     part.equals("iv") || part.equals("nonce") || part.equals("salt")) && hasSecretPrefix) {
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

    /** Returns true if the Authorization header value uses the Bearer scheme. */
    private static boolean isBearerScheme(String authHeader) {
        return authHeader != null && authHeader.trim().regionMatches(true, 0, "bearer ", 0, 7);
    }

    /** Returns true if {@code val} starts with a known vendor token prefix. */
    private static boolean hasBearerVendorPrefix(String val) {
        if (val == null) return false;
        for (String prefix : BEARER_VENDOR_PREFIXES) {
            if (val.startsWith(prefix)) return true;
        }
        return false;
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
     *   2. Deduplicates by (normalised URL + value) so the same credential at
     *      different endpoints is each reported once, but repeated calls to the
     *      same endpoint with the same key only produce one finding.
     * Response findings are NOT passed through here.
     */
    private List<SecretFinding> filterRequestFindings(List<SecretFinding> findings) {
        List<SecretFinding> result = new ArrayList<>();
        for (SecretFinding f : findings) {
            if (isJwt(f.matchedValue())) continue;
            // Dedup by (host + value): the same credential on every request to the same
            // host is reported once. A different host with the same value is a distinct
            // finding and must not be suppressed.
            String rawUrl = f.sourceUrl() != null ? f.sourceUrl() : "";
            String host;
            try {
                String h = new java.net.URI(rawUrl).getHost();
                host = h != null ? h : rawUrl;
            } catch (Exception ignored) {
                host = rawUrl;
            }
            if (!seenRequestValues.add(host + '\u0000' + f.matchedValue())) continue;
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
               k.contains("decryptionkey") || k.contains("decryptkey") ||
               // Azure: App IDs, Tenant IDs, Client IDs, Resource GUIDs, address keys
               k.contains("appid") || k.contains("tenantid") || k.contains("clientid") ||
               k.contains("resourceid") || k.contains("resource") ||
               k.contains("addresskey") ||
               // Azure App Insights telemetry key — public-facing by design but worth noting as INFORMATION
               k.contains("instrumentationkey") || k.contains("insightsikey");
    }

    /**
     * Returns true if the value is an Azure/RFC-4122 GUID.
     * These are used as App IDs, Tenant IDs, Client IDs, and Resource IDs in Azure
     * service principal configs and are genuine credential-bearing identifiers.
     */
    private static boolean isAzureGuid(String val) {
        return val != null && val.matches(
                "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    }

    /**
     * Returns true if the key name indicates it holds an Azure credential identifier —
     * an App ID, Tenant ID, Client ID, Resource GUID, or similar.
     * Used to allow UUID values through the isProbableSecretValue gate.
     */
    private static boolean isAzureCredentialKey(String key) {
        if (key == null) return false;
        if (isApiOverrideKey(key)) return true;   // e.g. claimapiKey, inviteApiKey with UUID value
        String k = key.toLowerCase().replaceAll("[_\\-]", "");
        return k.contains("appid")     || k.contains("appguid")    ||
               k.contains("tenantid")  || k.contains("tenantguid") ||
               k.contains("clientid")  || k.contains("clientguid") ||
               k.contains("resourceid") || k.contains("resourceguid") ||
               k.contains("cinfo");   // "client info" shorthand (e.g. appConfig.cInfo = <azure app guid>)
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
        // (b) short alphanumeric identifiers — but exempt all-hex strings (APIM keys, MD5 hashes,
        //     subscription keys) which are always credential values, never schema field names.
        if (!v.matches("[a-fA-F0-9]+") && v.matches("[A-Za-z_][A-Za-z0-9_]*") && v.length() <= 32) {
            // Exception: random crypto keys (AES-256, HMAC, etc.) stored as 32-char alphanumeric
            // strings have frequent case alternation throughout the string, unlike camelCase/PascalCase
            // identifiers that only change case at word boundaries.  If ≥30% of adjacent letter pairs
            // are case-mismatched, the value is treated as random material, not an identifier name.
            if (v.length() >= 20) {
                int letterPairs = 0, caseChanges = 0;
                for (int ci = 1; ci < v.length(); ci++) {
                    char a = v.charAt(ci - 1), b = v.charAt(ci);
                    if (Character.isLetter(a) && Character.isLetter(b)) {
                        letterPairs++;
                        if (Character.isUpperCase(a) != Character.isUpperCase(b)) caseChanges++;
                    }
                }
                if (letterPairs >= 10 && caseChanges * 10 >= letterPairs * 3) return true;
            }
            return false;
        }
        // Reject SCREAMING_SNAKE_CASE enum/constant values
        // e.g., PENDING_UNABLE_POSTPONE_PAYMENT_12_DAYS_CHANGE_KEY, INTERACTION_STATUS_KEY
        if (v.matches("[A-Z][A-Z0-9_]+") && v.length() <= 80) return false;
        // Reject dotted/colon namespace identifier patterns (library constants, URNs, event names)
        // e.g., adal.idtoken, msal:acquireTokenStart, interaction.status, oauth2:scope:read
        if (v.matches("[a-zA-Z][a-zA-Z0-9]*([:._][a-zA-Z][a-zA-Z0-9]*)+")) return false;
        // Extend the dotted-namespace rejection to JS identifiers starting with _ or $
        // (Angular / Vue framework runtime references, e.g. "__$$environment.apis.agentKeyApi",
        //  "$scope.user.token", "_prototype.toString").  These are runtime-template-substituted
        //  values, never hardcoded credentials.  The existing check above only covers [a-zA-Z] start.
        if (v.matches("[_$]+[a-zA-Z][_$a-zA-Z0-9]*(\\.[a-zA-Z][_$a-zA-Z0-9]*)+")) return false;
        // Firebase Web App ID: "1:<project-number>:web:<hex>" — always public client config
        // embedded in every Firebase-backed web app's JS initialization object.
        // Key example: appId:"1:768471912264:web:ea4c302387f38e861b2d7d"
        if (v.matches("\\d+:\\d+:[a-zA-Z]+:[a-fA-F0-9]+")) return false;
        // Reject Azure AD B2C policy/user-flow name format: B2C_1_Name or B2C_1A_Name
        // These are framework policy identifiers, never credential values.
        if (v.matches("(?i)B2C_1[A-Z0-9]?_[A-Za-z0-9_]+")) return false;
        // Reject JavaScript Unicode escape sequences — e.g. Thai/CJK i18n strings encoded as \\uXXXX.
        // These are localization labels, not secrets. The hex digits in the escape sequences
        // fool the digit check below into treating them as credentials.
        if (v.matches("(\\\\u[0-9A-Fa-f]{4})+")) return false;
        // HTML-entity-encoded strings are UI labels, not credentials.
        // e.g. "Contrase&#241;a" is Spanish for "Password" — a placeholder label string.
        if (v.contains("&#")) return false;
        // Reject UI label strings ending in ':' — NLS/i18n bundle entries like "Password:",
        // "Credentials:", "Database Credentials:" are form labels, not credential values.
        if (v.endsWith(":")) {
            String label = v.substring(0, v.length() - 1).trim();
            if (label.matches("[A-Za-z][A-Za-z \\-]*")) return false;
        }
        // JS string-concatenation fragments are never credentials.
        // e.g. ").concat(googleClientID, " is a JS template-build expression, not a token value.
        if (v.contains(".concat(")) return false;
        // '+' at start/end means the captured value is a JS '+' concatenation operand, not a token.
        // e.g. "+Or.N.adb2cSettings.clientId+" from client_id="+...+"
        if (v.startsWith("+") || v.endsWith("+")) return false;
        // Reject JS/code fragment values (minified JS operator patterns)
        // e.g., "+i):r&&f.push(", "this.apiKey),this.channel&&(e+="
        if (v.contains("&&") || v.contains("||") || v.contains("=>") || v.contains("?.")) return false;
        if (v.contains(".push(") || v.contains(".call(") || v.contains(".apply(")) return false;
        // Reject JS URL-building expression fragments (e.g. "+(g?encodeURIComponent(g):")
        if (v.startsWith("+(") || v.contains("encodeURIComponent") || v.contains("decodeURIComponent")) return false;
        // Reject React/DOM code fragments embedded in minified JS key-value matches
        if (v.contains(".render(") || v.contains("document.getElementById") ||
                v.contains("document.querySelector")) return false;
        // JS call-chain and object-reference patterns — never present in real credential values
        // e.g., "+S),ir.e.createUnexpectedCredentialTypeError()}this.setItem("
        if (v.contains("this.") || v.contains("),") || v.contains(")}") || v.contains("){")) return false;
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
        // Extend %...% to cover template syntaxes that use colons/mixed-case
        // e.g. Adobe DTM: %dl:marketplace:User_id%, %dl:marketplace:event-name%
        if (v.matches(".*([xX]{6,}|placeholder|example|your[_\\-]?token|" +
                      "<[^>]+>|\\$\\{[^}]+\\}|%[^%\\s]{1,80}%|dummy|test_?key|" +
                      "changeme|replace_?me|insert_?here).*")) return true;
        // Curly-brace URL/path template placeholders: {userID}, {email}, {param}
        // e.g. "SearchUser?email={userID}", "/api/users/{userId}/profile"
        // These are REST URL templates — never real credential values.
        if (val.matches(".*\\{[a-zA-Z][a-zA-Z0-9_]*\\}.*")) return true;
        // Monotone string: same character repeated 20+ times (e.g. Twitter public bearer AAAA...)
        if (val.length() >= 20 && val.chars().distinct().count() == 1) return true;
        // Homogeneous string: a single character dominates >60% of the value (e.g., AAAAAAA...BC).
        // Real credentials are random — no character should dominate this heavily.
        if (val.length() >= 16) {
            int[] freq = new int[128];
            int maxFreq = 0;
            for (char c : val.toCharArray()) {
                if (c < 128 && ++freq[c] > maxFreq) maxFreq = freq[c];
            }
            if (maxFreq * 100 / val.length() > 60) return true;
        }
        // SQL/template named parameter: @paramName (Dapper, ADO.NET, C# Razor, etc.)
        // e.g. @transactionMasterId, @userId — these are parameterized query placeholders, never secrets.
        if (val.matches("@[A-Za-z][A-Za-z0-9_]+")) return true;

        // Fake UUID / template identifier: 5 hyphen-separated segments where 2 or more
        // segments are pure alpha and contain at least one non-hex letter (g–z).
        // e.g. "abcd-1234-5678-lala-xyz" — real tokens never have human-readable alpha segments.
        String[] hsegs = v.split("-");
        if (hsegs.length >= 5) {
            int nonHexAlpha = 0;
            for (String seg : hsegs) {
                if (seg.length() >= 3 && seg.matches("[a-z]+") && !seg.matches("[a-f]+"))
                    nonHexAlpha++;
            }
            if (nonHexAlpha >= 2) return true;
        }
        return false;
    }

    // =========================================================================
    // Severity scoring
    // =========================================================================

    private String scoreSeverity(String key, String val) {
        if (key == null) return "LOW";
        // Azure GUIDs used as credential keys are reported at INFORMATION/MEDIUM per the key checks below.
        // All other non-probable values default to LOW.
        if (!isProbableSecretValue(val) && !isAzureGuid(val)) return "LOW";
        String k = key.toLowerCase().replaceAll("[_\\-]", "");
        // *Hex-suffixed crypto material keys (kyHex, ivHex, keyHex, secretHex, tokenHex) are always
        // raw cryptographic key/IV material — score HIGH regardless of the prefix segment.
        if (k.endsWith("hex") && k.length() > 3) return "HIGH";
        // Crypto operation key names: encryptionKey*, decryptionKey*, cipherKey*, aesKey*, hmacKey*
        if (k.contains("encryptionkey") || k.contains("decryptionkey")
                || k.contains("cipherkey") || k.contains("aeskey") || k.contains("hmackey")) return "HIGH";
        if (k.contains("encryptedenv") || k.contains("cryptojskey") || k.contains("cryptokey")) return "HIGH";
        if (k.contains("subscriptionkey") || k.contains("subkey") || k.contains("ocpapim")) return "HIGH";
        if (k.contains("apimkey"))         return "HIGH";
        if (k.contains("appkey") || k.contains("applicationkey")) return "HIGH";
        if (k.equals("secret")) return "HIGH";   // bare "secret" field in config/JSON
        if (k.contains("secretkey") || k.contains("signingkey") || k.contains("masterkey")) return "HIGH";
        if (k.contains("apikey") || k.contains("xapikey"))       return "HIGH";
        if (k.contains("resourcekey") || k.contains("storagekey") || k.contains("addresskey")) return "HIGH";
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
        // Azure ADAL/MSAL resource identifier — bare "resource" key holding a GUID or URL
        // identifies which Azure service is being accessed; HIGH for recon in service principal config.
        if (k.equals("resource") || k.contains("resourceid") || k.contains("resourceguid")) return "HIGH";
        // VAPID public key — intentionally public (Web Push), not a secret credential.
        if (k.contains("vapid"))                                  return "INFORMATION";
        if (k.contains("userid"))                                 return "LOW";
        if (isSemanticSecretKey(key))      return "MEDIUM";
        return "LOW";
    }

    // =========================================================================
    // Deduplication
    // =========================================================================

    private static final java.util.regex.Pattern UUID_IN_VAL = java.util.regex.Pattern.compile(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");

    private static List<SecretFinding> deduplicate(List<SecretFinding> raw) {
        Set<String> seenRuleValue = new LinkedHashSet<>();
        Set<String> seenValue     = new LinkedHashSet<>();   // values seen by specific rules
        // Cross-rule UUID dedup: Azure connection strings (e.g. InstrumentationKey=UUID;...)
        // can be matched by multiple rules simultaneously (AZURE_APPINSIGHTS_001, GENERIC_KV,
        // JSON_WALK), all extracting the same UUID but with different key names. Track each
        // UUID seen per source-URL so only the first (highest-priority) finding is kept.
        Set<String> seenUuids     = new HashSet<>();
        // Cross-rule value+line dedup: same secret value at the same line number is one
        // finding regardless of which rule caught it (e.g. JWT_TOKEN_001 and GENERIC_KV
        // both matching the same JWT embedded in a hidden field on line 20).
        // Only applied when lineNumber > 0 to avoid collapsing findings that have no
        // meaningful document position.  First rule in the pipeline wins (anchored vendor
        // rules are added before generic KV / entropy scanners).
        Set<String> seenValueLine = new HashSet<>();
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
            // Include line number AND match offset in dedup keys so the same credential at
            // different lines or different positions within a minified bundle each produce a
            // separate finding. lineNumber alone is insufficient for minified JS where every
            // match shares the same line; offset disambiguates per-occurrence within one line.
            String lineSuffix   = (f.lineNumber() > 0) ? ":" + f.lineNumber() : "";
            String offsetSuffix = (f.matchOffset() >= 0) ? ":" + f.matchOffset() : "";
            String dedupeKey = f.ruleId().equals("GENERIC_KV")
                    ? f.ruleId() + ":" + f.keyName() + ":" + f.matchedValue() + lineSuffix + offsetSuffix
                    : contextSensitive
                        ? f.ruleId() + ":" + f.keyName() + ":" + f.matchedValue() + offsetSuffix
                        : f.ruleId() + ":" + f.matchedValue() + lineSuffix + offsetSuffix;
            if (!seenRuleValue.add(dedupeKey)) continue;

            // Cross-rule value+(line|offset) dedup: same value at the same position = one finding.
            // Prefer offset when present (works for minified files); fall back to line otherwise.
            if (f.matchOffset() >= 0) {
                if (!seenValueLine.add(f.matchedValue() + "\0" + f.matchOffset())) continue;
            } else if (f.lineNumber() > 0) {
                if (!seenValueLine.add(f.matchedValue() + "\0" + f.lineNumber())) continue;
            }

            // Cross-rule UUID dedup: a UUID embedded in an Azure connection string
            // (e.g. "InstrumentationKey=<uuid>;IngestionEndpoint=...") is extracted by
            // AZURE_APPINSIGHTS_001, GENERIC_KV (key="connectionString"), and sometimes
            // JSON_WALK all in the same scan pass — each with a different key name.
            // After the first (highest-priority, as rules are ordered) finding wins,
            // suppress subsequent findings whose matched value *contains* the same UUID.
            java.util.regex.Matcher uuidM = UUID_IN_VAL.matcher(f.matchedValue());
            if (uuidM.find()) {
                String uuid = uuidM.group().toLowerCase();
                String uuidKey = uuid + "@" + f.sourceUrl();
                if (!seenUuids.add(uuidKey)) continue;
            }

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
     * Scans text against user-defined custom rules from ScanSettings.
     * Each rule line has the format: RuleName | regex | severity
     * Lines that are blank, start with '#', or are malformed are silently skipped.
     * Bad regex patterns are skipped individually and do not affect other rules.
     * This method is purely additive — it never modifies built-in detection.
     */
    private List<SecretFinding> scanCustomRules(String text, String url) {
        return scanCustomRules(text, url, null);
    }

    private List<SecretFinding> scanCustomRules(String text, String url, List<DebugEntry> dbg) {
        if (!settings.isCustomRulesEnabled()) return List.of();
        List<String> ruleLines = settings.getCustomRules();
        if (ruleLines.isEmpty()) return List.of();
        // CDN check — skip known CDN URLs entirely (same gate as built-in scanners).
        // Note: CDN check also applies in raw mode — user said allow/block/CDN stay active.
        if (isExternalCdn(url)) return List.of();
        // Raw mode (custom-rules-only): bypass FP gates inside the per-match loop. Every
        // regex hit is reported as-is. CDN/allowlist/blocklist still apply at the call sites.
        final boolean rawMode = settings.isCustomRulesOnly();
        // Pre-compile inner-value extractor for KEY=VALUE / KEY:VALUE patterns (no capture group).
        // Catches config-file-targeting rules firing on JS enum constants, error codes, icon names.
        java.util.regex.Pattern assignPat = java.util.regex.Pattern.compile(
                "[\\w\\-]+[=:][\"']?([^\"'\\r\\n=:{},]{4,})[\"']?");
        List<SecretFinding> findings = new ArrayList<>();
        for (String line : ruleLines) {
            if (line.isBlank() || line.startsWith("#")) continue;
            String[] parts = line.split(" \\| ", 3);
            if (parts.length < 3) continue;
            String ruleName = parts[0].trim();
            String regex    = parts[1].trim();
            String severity = parts[2].trim().toUpperCase();
            if (ruleName.isEmpty() || regex.isEmpty()) continue;
            if (!severity.equals("HIGH") && !severity.equals("MEDIUM")
                    && !severity.equals("LOW") && !severity.equals("INFORMATION")) {
                severity = "MEDIUM";
            }
            java.util.regex.Pattern pat;
            try {
                pat = java.util.regex.Pattern.compile(regex);
            } catch (Exception ex) {
                logging.logToError("[SecretSifter] Custom rule '" + ruleName +
                        "' has invalid regex — skipping: " + ex.getMessage());
                continue;
            }
            java.util.regex.Matcher m = pat.matcher(text);
            Set<String> seen = new HashSet<>();
            while (m.find()) {
                if (!rawMode) {
                // Mid-identifier suffix guard: if the char immediately before this match is a
                // letter, digit, or hyphen, the pattern fired on the tail of a longer compound
                // name.  Examples:
                //   data-sitekey="6Lf..." → 'e' precedes match (letter)
                //   data-netlify-cwv-token="eyJ..." → '-' precedes "token=" (hyphen in compound)
                // Real env/config KEY=VALUE tokens are always preceded by whitespace, '{', ';',
                // newline, or start-of-string — never by a word char or hyphen.
                // Rules with capture groups are exempt — their group(0) context handles this.
                if (m.start() > 0 && m.groupCount() == 0) {
                    char prevChar = text.charAt(m.start() - 1);
                    if (Character.isLetterOrDigit(prevChar) || prevChar == '-') continue;
                }
                // (A1) PEM header-only guard: community rules targeting PEM block headers
                // (e.g. PgpPrivateKeyBlock matching "-----BEGIN PGP PRIVATE KEY BLOCK-----")
                // fire on header-only occurrences — stub values, comments, documentation strings,
                // and <meta> tags — where no actual key body follows.  The built-in PEM_PRIVATE_KEY
                // anchored rule requires at least one base64 line after the header; community rules
                // often omit this requirement.  Skip any match whose full text is exactly a PEM
                // block header line with no key body content after it.
                {
                    String v0 = m.group(0).trim();
                    if (v0.startsWith("-----BEGIN ") && v0.endsWith("-----")
                            && !v0.contains("\n") && !v0.contains("\\n")) continue;
                }
                } // end !rawMode (early-gate block)
                // If the regex has a capture group, use group(1) as the extracted value
                // (e.g. MixpanelApiKey | (?:mixpanel)[^a-z0-9]{0,10}([a-f0-9]{32}) | MEDIUM
                //  — group(1) is just the token, group(0) includes the vendor prefix context).
                // Fall back to group(0) when there are no capture groups.
                String val;
                boolean usedFullMatch; // true when group(0) was used (no capture group)
                try {
                    String g1 = m.groupCount() >= 1 ? m.group(1) : null;
                    if (g1 != null && !g1.isBlank()) {
                        val = g1.trim();
                        usedFullMatch = false;
                    } else {
                        val = m.group(0).trim();
                        usedFullMatch = true;
                    }
                } catch (Exception ex) {
                    val = m.group(0).trim();
                    usedFullMatch = true;
                }
                if (val.isEmpty()) continue;
                // Per-rule per-value dedup: skip in raw mode so users see every regex hit
                // (different offsets of the same captured value each surface separately).
                if (!rawMode && !seen.add(val)) continue;
                if (!rawMode) {
                // Noise suppression — same gates used by built-in scanners:
                // (1) isProbableSecretValue: rejects all-alpha identifiers, camelCase/PascalCase
                //     class names, SCREAMING_SNAKE_CASE constants, kebab-case paths, JS fragments.
                if (!isProbableSecretValue(val)) {
                    dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                            ruleName, dbgVal(val), "not_probable_secret_value", url));
                    continue;
                }
                // (1b) All-digit strings are never API tokens; real vendor tokens always mix
                //      letters with digits.  Broad patterns (e.g. \b[A-Za-z0-9]{31}\b for
                //      BackblazeB2AppKey, \b[a-z0-9]{30}\b for PushoverApiToken) match timezone
                //      DST transition index strings like "0121212121212121212121212121212"
                //      which are pure-numeric.
                if (val.matches("\\d+")) {
                    dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                            ruleName, dbgVal(val), "all_digits", url));
                    continue;
                }
                // (1d) SRI integrity hash filter: sha256-/sha384-/sha512- prefixed base64 strings
                //      are Subresource Integrity checksums embedded in HTML <script integrity="...">
                //      attributes — public file-integrity proofs, never credential values.
                //      e.g. "sha512-BiLd1BPipMJHwKREZnwWCrHBfMZMpdi1qtok..."
                if (val.startsWith("sha256-") || val.startsWith("sha384-") || val.startsWith("sha512-")) {
                    dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                            ruleName, dbgVal(val), "sri_hash", url));
                    continue;
                }
                // (1c) Lowercase hex strings in the 28–40 char range are ASN.1/DER algorithm
                //      identifier headers (PKCS#1 DigestInfo OIDs bundled in crypto libraries
                //      like jsrsasign): sha1="3021300906052b0e03021a05000414" (30 chars),
                //      ripemd160="3021300906052b2403020105000414" (30 chars), etc.
                //      Real API tokens that use hex always contain uppercase letters.
                if (val.matches("[0-9a-f]{28,40}")) {
                    dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                            ruleName, dbgVal(val), "hex_crypto_oid", url));
                    continue;
                }
                // (2) Short pure-hex values (< 24 chars) are webpack chunk hashes / MD5 fragments,
                //     not API keys. Real hex tokens (subscription keys, APIM) are 32+ chars.
                if (val.matches("[a-fA-F0-9]+") && val.length() < 24) {
                    dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                            ruleName, dbgVal(val), "short_hex", url));
                    continue;
                }
                // (3) Multi-hyphen slug rejection: URL path slugs, webpack module paths, and
                //     news-headline fragments contain 3+ hyphens with only word/hyphen chars.
                //     Real API keys with hyphens use at most 1-2 segments.
                //     UUID format is exempted (handled as Azure credentials elsewhere).
                if (val.chars().filter(c -> c == '-').count() >= 3
                        && val.matches("[A-Za-z0-9_\\-]+")
                        && !val.matches("[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}")) {
                    dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                            ruleName, dbgVal(val), "url_slug", url));
                    continue;
                }
                // (4) Inner-value extraction: when val is a KEY=VALUE / KEY:VALUE full match
                //     (pattern uses no capture group), re-test isProbableSecretValue on just the
                //     VALUE part.  Filters MSAL enum constants, OAuth2 grant type strings,
                //     AG Grid event names, and icon keys that pass the outer gate only because
                //     = and " are punctuation chars that satisfy the strongSym check.
                java.util.regex.Matcher assign = assignPat.matcher(val);
                boolean assignMatched = assign.matches();
                if (assignMatched) {
                    String inner = assign.group(1).replace("\"", "").replace("'", "").trim();
                    if (!isProbableSecretValue(inner)) {
                        dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                                ruleName, dbgVal(val), "not_probable_secret_value_inner", url));
                        continue;
                    }
                    // JS string-concatenation fragments: the extracted inner value starts or ends
                    // with '+' — it is the adjacent operand in a JS string-build expression, not
                    // a hardcoded token.  e.g. Token="+TK_requestToken (from RAON TransKey SDK).
                    if (inner.startsWith("+") || inner.endsWith("+")) {
                        dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                                ruleName, dbgVal(val), "js_concat_fragment", url));
                        continue;
                    }
                    // Multi-hyphen slug on inner: filter (3) above applies to `val` but the full
                    // match (e.g. key="gwp-6073-dreamdata-gate") contains quote chars so it fails
                    // the [A-Za-z0-9_\-]+ guard.  Apply the same slug check to the extracted
                    // inner value. e.g. HTML data-flag-key="gwp-6073-dreamdata-gate" → inner has
                    // 3 hyphens and is pure word chars → slug, not a credential.
                    if (inner.chars().filter(c -> c == '-').count() >= 3
                            && inner.matches("[A-Za-z0-9_\\-]+")
                            && !inner.matches("[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}")) {
                        dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                                ruleName, dbgVal(val), "url_slug_inner", url));
                        continue;
                    }
                    // URL query parameter look-back: the full-match KEY=VALUE regex may fire
                    // mid-key-name when a broader key contains the matched sub-key, e.g.
                    // "&amp;idkey=0Es..." — the rule matches "key=0Es..." starting inside
                    // "idkey". Walk backward from m.start() through any word-chars; if we reach
                    // '?', '&', or HTML-encoded '&amp;', the whole expression is a URL query
                    // param value (server-generated, non-extractable) — not a config assignment.
                    {
                        int back  = m.start() - 1;
                        int steps = 0;
                        while (back >= 0 && steps < 30
                                && (Character.isLetterOrDigit(text.charAt(back))
                                    || text.charAt(back) == '_')) {
                            back--;
                            steps++;
                        }
                        if (back >= 0) {
                            char bc = text.charAt(back);
                            boolean isQp = (bc == '?' || bc == '&')
                                    || (bc == ';' && back >= 4
                                        && text.substring(back - 4, back).equals("&amp"));
                            if (isQp) {
                                dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                                        ruleName, dbgVal(val), "url_query_param_value", url));
                                continue;
                            }
                        }
                    }
                }
                // (4b) Empty-value assignment filter: when assignPat fails to extract a clean
                //      inner value (assign.matches() == false) but the full match is a KEY=VALUE
                //      form, check whether the actual value after '=' is empty or starts with a
                //      delimiter.  Catches rules that fire on config keys where the value is
                //      runtime-injected (blank at scan time), e.g.
                //      x-unblu-apikey=",unbluVisitorApiScriptPath:" — the value literal is "".
                if (usedFullMatch && !assignMatched) {
                    int eqPos  = val.indexOf('=');
                    int colPos = val.indexOf(':');
                    int sep    = (eqPos >= 0) ? eqPos : colPos;
                    if (sep >= 0 && sep < val.length() - 1) {
                        String after = val.substring(sep + 1);
                        // strip one leading quote
                        if (!after.isEmpty() && (after.charAt(0) == '"' || after.charAt(0) == '\''))
                            after = after.substring(1);
                        // empty or delimiter-start → no real value present
                        if (after.isEmpty()
                                || after.charAt(0) == ','
                                || after.charAt(0) == '"'
                                || after.charAt(0) == '\''
                                // JS string-concatenation: value after `=` is `"+variable`
                                // (e.g. WordPress wp-embed: `secret="+t,e.setAttribute(`)
                                // After stripping the opening `"`, inner starts with `+`.
                                || after.startsWith("+")
                                // CSS attribute selector: password:"[type=password]" — the value
                                // is an input-type selector constant, not a credential.
                                || (after.startsWith("[") && after.contains("=") && after.contains("]"))) {
                            dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                                    ruleName, dbgVal(val), "empty_assignment", url));
                            continue;
                        }
                    }
                }
                // (5a) URL value filter: reject matches whose full match or inner value is a URL.
                //      isProbableSecretValue rejects values starting with "https://" but the
                //      assignPat inner-value extractor fails when "://" contains a ":" (which
                //      is excluded from the capture group charset), leaving the full match —
                //      e.g. authToken:"https://..." — to pass via the strongSym ":" check.
                if (val.contains("://")) {
                    dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                            ruleName, dbgVal(val), "url_value", url));
                    continue;
                }
                // (5b) CSS animation-name / keyframe-name filter: CSS @keyframes names often
                //      embed ARGB color values as lowercase-word + hex segments, e.g.
                //      "background-8A000000FFF4433600000000FFF44336". The word prefix passes
                //      the all-alpha check (hasDigit=true from hex), but it is not a secret.
                if (val.matches("[a-z][a-z0-9]*(-[0-9A-Fa-f]{6,})+")) {
                    dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                            ruleName, dbgVal(val), "css_animation_keyframe", url));
                    continue;
                }
                // (5c) JWT signature segment filter: the third segment of a JWT (HMAC signature)
                //      appears immediately after "." in "header.payload.SIGNATURE".
                //      JWT_TOKEN_001 already captures the full token; matching only the
                //      signature creates noise duplicates for e.g. BOT_PROJECT_TOKEN JWTs.
                //      Signal: matched value is base64url AND the preceding char is ".".
                if (m.start() > 1
                        && text.charAt(m.start() - 1) == '.'
                        && isBase64UrlChar(text.charAt(m.start() - 2))) {
                    dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                            ruleName, dbgVal(val), "jwt_signature_segment", url));
                    continue;
                }
                // (5d) URL query parameter filter: values appearing as ?key=VALUE or &key=VALUE
                //      (ASP.NET ?v=BASE64URL cache-busters, nonce query params, etc.) are
                //      server-generated, public-facing values — not extractable secrets.
                //      Signal: the char immediately before the match is '=', and scanning
                //      backward through the key name finds a '?' or '&' delimiter.
                if (m.start() >= 2 && text.charAt(m.start() - 1) == '=') {
                    int back  = m.start() - 2;
                    int steps = 0;
                    while (back >= 0 && steps < 30
                            && (Character.isLetterOrDigit(text.charAt(back))
                                || text.charAt(back) == '_')) {
                        back--;
                        steps++;
                    }
                    if (back >= 0 && (text.charAt(back) == '?' || text.charAt(back) == '&')) {
                        dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                                ruleName, dbgVal(val), "url_query_param", url));
                        continue;
                    }
                }
                // (5e) CSRF anti-forgery token filter: "csrf_token=VALUE" or "csrf-token=VALUE"
                //      appear in HTML href/action attributes and JavaScript template strings.
                //      The regex often matches starting mid-key (at "token=..."), so check
                //      whether "csrf" appears in the 5 chars immediately preceding the match.
                if (m.start() >= 4) {
                    String near = text.substring(Math.max(0, m.start() - 5), m.start());
                    if (near.toLowerCase().contains("csrf")) {
                        dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                                ruleName, dbgVal(val), "csrf_token_value", url));
                        continue;
                    }
                }
                // (5f) CSP nonce filter: Content-Security-Policy nonces appear as
                //      nonce="VALUE" or nonce='VALUE' in HTML <script> and <style> tags.
                //      They are single-use random values, not extractable secrets.
                if (m.start() >= 7) {
                    String pre7 = text.substring(m.start() - 7, m.start());
                    if (pre7.equals("nonce=\"") || pre7.equals("nonce='")) {
                        dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                                ruleName, dbgVal(val), "csp_nonce_value", url));
                        continue;
                    }
                }
                // (5g) SVG path data filter: FontAwesome / Material icons inline their glyph
                //      paths as SVG `d="M0 224h192V32H0v192zM64..."` strings.  The path
                //      command letters (h, H, v, V, z, m, M, l, L, c, C, s, S, q, Q, t, T, a, A)
                //      interspersed with coordinates look like alphanumeric tokens to generic
                //      rules (e.g. CUSTOM_HEREAPIKEY matching "480h192V288H0v192zm64-128h64v64").
                //      Signal: the matched value contains at least 3 occurrences of a digit
                //      immediately adjacent to an SVG path command letter.
                {
                    int svgHits = 0;
                    for (int si = 0; si < val.length() - 1; si++) {
                        char cur  = val.charAt(si);
                        char next = val.charAt(si + 1);
                        if ((Character.isDigit(cur) || cur == '-')
                                && "mMlLhHvVzZcCsSqQtTaA".indexOf(next) >= 0) { svgHits++; }
                        else if ("mMlLhHvVzZcCsSqQtTaA".indexOf(cur) >= 0
                                && (Character.isDigit(next) || next == '-')) { svgHits++; }
                    }
                    if (svgHits >= 3) {
                        dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                                ruleName, dbgVal(val), "svg_path_data", url));
                        continue;
                    }
                }
                // (5g-url) Percent-encoded blob context filter: if the ±80-char window
                //          around the match contains 3 or more %XX percent-encoded
                //          sequences, the matched value is embedded inside a URL-encoded
                //          blob (obfuscated JS, query-param payload, base64 chunk).
                //          A single lone '%' is not enough — require 3+ to avoid
                //          suppressing legitimate keys that happen to sit near one escape.
                {
                    int winStart = Math.max(0, m.start() - 80);
                    int winEnd   = Math.min(text.length(), m.end() + 80);
                    String window = text.substring(winStart, winEnd);
                    int pctCount = 0;
                    for (int wi = 0; wi < window.length() - 2; wi++) {
                        if (window.charAt(wi) == '%') {
                            char h1 = window.charAt(wi + 1), h2 = window.charAt(wi + 2);
                            if (isHexDigit(h1) && isHexDigit(h2)) { pctCount++; wi += 2; }
                        }
                    }
                    if (pctCount >= 3) {
                        dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                                ruleName, dbgVal(val), "percent_encoded_context", url));
                        continue;
                    }
                }
                // (5g-corp) Google internal hostname filter: values ending in ".corp" are
                //           Google's internal `.corp.google.com` routing domain constants,
                //           hardcoded in every distributed Google JS bundle — not secrets.
                if (val.endsWith(".corp") || val.contains(".corp.")) {
                    dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                            ruleName, dbgVal(val), "google_corp_hostname", url));
                    continue;
                }
                // (5g-ph) Placeholder / example value filter: UI input placeholders and
                //         documentation examples embed real-looking values (IP addresses,
                //         key formats) as illustrative text, not real credentials.
                //         Signal: "placeholder" or "e.g." appears within 40 chars before match.
                if (m.start() > 0) {
                    String pre40 = text.substring(Math.max(0, m.start() - 40), m.start());
                    String pre40lc = pre40.toLowerCase();
                    if (pre40lc.contains("placeholder") || pre40lc.contains("e.g.")) {
                        dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                                ruleName, dbgVal(val), "placeholder_context", url));
                        continue;
                    }
                }
                // (5h) URL path filename / slug filter: a match immediately followed by
                //      '.' + a file extension (pdf, js, html, png, etc.) is a filename
                //      embedded in a URL path or href attribute, not a secret token.
                //      e.g. "fraud-warning-notice_smallbusiness_04032023.pdf"
                if (m.end() < text.length() - 1 && text.charAt(m.end()) == '.') {
                    int extEnd = m.end() + 1;
                    while (extEnd < text.length()
                            && extEnd - m.end() <= 6
                            && Character.isLetter(text.charAt(extEnd))) extEnd++;
                    int extLen = extEnd - m.end() - 1;
                    if (extLen >= 2 && extLen <= 5) {
                        dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                                ruleName, dbgVal(val), "url_filename_suffix", url));
                        continue;
                    }
                }
                // (5i) Webpack bundle identifier filter: minified webpack output wraps every
                //      imported module in a variable like "rxjs_operators__WEBPACK_IMPORTED_MODULE_9__".
                //      These are build-tool artefacts, never credential values.
                if (val.contains("__WEBPACK_") || val.contains("__webpack_")) {
                    dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                            ruleName, dbgVal(val), "webpack_identifier", url));
                    continue;
                }
                // (5i-b) Webpack variable assignment filter: even when the variable name itself
                //        contains no "__WEBPACK__" marker (e.g. "wic_frequency_..._master_1",
                //        "select_plus_sg_..._component_1"), the assignment context always reads
                //        "var <name> = __webpack_require__(N)".  Check the 40-char window after
                //        the match end — if it contains "webpack_require", the matched value is
                //        a build-tool variable name, not a credential.
                if (m.end() < text.length()) {
                    String afterMatch = text.substring(m.end(),
                            Math.min(text.length(), m.end() + 40));
                    if (afterMatch.contains("webpack_require")) {
                        dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                                ruleName, dbgVal(val), "webpack_variable_assignment", url));
                        continue;
                    }
                }
                // (5i-c) Object/JSON property key filter: if the match is immediately followed
                //        by ':' (and the char after ':' is not '/' which would indicate a URL
                //        scheme like "://"), the matched string is a JSON/object property KEY,
                //        not a credential value.  e.g. "totalhroGreaterThan1Point2MRange: …"
                if (m.end() < text.length() && text.charAt(m.end()) == ':') {
                    char afterColon = (m.end() + 1 < text.length())
                            ? text.charAt(m.end() + 1) : '\0';
                    if (afterColon != '/') {
                        dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                                ruleName, dbgVal(val), "object_property_key", url));
                        continue;
                    }
                }
                // (5i-d) JS function name filter: if the match is immediately followed by '(',
                //        the matched string is a function name or function call, not a token.
                //        Catches Angular compiled template functions whose length coincidentally
                //        matches a broad vendor-key pattern length (e.g. HereApiKey matches
                //        \b[A-Za-z0-9_-]{43}\b and Angular emits 43-char function names like
                //        "KWizardActionsComponent_k_button_2_Template").
                if (m.end() < text.length() && text.charAt(m.end()) == '(') {
                    dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                            ruleName, dbgVal(val), "function_name", url));
                    continue;
                }
                // (5i-e) Packed/eval-obfuscated JS scope string filter: minified JS packed with
                //        tools like JsPacker or p,a,c,k,e,d encodes all identifiers in a
                //        pipe-delimited scope string, e.g.
                //        'fo|0x98badcfe|rstr_md5|_x509_getSubjectPublicKeyInfoPosFromCertHex|...'
                //        A match immediately preceded or followed by '|' is an identifier inside
                //        this scope list — not a credential value.
                if ((m.start() > 0 && text.charAt(m.start() - 1) == '|')
                        || (m.end() < text.length() && text.charAt(m.end()) == '|')) {
                    dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                            ruleName, dbgVal(val), "packed_js_scope_string", url));
                    continue;
                }
                // (5i-e2) Unit test name filter: test assertion helpers embed parameter names
                //         in a "testMethodName_input_expected_value" format.  The `_expected_`
                //         segment (or `_expected-`) is the canonical signal.
                //         e.g. "testArrayClosestItemKeyIndex_-1_expected_-1"
                if (val.contains("_expected_") || val.contains("_expected-")) {
                    dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                            ruleName, dbgVal(val), "test_assertion_name", url));
                    continue;
                }
                // (5i-e3) TypeScript compiler diagnostic key filter: TypeScript (and tsc-compiled
                //         webpack bundles) embeds its error/warning message registry as
                //         Snake_Case_Identifiers_with_a_4or5digit_suffix, e.g.:
                //           "const_declarations_must_be_initialized_1155"
                //           "Classes_can_only_extend_a_single_class_1174"
                //         Broad vendor-key patterns (e.g. CUSTOM_HEREAPIKEY) fire on these
                //         because they are long alphanumeric+underscore strings of the right
                //         length.  Signal: ≥3 underscore-separated word segments ending with
                //         a 4–5 digit numeric suffix.
                if (val.matches("[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z][A-Za-z0-9]*){2,}_\\d{4,5}")) {
                    dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                            ruleName, dbgVal(val), "typescript_diagnostic_key", url));
                    continue;
                }
                // (5i-e4) Salesforce custom field / relationship API name filter:
                //         Salesforce custom fields and objects always end with __c, custom
                //         relationships with __r, and external-ID fields with __x.  These are
                //         Salesforce schema identifiers compiled into LWC / Aura bundles and are
                //         never credential values.
                //         e.g. "Include_COVID_19_Language_for_Accident_P__c"
                if (val.endsWith("__c") || val.endsWith("__r") || val.endsWith("__x")) {
                    dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                            ruleName, dbgVal(val), "salesforce_custom_field", url));
                    continue;
                }
                // (5i-e5) Digit-prefixed data-model field name filter: JavaScript bracket-notation
                //         property keys that start with a digit then underscore are indexed
                //         form-field or data-model identifiers
                //         (e.g. "1_applicantWidgetExistingDisability_insurer").
                //         Real vendor API keys never start with a digit followed by an underscore.
                if (val.matches("\\d+_[A-Za-z][A-Za-z0-9_]+")) {
                    dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                            ruleName, dbgVal(val), "indexed_field_name", url));
                    continue;
                }
                // (5i-f-css) CSS Modules class name filter: React/Next.js CSS Modules generates
                //            class identifiers with a double-underscore hash suffix, e.g.
                //            "ComponentName_element-name__QL4EZ" or
                //            "leftRightImageTextPanel_quote-column__Gr5sl".
                //            The "__HASH" (3–8 alphanumeric chars) at the end is the canonical
                //            CSS Modules / SVG-export build-tool content hash — not a credential.
                //            Also catches Adobe Illustrator SVG export classes: "_svg__st0",
                //            "_svg__st1", etc. (Illustrator always generates __stN suffixes).
                //            Create React App / Emotion also produce triple-underscore hashes with
                //            underscores and hyphens in the suffix, e.g. "___1Hl_E", "___3G-yc".
                if (val.matches(".*__[A-Za-z0-9_\\-]{3,8}$")) {
                    dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                            ruleName, dbgVal(val), "css_modules_class", url));
                    continue;
                }
                // (5i-f-data) HTML data-* attribute context filter: values in non-secret
                //             data-* HTML attributes are public metadata (Drupal contextual
                //             tokens, feature flags, component props).  Look in the 80-char
                //             window before the match for data-ATTRNAME=" — if found and the
                //             attribute is not a known secret attr, suppress.
                {
                    String pre80 = text.substring(Math.max(0, m.start() - 80), m.start());
                    java.util.regex.Matcher dam = java.util.regex.Pattern
                            .compile("(?i)\\bdata-([a-z][a-z0-9-]*)=[\"']?$").matcher(pre80);
                    if (dam.find()) {
                        String attrName = dam.group(1);
                        if (!attrName.matches("api.?key|auth.?token|secret|access.?token|client.?secret")) {
                            dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                                    ruleName, dbgVal(val), "html_data_attr", url));
                            continue;
                        }
                    }
                }
                // (5i-f-nr) New Relic Browser Agent (NREUM) init snippet filter: the NRJS-
                //           browser license key is intentionally embedded in every HTML page
                //           the NREUM browser-monitoring agent ships — it is public by design,
                //           like a Google Analytics tracking ID.  Signal: "NREUM" appears
                //           within 300 chars of the match position.
                {
                    int winS = Math.max(0, m.start() - 300);
                    int winE = Math.min(text.length(), m.end() + 300);
                    if (text.substring(winS, winE).contains("NREUM")) {
                        dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                                ruleName, dbgVal(val), "newrelic_license_key", url));
                        continue;
                    }
                }
                // (5i-f) HTML meta site-verification token filter: search-engine ownership
                //        verification tokens appear as <meta name="google-site-verification"
                //        content="TOKEN"> or <meta name="msvalidate.01" content="TOKEN">.
                //        They are public, single-use ownership proofs — not extractable secrets.
                //        Signal: "verification" appears in the 100-char window before the match.
                if (m.start() > 0) {
                    String pre100 = text.substring(Math.max(0, m.start() - 100), m.start());
                    if (pre100.toLowerCase().contains("verification")) {
                        dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                                ruleName, dbgVal(val), "site_verification_token", url));
                        continue;
                    }
                }
                // (5j) Angular compiler internal symbol filter: Angular's compiler emits private
                //      API exports prefixed with \u0275 (rendered as "u0275" in raw JS source).
                //      Suffixes "__POST_R3__" and "__R3__" identify runtime-compatibility variants.
                //      e.g. "u0275Compiler_compileModuleAsync__POST_R3__"
                if (val.startsWith("u0275")
                        || val.contains("__POST_R3__") || val.contains("__R3__")) {
                    dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                            ruleName, dbgVal(val), "angular_compiler_symbol", url));
                    continue;
                }
                // (5k) PDF font kerning / metrics data filter: jsPDF and pdfmake embed font width
                //      and kerning tables as compact lowercase+digit strings with many digit↔letter
                //      transitions, e.g. "2ktclucmucnu4otcpu4lu4wycoucku".  Real API tokens always
                //      contain uppercase letters; font data never does.
                //      Signal: all lowercase + digits AND ≥5 digit↔letter class transitions.
                if (val.matches("[0-9a-z]+")) {
                    int dlTrans = 0;
                    for (int si = 0; si < val.length() - 1; si++) {
                        if (Character.isDigit(val.charAt(si)) != Character.isDigit(val.charAt(si + 1)))
                            dlTrans++;
                    }
                    if (dlTrans >= 5) {
                        dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                                ruleName, dbgVal(val), "pdf_font_data", url));
                        continue;
                    }
                }
                // (5) Mid-stream base64 / data URI filter: reject matches that land
                //     inside a continuous base64 stream (CSS mask-image SVG icons,
                //     font-face data URIs, background-image blobs, etc.).
                //     Signal: the matched value is pure base64 AND the adjacent char
                //     in the raw text is also a base64 char — we are in the middle
                //     of a larger encoded blob, not at a clean token boundary.
                //     Also covers base64url (uses - and _ instead of + and /).
                if (val.matches("[A-Za-z0-9+/]+=*")) {
                    boolean prevB64 = m.start() > 0
                            && isBase64Char(text.charAt(m.start() - 1));
                    boolean nextB64 = m.end() < text.length()
                            && isBase64Char(text.charAt(m.end()));
                    if (prevB64 || nextB64) {
                        dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                                ruleName, dbgVal(val), "base64_stream_context", url));
                        continue;
                    }
                }
                if (val.matches("[A-Za-z0-9\\-_]+=*")) {
                    boolean prevB64url = m.start() > 0
                            && isBase64UrlChar(text.charAt(m.start() - 1));
                    boolean nextB64url = m.end() < text.length()
                            && isBase64UrlChar(text.charAt(m.end()));
                    if (prevB64url || nextB64url) {
                        dbgAdd(dbg, new DebugEntry("CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                                ruleName, dbgVal(val), "base64url_stream_context", url));
                        continue;
                    }
                }
                } // end !rawMode (FP-gate block)
                // Derive keyName: when the full match is a KEY=VALUE / KEY:VALUE string,
                // extract the key part (e.g. "apiKey" from "apiKey=abc123"). This gives
                // meaningful column content in the SecretSifter tab and Bulk Scan panel.
                // Falls back to ruleName when the rule used a capture group (bare token).
                String keyName = ruleName;
                if (usedFullMatch) {
                    java.util.regex.Matcher keyM = java.util.regex.Pattern.compile(
                            "^([\\w][\\w\\-\\.]*)[=:]").matcher(val);
                    if (keyM.find()) keyName = keyM.group(1);
                }
                int    lineNum = countLines(text, m.start());
                String ctx     = extractContext(text, m.start(), m.end());
                findings.add(SecretFinding.of(
                        "CUSTOM_" + ruleName.toUpperCase().replaceAll("\\s+", "_"),
                        ruleName, keyName, val, severity, "FIRM", lineNum, ctx, url));
            }
        }
        return findings;
    }

    /**
     * Applies key-name blocklist/allowlist from ScanSettings, then deduplicates.
     * - Allowlist wins: if keyName matches any allowlist entry, finding is always kept.
     * - Blocklist: if keyName matches any blocklist entry (and not allowlisted), finding is dropped.
     * Called at every public scan exit point so both scanText() and scanRequestResponse() honour the lists.
     */
    /** Proxy/request scan path — no debug accumulator. */
    private List<SecretFinding> filterAndDeduplicate(List<SecretFinding> raw) {
        return filterAndDeduplicate(raw, null);
    }

    private List<SecretFinding> filterAndDeduplicate(List<SecretFinding> raw, List<DebugEntry> dbg) {
        List<SecretFinding> filtered = new ArrayList<>(raw.size());
        for (SecretFinding f : raw) {
            // Drop any finding whose value is blank — belt-and-suspenders guard
            if (f.matchedValue() == null || f.matchedValue().isBlank()) continue;
            if (settings.isKeyAllowlisted(f.keyName())) {
                filtered.add(f);          // allowlist always wins
            } else if (!settings.isKeyBlocked(f.keyName())) {
                filtered.add(f);          // not blocked — normal path
            } else {
                // Blocked and not allowlisted → record suppression in debug log
                dbgAdd(dbg, new DebugEntry(f.ruleId(), f.keyName(),
                        dbgVal(f.matchedValue()), "blocklist_key", f.sourceUrl()));
            }
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
                // ALGOLIA_KEY_001: real Algolia App IDs are always UPPERCASE alphanumeric
                // (e.g. JRFR1I7G8S).  The (?i) flag on the pattern makes the [A-Z0-9]{10}
                // capture group also match lowercase — causing JavaScript function/variable
                // names like "autocomple" (first 10 chars of "autocomplete") to fire.
                if ("ALGOLIA_KEY_001".equals(rule.ruleId()) && !val.equals(val.toUpperCase())) continue;
                String dedupe = rule.ruleId() + ":" + val;
                if (!seen.add(dedupe)) continue;
                int    line    = countLines(text, m.start());
                String ctx     = extractContext(text, m.start(), m.end());
                String keyName   = rule.keyName();
                String severity  = rule.severity();
                try {
                    String k = m.group("key");
                    if (k != null && !k.isBlank()) {
                        keyName = k.replaceAll("[\"']", "").trim();
                        // Only re-score when the rule has no explicit severity set (null/"").
                        // When the rule defines HIGH/MEDIUM, trust it — scoreSeverity uses the
                        // captured key name which may be an arbitrary variable (e.g. cctClientportalkey)
                        // and would wrongly downgrade a known-dangerous finding to LOW.
                        if (rule.severity() == null || rule.severity().isBlank()) {
                            severity = scoreSeverity(keyName, val);
                        }
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

    /** True if {@code c} is a valid base64 alphabet character (RFC 4648). */
    private static boolean isBase64Char(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
    }

    /** True if {@code c} is a valid base64url alphabet character (RFC 4648 §5 — uses - and _ instead of + and /). */
    private static boolean isBase64UrlChar(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9') || c == '-' || c == '_';
    }

    /**
     * Detects hardcoded CryptoJS / sjcl AES calls with string literal arguments.
     *
     * Two patterns:
     *   FULL:  .AES.decrypt("ciphertext", "passphrase") — reports both as separate findings
     *   PASSPHRASE_ONLY: .AES.decrypt(variable, "passphrase") — reports passphrase only
     *
     * Both the ciphertext and passphrase are reported as HIGH — the ciphertext is
     * decryptable by anyone who reads the passphrase from the same file.
     */
    private List<SecretFinding> scanCryptoJsPassphrases(String text, String url) {
        List<SecretFinding> findings = new ArrayList<>();
        Set<String> seenCipher = new HashSet<>();
        Set<String> seenPass   = new HashSet<>();

        // Full match: both ciphertext (group 1) and passphrase (group 2) are string literals
        Matcher m = Patterns.CRYPTOJS_AES_FULL.matcher(text);
        while (m.find()) {
            String ciphertext  = m.group(1);
            String passphrase  = m.group(2);
            int    line = countLines(text, m.start());
            String ctx  = extractContext(text, m.start(), m.end());
            if (ciphertext != null && !ciphertext.isBlank() && seenCipher.add(ciphertext)) {
                findings.add(SecretFinding.of(
                        "CRYPTOJS_AES_CIPHERTEXT", "CryptoJS AES Encrypted Payload (Decryptable)",
                        "cryptojs_aes_ciphertext", ciphertext,
                        "HIGH", "CERTAIN", line, ctx, url));
            }
            if (passphrase != null && !passphrase.isBlank()
                    && !isPlaceholder(passphrase) && seenPass.add(passphrase)) {
                findings.add(SecretFinding.of(
                        "CRYPTOJS_AES_KEY", "CryptoJS AES Hardcoded Passphrase",
                        "cryptojs_aes_passphrase", passphrase,
                        "HIGH", "CERTAIN", line, ctx, url));
            }
        }

        // Fallback: first arg is a variable — only passphrase is a string literal
        Matcher m2 = Patterns.CRYPTOJS_AES_PASSPHRASE_ONLY.matcher(text);
        while (m2.find()) {
            String passphrase = m2.group(1);
            if (passphrase == null || passphrase.isBlank()) continue;
            if (isPlaceholder(passphrase)) continue;
            if (!seenPass.add(passphrase)) continue;
            int    line = countLines(text, m2.start());
            String ctx  = extractContext(text, m2.start(), m2.end());
            findings.add(SecretFinding.of(
                    "CRYPTOJS_AES_KEY", "CryptoJS AES Hardcoded Passphrase",
                    "cryptojs_aes_passphrase", passphrase,
                    "HIGH", "CERTAIN", line, ctx, url));
        }

        // E4a — CryptoJS.HmacSHA256/SHA512/etc with hardcoded key
        Set<String> seenHmac = new HashSet<>();
        Matcher mHmac = Patterns.CRYPTOJS_HMAC.matcher(text);
        while (mHmac.find()) {
            String key = mHmac.group(1);
            if (key == null || key.isBlank() || isPlaceholder(key)) continue;
            if (!isProbableSecretValue(key)) continue;
            if (!seenHmac.add(key)) continue;
            int    line = countLines(text, mHmac.start());
            String ctx  = extractContext(text, mHmac.start(), mHmac.end());
            findings.add(SecretFinding.of(
                    "CRYPTOJS_HMAC_KEY", "CryptoJS HMAC Hardcoded Key",
                    "cryptojs_hmac_key", key, "HIGH", "CERTAIN", line, ctx, url));
        }

        // E4b — CryptoJS.enc.Hex.parse("...") / CryptoJS.enc.Base64.parse("...")
        // These pass raw key material to CryptoJS instead of a passphrase string.
        Set<String> seenParse = new HashSet<>();
        Matcher mParse = Patterns.CRYPTOJS_ENC_PARSE.matcher(text);
        while (mParse.find()) {
            String key = mParse.group(1);
            if (key == null || key.isBlank() || isPlaceholder(key)) continue;
            if (!seenParse.add(key)) continue;
            int    line = countLines(text, mParse.start());
            String ctx  = extractContext(text, mParse.start(), mParse.end());
            findings.add(SecretFinding.of(
                    "CRYPTOJS_RAW_KEY", "CryptoJS Raw Key Material (Hex/Base64)",
                    "cryptojs_raw_key", key, "HIGH", "CERTAIN", line, ctx, url));
        }

        // E1 — jwt.sign / jsonwebtoken.sign with hardcoded secret
        Set<String> seenJwt = new HashSet<>();
        Matcher mJwt = Patterns.JWT_SIGN_SECRET.matcher(text);
        while (mJwt.find()) {
            String secret = mJwt.group(1);
            if (secret == null || secret.isBlank() || isPlaceholder(secret)) continue;
            if (!isProbableSecretValue(secret)) continue;
            if (!seenJwt.add(secret)) continue;
            int    line = countLines(text, mJwt.start());
            String ctx  = extractContext(text, mJwt.start(), mJwt.end());
            findings.add(SecretFinding.of(
                    "JWT_SIGN_SECRET", "Hardcoded JWT Signing Secret",
                    "jwt_signing_secret", secret, "HIGH", "CERTAIN", line, ctx, url));
        }

        // E2 — process.env.X || "fallback" hardcoded default
        Set<String> seenFallback = new HashSet<>();
        Matcher mFallback = Patterns.ENV_FALLBACK.matcher(text);
        while (mFallback.find()) {
            String fallback = mFallback.group(1);
            if (fallback == null || fallback.isBlank() || isPlaceholder(fallback)) continue;
            if (!isProbableSecretValue(fallback)) continue;
            if (!seenFallback.add(fallback)) continue;
            int    line = countLines(text, mFallback.start());
            String ctx  = extractContext(text, mFallback.start(), mFallback.end());
            findings.add(SecretFinding.of(
                    "ENV_FALLBACK_SECRET", "Hardcoded process.env Fallback Secret",
                    "env_fallback_value", fallback, "HIGH", "CERTAIN", line, ctx, url));
        }

        // E3 — crypto.createCipheriv / createDecipheriv with hardcoded key
        Set<String> seenCipheriv = new HashSet<>();
        Matcher mCipher = Patterns.CRYPTO_CIPHERIV.matcher(text);
        while (mCipher.find()) {
            String key = mCipher.group(1);
            if (key == null || key.isBlank() || isPlaceholder(key)) continue;
            if (!seenCipheriv.add(key)) continue;
            int    line = countLines(text, mCipher.start());
            String ctx  = extractContext(text, mCipher.start(), mCipher.end());
            findings.add(SecretFinding.of(
                    "CRYPTO_CIPHERIV_KEY", "Hardcoded crypto.createCipheriv Key",
                    "cipheriv_key", key, "HIGH", "CERTAIN", line, ctx, url));
        }

        return findings;
    }

    private List<SecretFinding> scanCommentedGuids(String text, String url) {
        List<SecretFinding> findings = new ArrayList<>();
        String[] lines = text.split("\n", -1);
        java.util.regex.Pattern guidPat = java.util.regex.Pattern.compile(
                "(?://|/\\*)\\s*\"?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\"?");
        // Extracts key name from a JS object property line: "Key": ... or Key: ...
        java.util.regex.Pattern keyPat = java.util.regex.Pattern.compile(
                "\"([^\"]+)\"\\s*:|\\b([A-Za-z_][A-Za-z0-9_]*)\\s*:");
        for (int i = 0; i < lines.length; i++) {
            java.util.regex.Matcher gm = guidPat.matcher(lines[i]);
            if (!gm.find()) continue;
            String guid = gm.group(1);
            // Look back up to 3 lines for the nearest non-comment line with a key name
            String inferredKey = null;
            for (int j = i - 1; j >= Math.max(0, i - 3); j--) {
                String prev = lines[j].trim();
                if (prev.isEmpty() || prev.startsWith("//") || prev.startsWith("*") || prev.startsWith("/*")) continue;
                java.util.regex.Matcher km = keyPat.matcher(prev);
                if (km.find()) {
                    String candidate = km.group(1) != null ? km.group(1) : km.group(2);
                    if (candidate != null && isAzureCredentialKey(candidate)) {
                        inferredKey = candidate;
                    }
                }
                break; // only check the immediately preceding code line
            }
            if (inferredKey == null) continue;
            String sev = scoreSeverity(inferredKey, guid);
            // Commented-out GUIDs adjacent to credential keys are always worth reporting —
            // floor at MEDIUM so they appear in badges even when the key name alone scores INFORMATION.
            if (sev.equals("INFORMATION") || sev.equals("LOW")) sev = "MEDIUM";
            // Build a small context snippet spanning the key line + comment line
            int from = Math.max(0, i - 1);
            int to   = Math.min(lines.length - 1, i + 1);
            StringBuilder ctx = new StringBuilder();
            for (int k = from; k <= to; k++) ctx.append(lines[k].trim()).append(' ');
            findings.add(SecretFinding.of(
                    "COMMENTED_GUID", "Hardcoded GUID in Comment (adjacent to " + inferredKey + ")",
                    inferredKey, guid, sev, "FIRM",
                    i + 1, ctx.toString().trim(), url));
        }
        return findings;
    }

    /**
     * Detects base64-encoded blobs whose decoded content reveals sensitive context.
     *
     * Motivation: keys like {@code skei:"QWdlbnQgUG9ydGFs..."} pass every entropy
     * gate (the raw base64 is high-entropy) but are not caught by anchored or KV rules
     * because the key name ("skei") is vendor-specific. Decoding the blob and checking
     * for sensitive keywords in the plaintext catches these reliably.
     *
     * Algorithm:
     *   1. Find all quoted base64 strings ≥ 40 chars (standard alphabet + padding).
     *   2. Decode to UTF-8; skip non-printable / binary payloads.
     *   3. If the decoded text contains a sensitive keyword (environment, password,
     *      secret, credential, api.key, token, config, auth, .env, private), emit a
     *      MEDIUM / FIRM finding with rule BASE64_ENCODED_VALUE.
     *   4. Deduplicate by (ruleId + raw base64 value).
     *
     * Intentionally skipped:
     *   - SRI hashes (sha256-/sha384-/sha512- prefix)
     *   - Data URIs (data: prefix in surrounding context)
     *   - JWTs (already caught by JWT_TOKEN_001)
     *   - Short blobs < 40 chars (too many short base64 IDs in CSS/JS)
     */
    private List<SecretFinding> scanBase64Blobs(String text, String url) {
        List<SecretFinding> findings = new ArrayList<>();
        // Match quoted base64 values 40–8000 chars. Real secrets (PEM keys, JWTs,
        // connection strings) are at most a few KB; an 8 000-char cap prevents the
        // unbounded `{40,}` from matching embedded WOFF2 fonts, source maps, or other
        // large base64 assets in minified JS bundles, which would cause multi-minute
        // hangs when decoded and searched for keywords.
        java.util.regex.Pattern b64Pat = java.util.regex.Pattern.compile(
                "(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{40,8000}={0,2})(?![A-Za-z0-9+/=])");
        // Sensitive keywords to find in decoded plaintext (lowercase comparison)
        List<String> sensitiveWords = List.of(
                "password", "passwd", "secret", "credential", "api_key", "apikey",
                "api key", "private key", "access key", "token", "auth",
                "environment", ".env", "config", "connection string", "private",
                "subscription", "bearer", "passphrase", "encrypt", "decrypt");
        java.util.Base64.Decoder decoder = java.util.Base64.getDecoder();
        Set<String> seen = new HashSet<>();
        Matcher m = b64Pat.matcher(text);
        while (m.find()) {
            String raw = m.group(1);
            // Hard cap: skip blobs larger than 8 000 chars regardless of pattern match
            if (raw.length() > 8000) continue;
            // Skip SRI integrity hashes
            int preStart = Math.max(0, m.start() - 8);
            String pre8 = text.substring(preStart, m.start()).toLowerCase();
            if (pre8.contains("sha256-") || pre8.contains("sha384-") || pre8.contains("sha512-")) continue;
            // Skip data URIs
            String pre20 = text.substring(Math.max(0, m.start() - 20), m.start()).toLowerCase();
            if (pre20.contains("data:")) continue;
            // Skip JWTs — three-segment base64url starting with "ey"
            if (raw.startsWith("ey") && raw.contains(".")) continue;
            // Deduplicate
            if (!seen.add(raw)) continue;
            // Decode
            byte[] decoded;
            try {
                decoded = decoder.decode(raw);
            } catch (IllegalArgumentException e) {
                continue; // not valid base64
            }
            // Require printable UTF-8 text (reject binary payloads)
            String plain;
            try {
                plain = new String(decoded, StandardCharsets.UTF_8);
            } catch (Exception e) {
                continue;
            }
            // Reject if more than 10% non-printable characters (binary payload)
            long nonPrintable = plain.chars()
                    .filter(c -> c < 0x20 && c != '\n' && c != '\r' && c != '\t')
                    .count();
            if (nonPrintable > plain.length() * 0.10) continue;
            // Check decoded text for sensitive keywords
            String plainLower = plain.toLowerCase();
            String matchedWord = null;
            for (String kw : sensitiveWords) {
                if (plainLower.contains(kw)) { matchedWord = kw; break; }
            }
            if (matchedWord == null) continue;
            // Infer key name from surrounding text (KEY:"VALUE" or KEY=VALUE)
            String keyName = "base64_encoded_value";
            java.util.regex.Matcher keyM = java.util.regex.Pattern.compile(
                    "([\\w][\\w\\-\\.]{0,40})[\\s]*[=:\"'][\\s]*[\"']?$")
                    .matcher(text.substring(Math.max(0, m.start() - 60), m.start()));
            if (keyM.find()) keyName = keyM.group(1);
            int    line = countLines(text, m.start());
            String ctx  = extractContext(text, m.start(), m.end());
            // Annotate context with decoded snippet (first 80 chars)
            String decodedSnippet = plain.length() > 80 ? plain.substring(0, 77) + "..." : plain;
            String enrichedCtx = ctx + " [decoded: " + decodedSnippet.replace("\n", " ") + "]";
            findings.add(SecretFinding.of(
                    "BASE64_ENCODED_VALUE", "Base64-Encoded Sensitive Value",
                    keyName, raw, "MEDIUM", "FIRM", line, enrichedCtx, url));
        }
        return findings;
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
