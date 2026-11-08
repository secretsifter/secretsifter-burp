package com.secretscanner;

import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * All compiled regex Pattern constants and supporting data structures.
 * All fields are public static final — compiled once at class-load time.
 *
 * Severity note: Montoya AuditIssueSeverity has HIGH/MEDIUM/LOW/INFORMATION only.
 * Python CRITICAL → Java HIGH throughout.
 */
public final class Patterns {

    private Patterns() {}

    // =========================================================================
    // VENDOR TOKENS — format-anchored, near-zero FP
    // =========================================================================

    // =========================================================================
    // EXTENDED VENDOR TOKENS
    // =========================================================================

    // ── Additional vendor tokens ───────────────────────────────────────────────

    // =========================================================================
    // NEW VENDORS — SecretSifter parity additions
    // =========================================================================

    // SQL Server / ADO.NET / MySQL semicolon-delimited connection strings
    // Format: "Server=host;Database=db;...;Password=secret" or "Data Source=host;...;Pwd=secret"
    // Captures the password value in group 1.
    // Requires at least one "Key=Value;" pair BEFORE the password to avoid matching
    // bare "Password=xxx" variable assignments (which are caught by scanGenericKV).
    public static final Pattern DOTNET_CONN_STR      = Pattern.compile(
            "(?:[A-Za-z][A-Za-z\\s_]{0,40}=[^;\"'\\r\\n]{1,150};){1,15}" +
            "(?:password|pwd)\\s*=\\s*(\\{[^}\\r\\n]{1,200}\\}|[^;\"'\\r\\n]{4,200})",
            Pattern.CASE_INSENSITIVE);

    // =========================================================================
    // SECRETSIFTER PARITY — TIER A ADDITIONS
    // =========================================================================

    // =========================================================================
    // AZURE SERVICE CONNECTION STRINGS
    //
    // All patterns below anchor on a Microsoft-owned hostname suffix that is
    // unique to a single Azure service.  No random string will ever contain
    // "azure-devices.net", "servicebus.windows.net", etc.
    //
    // Safety notes applied to every pattern:
    //   (1) Field values are bounded by [^;]{1,N} — semicolons are the field
    //       separator in all Azure connection strings.  This prevents the regex
    //       engine from scanning across field boundaries on large JS files and
    //       eliminates catastrophic backtracking.
    //   (2) The key/password capture group uses [A-Za-z0-9+/=\\]{20,200}.
    //       '\\' is included because JSON serialisers escape '/' as '\/' so
    //       a Base64 key embedded in JSON text may contain literal backslashes.
    //   (3) Every pattern uses Pattern.CASE_INSENSITIVE — Azure-generated
    //       connection strings are case-insensitive by specification.
    //   (4) Protocol chars (://, :443/) are skipped with [^;]{0,15} rather
    //       than explicit slash matching to handle both raw and JSON-escaped
    //       forms without adding regex complexity.
    // =========================================================================

    // =========================================================================
    // ADDITIONAL VENDOR TOKEN PATTERNS
    // =========================================================================

    // =========================================================================
    // GAP-CLOSING PATTERNS
    // =========================================================================

    // CryptoJS / sjcl AES call — captures both the ciphertext and the passphrase.
    //   CryptoJS.AES.decrypt("ciphertext", "passphrase")
    //   l.AES.decrypt("ciphertext", "passphrase")
    // group(1) = ciphertext (string literal, 10+ chars) — decryptable with the passphrase
    // group(2) = passphrase (6+ chars) — the symmetric key hardcoded in the JS
    // When the first arg is a variable (not a string literal) only the passphrase is captured
    // via CRYPTOJS_AES_PASSPHRASE_ONLY below.
    public static final Pattern CRYPTOJS_AES_FULL = Pattern.compile(
            "\\.AES\\.(?:decrypt|encrypt)\\s*\\(\\s*\"([^\"]{10,})\"\\s*,\\s*\"([^\"]{6,})\"");

    // Fallback: first arg is a variable, only capture passphrase (group 1).
    public static final Pattern CRYPTOJS_AES_PASSPHRASE_ONLY = Pattern.compile(
            "\\.AES\\.(?:decrypt|encrypt)\\s*\\(\\s*[A-Za-z0-9_.]+\\s*,\\s*\"([^\"]{6,})\"");

    // CryptoJS HMAC with hardcoded key — group(1) = key string literal.
    // Covers: CryptoJS.HmacSHA256(data, "KEY"), CryptoJS.HmacSHA512(data, "KEY"), etc.
    public static final Pattern CRYPTOJS_HMAC = Pattern.compile(
            "(?i)CryptoJS\\.Hmac(?:SHA1|SHA256|SHA512|MD5|RIPEMD160)\\s*\\([^,\"']{0,60},\\s*[\"']([^\"']{6,})[\"']");

    // CryptoJS .enc.Hex.parse("hexkey") / .enc.Base64.parse("b64key") — group(1) = key material.
    // Used to pass raw hex/base64 keys to CryptoJS.AES.encrypt/decrypt instead of a passphrase.
    public static final Pattern CRYPTOJS_ENC_PARSE = Pattern.compile(
            "(?i)CryptoJS\\.enc\\.(?:Hex|Base64|Utf8)\\.parse\\s*\\(\\s*[\"']([^\"']{8,})[\"']");

    // jwt.sign / jsonwebtoken.sign hardcoded secret — group(1) = signing secret string literal.
    // Covers: jwt.sign(payload, "SECRET"), jsonwebtoken.sign(payload, "SECRET", {algorithm:...})
    // Requires the second argument to be a string literal (not a variable reference).
    // Min 8 chars to avoid matching empty / placeholder secrets.
    public static final Pattern JWT_SIGN_SECRET = Pattern.compile(
            "(?i)(?:jsonwebtoken|jwt)\\.sign\\s*\\([^,]{1,200},\\s*[\"']([^\"']{8,})[\"']");

    // process.env.X || "fallback" — group(1) = fallback value when env var is absent.
    // This is the most common way secrets leak into client bundles: developers set a "safe
    // default" that becomes the real secret in non-configured environments.
    // Covers: process.env.SECRET_KEY || "value", process.env.API_KEY ?? "value"
    public static final Pattern ENV_FALLBACK = Pattern.compile(
            "(?i)process\\.env\\.[A-Za-z0-9_]{2,60}\\s*(?:\\|\\||\\?\\?)\\s*[\"']([^\"']{8,})[\"']");

    // Node.js crypto.createCipheriv / createDecipheriv hardcoded key.
    // group(1) = key literal (string or Buffer.from("...") argument).
    // Only fires when the key argument is a string literal.
    public static final Pattern CRYPTO_CIPHERIV = Pattern.compile(
            "(?i)crypto\\.create(?:Cipher|Decipher)iv\\s*\\([^,\"']{0,40},\\s*" +
            "(?:Buffer\\.from\\s*\\(\\s*)?[\"']([^\"']{8,})[\"']");

    // =========================================================================
    // GENERIC PATTERNS
    // =========================================================================

    // Exclude JSON boundary characters from user/pass groups to avoid cross-boundary matches
    // e.g. prevents matching password=""care"` from React env-var blocks in minified JSON
    public static final Pattern URL_WITH_CREDS       = Pattern.compile(
            "(?i)\\bhttps?://([^/\\s:@\"'{}]*):([^/\\s@\"'{}]+)@([A-Za-z0-9.\\-]+)");

    // Credentials embedded as URL query parameters — ?username=X&password=Y or ?user=X&pass=Y
    // Catches hardcoded credentials in config files and commented-out URLs.
    public static final Pattern URL_QUERY_CREDS      = Pattern.compile(
            "(?i)\\bhttps?://[^\\s\"'<>{}]+?[?&](?:password|passwd|pwd|pass|pword)=([^&\\s\"'<>{}#]{4,})");

    // Same as above but works on relative-path and HTML-attribute-embedded URLs that have no
    // https:// prefix (e.g. <frame src="index.php?password=..."> or &amp;-separated params).
    // Minimum value length 20 avoids FPs on short IDs/codes.
    public static final Pattern BARE_QUERY_CREDS     = Pattern.compile(
            "(?i)(?:&amp;|[?&])(?:password|passwd|pwd|pass|pword)=([^&\\s\"'<>{}#]{20,})");

    // user may be empty (redis://:pass@host); the password may contain '/' and ':'
    public static final Pattern DB_CONN_STRING       = Pattern.compile(
            "(?i)\\b(mongodb(?:\\+srv)?|postgres(?:ql)?(?:\\+[a-z0-9]+)?|mysql(?:\\+[a-z0-9]+)?|mariadb|mssql|sqlserver|" +
            "redis|rediss|amqps?|jdbc:[a-z]+(?::[a-z]+)?|ftps?|sftp|smtps?|ldaps?|wss?|memcached|cassandra|couchbase|" +
            "neo4j(?:\\+s)?|nats|kafka|clickhouse|oracle)://" +
            "([^/\\s:@\"'<>]{0,100}):([^\\s@\"'<>]{1,200})@([A-Za-z0-9.\\-_]{3,})");

    /** ADO.NET string whose Password comes before the other pairs: "Password=x;Server=...;User ID=..." */
    public static final Pattern DOTNET_CONN_PWD_FIRST = Pattern.compile(
            "(?i)(?:^|[;\"'\\s=])(?:password|pwd)\\s*=\\s*(\\{[^}\\r\\n]{1,200}\\}|[^;\"'\\r\\n]{4,200}?)\\s*;" +
            "(?=[^\"'\\r\\n]{0,300}?(?:server|data source|user id|uid|initial catalog|database|host)\\s*=)");

    /** Secrets passed as URL query parameters (other than passwords, which URL_QUERY_CREDS covers). */
    public static final Pattern URL_QUERY_SECRET     = Pattern.compile(
            "(?i)(?:&amp;|[?&])(api[_\\-]?key|apikey|access[_\\-]?token|auth[_\\-]?token|client[_\\-]?secret|" +
            "secret[_\\-]?key|private[_\\-]?token|app[_\\-]?secret|api[_\\-]?secret)=([^&\\s\"'<>{}#]{16,512})");

    // =========================================================================
    // PII PATTERNS
    // =========================================================================

    public static final Pattern SSN                  = Pattern.compile(
            "\\b(?!000|666|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0000)\\d{4}\\b");

    public static final Pattern SSN_CONTEXT          = Pattern.compile(
            // sin / tin only as a key ("sin": ..., tin=...): bare words match Math.sin and "tin can"
            "(?i)\\b(ssn|social[_\\-]?security([_\\-]?number)?|sin(?=[\"']?\\s*[:=])|" +
            "tax[_\\-]?id(entification)?|tin(?=[\"']?\\s*[:=])|itin|national[_\\-]?id([_\\-]?number)?" +
            "|govt[_\\-]?id|government[_\\-]?id|fiscal[_\\-]?number)\\b");

    /** Combined CC candidate — run Luhn after match to eliminate FPs */
    public static final Pattern CC_CANDIDATE         = Pattern.compile(
            "\\b(?:4[0-9]{12}(?:[0-9]{3})?" +
            "|(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}" +
            "|3[47][0-9]{13}" +
            "|6(?:011|5[0-9]{2})[0-9]{12}" +
            "|3(?:0[0-5]|[68][0-9])[0-9]{11}" +
            "|(?:2131|1800|35\\d{3})\\d{11})\\b");

    // =========================================================================
    // SSR STATE BLOBS (Next.js, Nuxt, Redux)
    // =========================================================================

    public static final Pattern NEXT_DATA            = Pattern.compile(
            "window\\.__(?:NEXT_DATA__|INITIAL_STATE__|REDUX_STATE__|APP_STATE__|" +
            "PRELOADED_STATE__|NUXT__)\\s*=\\s*(\\{.*?\\})\\s*;",
            Pattern.DOTALL);

    // =========================================================================
    // GENERIC KEY=VALUE
    // =========================================================================

    // Group 1 = quoted key (may contain spaces, e.g. "User ID"), group 2 = unquoted key, group 3 = value.
    // Quoted keys allow up to 2 internal spaces so "User ID", "App Secret Key" etc. are captured.
    // The unquoted key may only start at an identifier boundary and is matched possessively:
    // without that, every position inside a long unbroken string was retried (quadratic time).
    public static final Pattern GENERIC_KV           = Pattern.compile(
            // groups: 1 = quoted key (also obj['x-api-key'] = ...), 2 = bare key, 3 = quote, 4 = value.
            // The value runs to the same quote it opened with, so it may contain the other quote
            // character; backtick template literals count (values holding ${...} are rejected later).
            "(?i)(?:[\"']([A-Za-z0-9_\\-]+(?:\\s[A-Za-z0-9_\\-]+){0,2})[\"']\\]?|(?<![A-Za-z0-9_\\-])([A-Za-z0-9_\\-]++))\\s*[:=]\\s*([\"'`])((?:(?!\\3)[^\\r\\n]){6,500}+)\\3");

    /** XML element value extractor — matches &lt;tagName&gt;value&lt;/tagName&gt; in API responses. */
    public static final Pattern XML_ELEMENT          = Pattern.compile(
            "<([A-Za-z][A-Za-z0-9_\\-]{1,49})(?:\\s[^>]*)?>([^<]{4,})<\\/\\1>");

    public static final Pattern NOISE_KEYNAMES       = Pattern.compile(
            "(?i)^(class|classname|cellclass|headername|tooltip|placeholder|label|title|" +
            "description|desc|message|text|subject|applicationname|module|component|" +
            "template|style|font|icon|filterby|weekdays|months|rfc1123|locale|" +
            "format|date|time|color|colour|width|height|size|margin|padding)$" +
            // Keys whose suffix indicates UI strings, validation patterns, policy text, or hostnames — never credentials
            "|(?i)^.+(?:msg|errormsg|regex|pattern|policy|caption|hint|domain|url|uri|host|path|endpoint|baseurl|homepage|website)$" +
            // Keys whose suffix indicates a type discriminator, error label, or state enum — never credential holders
            // e.g., CredentialType, TokenError, KeyState, SecretKind
            "|(?i)^.+(?:type|error|state|kind|thumbprint)$" +
            // Angular/webpack bundle chunk manifest keys: file-path-derived keys mapping to build content hashes.
            // e.g. src_app_modules_news-resource-center_newsresourcecenter_module_ts
            "|(?i)^.+[_-](?:module|component|service|directive|pipe|guard|resolver|interceptor|factory|effect|reducer)[_-](?:ts|js)$");

    public static final Pattern REAL_SECRET_KEYNAME  = Pattern.compile(
            "(?i)(api[_\\-]?key|apikey|app[_\\-]?key|appkey|app[_\\-]?secret|appsecret|" +
            "api[_\\-]?(?:token|secret)|" +                         // apiToken, api_token, apiSecret, api_secret
            "consumer[_\\-]?(?:key|token|secret)|" +                // consumerKey, consumer_secret (OAuth 1.0)
            "session[_\\-]?(?:key|token|secret)|" +                 // sessionKey, session_key (fills gap with session_token)
            "client[_\\-]?secret|client[_\\-]?key|" +
            "access[_\\-]?token|auth[_\\-]?token|id[_\\-]?token|" +
            "secret[_\\-]?key|private[_\\-]?key|signing[_\\-]?key|master[_\\-]?key|" +
            "bearer|credential|\\bauthorization\\b|" +
            "ocp[_\\-]?apim[_\\-]?subscription[_\\-]?key|subscription[_\\-]?key|" +
            "refresh[_\\-]?token|service[_\\-]?account|x[_\\-]?api[_\\-]?key|" +
            "instrumentation[_\\-]?key|connection[_\\-]?string|resource[_\\-]?key|" +
            "tenant[_\\-]?secret|apim[_\\-]?key|app[_\\-]?id|appid|" +
            "jwt[_\\-]?token|payment[_\\-]?(?:key|token|secret)|" +
            "ssh[_\\-]?(?:key|password)|" +                         // sshKey, ssh_key, ssh_password
            "aws[_\\-]?secret(?:[_\\-]?access[_\\-]?key)?|" +       // aws_secret, aws_secret_access_key
            "encrypt(?:ion)?[_\\-]?(?:key|secret)|" +               // encryptionKey, encrypt_key
            "decrypt(?:ion)?[_\\-]?(?:key|secret)|" +               // decryptionKey, decrypt_key
            "encrypted[_\\-]?env(?:[_\\-]?(?:string|blob|data|config))?|" + // encryptedEnvString, encrypted_env_blob
            "crypto[_\\-]?(?:js[_\\-]?)?(?:secret[_\\-]?)?key|" +  // cryptoJsSecretKey, cryptoKey
            "apim[_\\-]?subscription[_\\-]?key|" +                  // apimSubscriptionKey (explicit)
            "github[_\\-]?(?:token|key|secret)|" +                  // github_token as variable name
            "slack[_\\-]?(?:token|key)|" +                          // slack_token as variable name
            "(?:db|database|admin|root)[_\\-]?(?:password|pass(?:word)?)|" + // db_password, admin_password
            "(?:app|service)[_\\-]?password|" +
            "(?:smtp|mail|imap|pop3|ftp|sftp|ldap)[_\\-]?(?:user(?:name)?|pass(?:word)?|login|auth(?:entication)?)|" +
            "cbk[_\\-]?(?:app[_\\-]?id|appid|safe[_\\-]?id|safeid|key|url|object[_\\-]?id)|" + // CyberArk AIM config keys (cbkAppId, cbkSafeId, cbkKey, cbkUrl)
            "cyberark[_\\-]?(?:app[_\\-]?id|safe|key|url|credential|token|password|account))"); // CyberArk generic keys

    public static final Pattern BLOCKCHAIN_HASH_KEY  = Pattern.compile(
            "(?i)\\b(tx(?:id|hash)|txn?|transaction|block(?:hash|id)|eth|wallet|address)\\b");

    // =========================================================================
    // HIGH-ENTROPY SCANNER PATTERNS
    // =========================================================================

    /**
     * Finds any quoted string 20–512 chars composed of token-safe characters.
     * Used by scanHighEntropyValues() — combined with hasHighEntropy() and a
     * context-keyword check to distinguish real secrets from prose.
     */
    public static final Pattern QUOTED_LONG_VALUE    = Pattern.compile(
            "[\"']([A-Za-z0-9_.+=|?#~@!$%^&*/-]{20,512})[\"']");

    /**
     * Context keywords that signal a nearby value may be a secret.
     * Must appear within ±80 chars of a QUOTED_LONG_VALUE match.
     */
    public static final Pattern ENTROPY_CONTEXT_KW   = Pattern.compile(
            "(?i)\\b(api[_\\-]?key|apikey|app[_\\-]?key|appkey|app[_\\-]?secret|" +
            "api[_\\-]?(?:token|secret)|" +
            "consumer[_\\-]?(?:key|token|secret)|" +
            "access[_\\-]?token|auth[_\\-]?token|id[_\\-]?token|" +
            "subscription[_\\-]?key|apim[_\\-]?key|apim[_\\-]?secret[_\\-]?key|x[_\\-]?api[_\\-]?key|" +
            "client[_\\-]?secret|private[_\\-]?key|bearer[_\\-]?token|" +
            "credential|payment[_\\-]?(?:key|token|secret)|jwt[_\\-]?token|" +
            "aws[_\\-]?secret|ssh[_\\-]?key|password|passwd|secret|" +
            "encrypt(?:ion)?[_\\-]?(?:key|secret)|decrypt(?:ion)?[_\\-]?(?:key|secret)|" +
            "encrypted[_\\-]?env|crypto[_\\-]?(?:js)?[_\\-]?(?:secret)?[_\\-]?key|" +
            "apim[_\\-]?subscription[_\\-]?key|" +
            // Standalone crypto operation keywords: AES/HMAC/cipher function calls and library
            // references indicate the surrounding code performs cryptographic operations —
            // nearby high-entropy hex values are likely key material, not analytics IDs or hashes.
            "AES|HMAC|CryptoJS|\\bcipher\\b|\\bdecipher\\b|crypto\\.subtle|SubtleCrypto)\\b");

    /**
     * Crypto operation keyword pattern — used for hex-guard exceptions in secret scanners.
     * A wider ±200-char window is used compared to ENTROPY_CONTEXT_KW's ±80 chars, since
     * minified JS bundles may separate a hex key literal from its encryption call site by
     * 100+ characters.
     * Matches: encrypt/decrypt function names, AES/HMAC cipher names, CryptoJS library calls,
     * Web Crypto API references, and cipher/decipher patterns.
     */
    public static final Pattern CRYPTO_OP_PATTERN = Pattern.compile(
            "(?i)\\b(encrypt|decrypt|\\bAES\\b|\\bHMAC\\b|CryptoJS|cipher|decipher|" +
            "crypto\\.subtle|SubtleCrypto|hmacSHA|pbkdf2|bcrypt|scrypt)\\b");

    /**
     * Extracts the last key name immediately before a value assignment
     * on the same line (used for key name recovery in entropy scanner).
     */
    public static final Pattern KEY_BEFORE_VALUE     = Pattern.compile(
            "([A-Za-z][A-Za-z0-9_\\-]{2,50})[\"']?\\]?\\s*[:=]\\s*[\"'`]?\\s*$");

    // =========================================================================
    // FORCED NOISE KEYS — exact lowercase match, bypass all other checks
    // =========================================================================

    public static final Set<String> FORCED_NOISE_KEYS = Set.of(
            // Generic bare field names — too broad to signal any specific secret
            "key", "keys", "value", "values", "name", "names",
            "id", "ids", "code", "codes", "flag", "flags",
            "type", "types", "format", "formats", "scope", "scopes",
            "tag", "tags", "label", "labels", "group", "groups",
            "status", "state", "result", "results", "data",
            // OAuth / OIDC flow params — values are URLs or short codes, never long secrets
            "success", "error_description",
            "traceid", "trace_id", "correlationid", "correlation_id",
            "requestid", "request_id", "apiurl", "api_url",
            "apiendpoint", "api_endpoint", "endpoint", "baseurl", "base_url",
            "serviceurl", "service_url", "callback_url", "callbackurl",
            "redirect_url", "redirecturl", "redirecturi", "redirect_uri",
            "client_id", "tenant_id",
            "csrf", "csrftoken", "xsrf", "xsrftoken",
            "x-csrf-token", "x-xsrf-token", "xsrf-token", "csrf-token",
            "_csrf", "csrfmiddlewaretoken", "__requestverificationtoken",
            "antiforgerytoken", "antiforgery", "requestverificationtoken",
            // OAuth2 / Azure AD flow params — values are resource URIs or GUIDs.
            // "resource" bare key is intentionally NOT suppressed here so that GUID values
            // (e.g. Resource:"286cd9a2-...") are reported as INFORMATION (Azure recon).
            // "resource_id" / "resourceid" intentionally NOT suppressed — GUID gate in scanGenericKV
            // handles them via isAzureCredentialKey() so Resource_ID:"025ad63a-..." is reported.
            "anonymous_id", "anonymousid", "anon_id", "device_id", "deviceid",
            "telemetryservertoken", "telemetry_server_token",
            "productid", "product_id", "categoryid", "category_id",
            "itemid", "item_id", "ruleid", "rule_id", "processingid",
            "renderkey", "render_key", "version", "build", "revision",
            // UI / framework event/state identifiers — not secrets
            "alertkey", "alert_key", "instancekey", "instance_key",
            "castingkey", "casting_key", "displaykey", "display_key",
            "sortkey", "sort_key", "filterkey", "filter_key",
            "pagekey", "page_key", "cachekey", "cache_key",
            "routekey", "route_key", "menukey", "menu_key",
            "tabkey", "tab_key", "panelkey", "panel_key",
            "listkey", "list_key", "rowkey", "row_key", "colkey", "col_key",
            "nodekey", "node_key", "treekey", "tree_key", "leafkey", "leaf_key",
            "eventkey", "event_key", "actionkey", "action_key",
            "widgetkey", "widget_key", "componentkey", "component_key",
            // MSAL / ADAL library constant key names
            "interaction_status_key", "interactionstatuskey",
            "acquire_token_start", "acquiretokenstart",
            "acquire_token_success", "acquiretokensuccess",
            "acquire_token_failure", "acquiretokenfailure",
            "adal_id_token", "adalidtoken",
            "adal_error", "adalerror",
            // OIDC / OAuth 2.0 discovery document fields — values are URLs, never secrets
            "issuer", "token_endpoint", "authorization_endpoint",
            "end_session_endpoint", "jwks_uri", "userinfo_endpoint",
            "device_authorization_endpoint", "registration_endpoint",
            "introspection_endpoint", "revocation_endpoint",
            "check_session_iframe", "frontchannel_logout_uri",
            "backchannel_logout_uri",
            // Miscellaneous identifiers from common FP patterns
            "response_type", "grant_type", "token_type",
            "nonce", "iss", "sub", "aud", "exp", "iat", "jti",
            // Firebase / Google SDK config fields — values are project identifiers, not secrets
            "authdomain", "auth_domain", "projectid", "project_id",
            "storagebucket", "storage_bucket", "messagingsenderid", "messaging_sender_id",
            "databaseurl", "database_url",
            // Application Insights SDK constants — format strings / SDK identifiers, not secrets
            "requestcontextappidformat", "requestcontexttargetkey", "requestidheader",
            "sdkextension", "sdkversion", "instrumentationkey",
            // Session identifiers — ephemeral per-user values, not reusable credentials
            "sessionid", "session_id", "jsessionid", "phpsessid", "asp.net_sessionid",
            "sessid", "sess_id", "sessionstate", "session_state",
            // Organization identifiers — public client-side IDs, never secrets
            // e.g. Adobe orgId: "48B564D85E5D2CDD0A495CF8@AdobeOrg"
            "orgid", "org_id"
    );

    // =========================================================================
    // HTML PARSING — inline script extraction and script-src following
    // =========================================================================

    /** Matches <script src="..."> or <script src='...'> — captures the src value. */
    public static final Pattern SCRIPT_SRC = Pattern.compile(
            "<script[^>]{1,4096}\\bsrc\\s*=\\s*(?:[\"']([^\"'\\s>]+)[\"']|([^\"'\\s>]+))[^>]{0,4096}>",
            Pattern.CASE_INSENSITIVE);

    // INLINE_SCRIPT: replaced by core.ScriptBlocks (linear time on malformed HTML)

    /**
     * Matches {@code <frame src="...">} and {@code <iframe src="...">} tags.
     * Captures the src value in group 1.  Used to follow classic frameset pages
     * where the real content (and its &lt;script src&gt; references) lives in a child frame.
     */
    public static final Pattern FRAME_SRC = Pattern.compile(
            "<i?frame[^>]{1,4096}\\bsrc\\s*=\\s*[\"']([^\"'\\s>]+)[\"'][^>]{0,4096}>",
            Pattern.CASE_INSENSITIVE);

    /**
     * Matches JS-based page redirects that cannot be followed by static HTML parsing:
     *   window.location = "/path"
     *   window.location.href = "/path"
     *   document.location = "/path"
     *   location.replace("/path")  /  location.assign("/path")
     * Captures the target URL in group 1.
     */
    public static final Pattern JS_REDIRECT = Pattern.compile(
            "(?:window\\.location(?:\\.href)?|document\\.location(?:\\.href)?|location\\.(?:href|replace|assign))\\s*[=(]\\s*[\"']([^\"'\\r\\n]{1,300})[\"']",
            Pattern.CASE_INSENSITIVE);

    /**
     * Matches {@code <meta http-equiv="refresh" content="N; url=...">} redirects.
     * Uses a lookahead so both attribute orderings are supported:
     *   {@code <meta http-equiv="refresh" content="0; url=...">}
     *   {@code <meta content="0; url=..." http-equiv="refresh">}
     * Captures the target URL in group 1.
     */
    public static final Pattern META_REFRESH = Pattern.compile(
            "<meta\\b(?=[^>]{0,4096}\\bhttp-equiv\\s*=\\s*[\"']refresh[\"'])[^>]{0,4096}\\bcontent\\s*=\\s*[\"'][^\"']*\\burl\\s*=\\s*([^\"'\\s>][^\"']{0,300})[\"']",
            Pattern.CASE_INSENSITIVE);

    /**
     * Matches hostname-concatenation redirects like:
     *   {@code window.location.href = 'https://' + window.location.hostname + '/path/'}
     *   {@code location.href = "https://" + location.hostname + "/app"}
     * The path portion (group 1) is resolved relative to the page's base URL,
     * producing the same-host target URL.
     */
    public static final Pattern JS_REDIRECT_HOSTNAME = Pattern.compile(
            "(?:window\\.|document\\.)?location(?:\\.href)?\\s*=\\s*[\"']https?://[\"']\\s*\\+\\s*(?:window\\.)?(?:document\\.)?location\\.hostname\\s*\\+\\s*[\"']([^\"'\\r\\n]{1,200})[\"']",
            Pattern.CASE_INSENSITIVE);

    /** Webpack / Next.js / Vite chunk file references embedded in JS bundles. */
    public static final Pattern WEBPACK_CHUNK_REF = Pattern.compile(
            // any quoted relative or absolute path to a .js / .mjs file (webpack, Vite assets/, Next _next/,
            // Nuxt _nuxt/), optionally with a query string
            "[\"'`]((?:\\.{0,2}/)?(?:[A-Za-z0-9_@~.\\-]+/){0,12}[A-Za-z0-9_@~.\\-]+\\.m?js)(?:\\?[^\"'`\\s]{0,80})?[\"'`]");

    /**
     * Matches &lt;link rel="preload" as="script" href="..."&gt; in either attribute order.
     * Used to discover JS chunks that are eagerly preloaded by SPAs.
     */
    public static final Pattern PRELOAD_JS_LINK = Pattern.compile(
            "<link(?=[^>]{0,4096}(?:\\bas\\s*=\\s*[\"']?script|\\brel\\s*=\\s*[\"']?modulepreload))[^>]{0,4096}\\bhref\\s*=\\s*[\"']?([^\"'\\s>]+)[\"']?[^>]{0,4096}/?>",
            Pattern.CASE_INSENSITIVE);

    // JSON_SCRIPT_TAG: replaced by core.ScriptBlocks (linear time on malformed HTML)

    /**
     * Extended SPA config state patterns beyond the standard Next/Redux dunders.
     * Catches: window.__CONFIG__ = {...}, window._env_ = {...},
     *          window.appConfig = {...}, window.serverData = {...}, etc.
     * group 1 = the JSON object body.
     */
    public static final Pattern GENERIC_WINDOW_CONFIG = Pattern.compile(
            "(?:window|self|globalThis)\\." +
            "(?:__[A-Za-z][A-Za-z0-9_]*__|_[A-Za-z][A-Za-z0-9_]*_|" +
            "ENV|[A-Za-z][A-Za-z0-9]*(?:Config|Settings|Env|Data|State|Constants|Vars|Props))\\s*=" +
            "\\s*(\\{[\\s\\S]{20,5000}?\\})\\s*[;,]",
            Pattern.DOTALL);

    // =========================================================================
    // GETTER FUNCTION RETURN VALUE PATTERNS (JS-specific, FULL tier)
    // Catches runtime-assembled keys that appear only as function return values —
    // invisible to the anchored-token and generic KV scanners. Mirrors Python's
    // RE_ARROW_SHORT_RETURN / RE_ARROW_BLOCK_RETURN / RE_NAMED_FUNC_RETURN passes.
    // No DOTALL — bounded patterns prevent catastrophic backtracking on minified JS.
    // =========================================================================

    /**
     * Arrow function with immediate return: const getApiKey = () => 'VALUE'
     * Group 1 = variable name, Group 2 = return value.
     */
    public static final Pattern GETTER_ARROW_SHORT = Pattern.compile(
            "(?:const|let|var)\\s+([A-Za-z_$][A-Za-z0-9_$]+)\\s*=\\s*" +
            "\\([^)\\n]{0,60}\\)\\s*=>\\s*[\"']([A-Za-z0-9_.+=|?#~@!$%^&*/\\-]{20,512})[\"']",
            Pattern.CASE_INSENSITIVE);

    /**
     * Block arrow or named function with inline return:
     *   const getApiKey = function() { return 'VALUE'; }
     *   const getApiKey = () => { return 'VALUE'; }
     * Group 1 = variable name, Group 2 = return value.
     * Function body capped to 300 chars (including newlines) to prevent backtracking.
     */
    public static final Pattern GETTER_FUNC_RETURN = Pattern.compile(
            "(?:const|let|var)\\s+([A-Za-z_$][A-Za-z0-9_$]+)\\s*=\\s*" +
            "(?:\\([^)\\n]{0,60}\\)\\s*=>|function\\s*(?:[A-Za-z_$][A-Za-z0-9_$]*)?\\s*\\([^)\\n]{0,60}\\))\\s*" +
            "\\{[^{}]{0,300}?return\\s+[\"']([A-Za-z0-9_.+=|?#~@!$%^&*/\\-]{20,512})[\"']",
            Pattern.CASE_INSENSITIVE);

    // =========================================================================
    // FALSE-POSITIVE REDUCTION — framework attributes + template expressions
    // =========================================================================

    /**
     * Framework attribute prefixes: keys starting with these are UI framework
     * directives (Angular, Vue, Alpine.js) — not secrets.
     */
    public static final Set<String> FRAMEWORK_ATTR_PREFIXES = Set.of(
            "ng-", "v-", "v-on:", "v-bind:", "x-on:", "x-bind:", "data-ng-",
            "data-v-", "wire:", ":class", ":style", "@click", "@keyup",
            "@keydown", "@change", "@input", "@submit");

    /**
     * Matches framework runtime / template expressions used as values:
     * $event, $index, {{ expr }}, ${var}, @{expr} — these are runtime references,
     * never actual secrets.
     */
    public static final Pattern TEMPLATE_EXPR = Pattern.compile(
            "^\\$[a-zA-Z_$][\\w.]*$|^\\{\\{.*\\}\\}$|^\\$\\{[^}]+\\}$|" +
            "^@\\{[^}]+\\}$|^#\\{[^}]+\\}$");

    // =========================================================================
    // ANCHORED RULES TABLE — iterated in SecretScanner.scanAnchoredTokens()
    // =========================================================================

    public record AnchoredRule(
            Pattern pattern,
            String  keyName,
            String  ruleId,
            String  ruleName,
            String  severity,  // "HIGH" or "MEDIUM" — Montoya has no CRITICAL
            List<String> keywords  // prefilter keywords (lowercase); empty = always run
    ) {}

    // =========================================================================
    // CONTEXT-GATED RULES — keyword must appear near the value to match
    // =========================================================================

    public record CtxRule(
            java.util.regex.Pattern pattern,
            int    captureGroup,
            String keyName,
            String ruleId,
            String ruleName,
            String severity,
            List<String> keywords  // prefilter keywords (lowercase); empty = always run
    ) {}

    // =========================================================================
    // ACTIVE RULE TABLES — read by SecretScanner
    // =========================================================================

    /** Built-in rule files on the classpath, in evaluation order. */
    public static final String ANCHORED_RULES_RESOURCE = "/rules/builtin-anchored.yaml";
    public static final String CONTEXT_RULES_RESOURCE  = "/rules/builtin-context.yaml";

    /** Anchored rules the scanner evaluates, loaded from {@link #ANCHORED_RULES_RESOURCE}. */
    public static final List<AnchoredRule> ANCHORED_RULES = loadAnchoredRules();

    /** Context-gated rules the scanner evaluates, loaded from {@link #CONTEXT_RULES_RESOURCE}. */
    public static final List<CtxRule> CONTEXT_GATED_RULES = loadContextRules();

    /** Keyword prefilter over {@link #ANCHORED_RULES}, by list index. */
    public static final com.secretscanner.rules.KeywordPrefilter ANCHORED_PREFILTER =
            new com.secretscanner.rules.KeywordPrefilter(ANCHORED_RULES.stream().map(AnchoredRule::keywords).toList());

    /** Keyword prefilter over {@link #CONTEXT_GATED_RULES}, by list index. */
    public static final com.secretscanner.rules.KeywordPrefilter CONTEXT_PREFILTER =
            new com.secretscanner.rules.KeywordPrefilter(CONTEXT_GATED_RULES.stream().map(CtxRule::keywords).toList());

    /**
     * Prefilter keywords for a rule: the YAML {@code keywords} if given, otherwise literals derived
     * from the regex that every match must contain (see RequiredLiterals).
     */
    static List<String> keywordsFor(com.secretscanner.rules.RuleDef r) {
        if (!r.keywords().isEmpty())
            return r.keywords().stream().map(k -> k.toLowerCase(java.util.Locale.ROOT)).toList();
        return com.secretscanner.rules.RequiredLiterals.of(r.pattern());
    }

    /** Returns the compiled pattern of the built-in rule with this id. */
    public static Pattern rulePattern(String ruleId) {
        for (AnchoredRule r : ANCHORED_RULES) if (r.ruleId().equals(ruleId)) return r.pattern();
        for (CtxRule r : CONTEXT_GATED_RULES) if (r.ruleId().equals(ruleId)) return r.pattern();
        throw new IllegalArgumentException("no built-in rule with id " + ruleId);
    }

    /** Loads the anchored rule table from its YAML file. */
    public static List<AnchoredRule> loadAnchoredRules() {
        return com.secretscanner.rules.RuleLoader.loadResource(ANCHORED_RULES_RESOURCE).stream()
                .map(r -> {
                    if (r.kind() != com.secretscanner.rules.RuleDef.Kind.ANCHORED || r.group() != 0)
                        throw new IllegalStateException(r.id() + ": anchored rule file holds a non-anchored rule");
                    return new AnchoredRule(r.pattern(), r.key(), r.id(), r.name(), r.severity(), keywordsFor(r));
                })
                .toList();
    }

    /** Loads the context-gated rule table from its YAML file. */
    public static List<CtxRule> loadContextRules() {
        return com.secretscanner.rules.RuleLoader.loadResource(CONTEXT_RULES_RESOURCE).stream()
                .map(r -> {
                    if (r.kind() != com.secretscanner.rules.RuleDef.Kind.CONTEXT)
                        throw new IllegalStateException(r.id() + ": context rule file holds a non-context rule");
                    return new CtxRule(r.pattern(), r.group(), r.key(), r.id(), r.name(), r.severity(), keywordsFor(r));
                })
                .toList();
    }
}
