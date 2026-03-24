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

    public static final Pattern GITHUB_PAT_CLASSIC   = Pattern.compile("\\bghp_[A-Za-z0-9]{36}\\b");
    public static final Pattern GITHUB_OAUTH         = Pattern.compile("\\bgho_[A-Za-z0-9]{36}\\b");
    public static final Pattern GITHUB_ACTIONS       = Pattern.compile("\\bghs_[A-Za-z0-9]{36}\\b");
    public static final Pattern GITHUB_REFRESH       = Pattern.compile("\\bghr_[A-Za-z0-9]{76}\\b");
    public static final Pattern GITHUB_FINE_PAT      = Pattern.compile("\\bgithub_pat_[A-Za-z0-9_]{82}\\b");

    public static final Pattern GITLAB_PAT           = Pattern.compile("\\bglpat-[A-Za-z0-9\\-_]{20}\\b");
    public static final Pattern GITLAB_DEPLOY        = Pattern.compile("\\bgldt-[A-Za-z0-9\\-_]{20}\\b");

    public static final Pattern NPM_TOKEN            = Pattern.compile("\\bnpm_[A-Za-z0-9]{36}\\b");

    public static final Pattern SLACK_BOT            = Pattern.compile(
            "\\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}\\b");
    public static final Pattern SLACK_USER           = Pattern.compile(
            "\\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{32}\\b");
    public static final Pattern SLACK_APP            = Pattern.compile("\\bxapp-\\d+-[A-Za-z0-9]{24,}\\b");
    public static final Pattern SLACK_CONFIG         = Pattern.compile("\\bxoxe\\.[A-Za-z0-9\\-_]{140,}\\b");

    public static final Pattern STRIPE_SECRET_LIVE   = Pattern.compile("\\bsk_live_[A-Za-z0-9]{24,99}\\b");
    public static final Pattern STRIPE_SECRET_TEST   = Pattern.compile("\\bsk_test_[A-Za-z0-9]{24,99}\\b");
    public static final Pattern STRIPE_RESTRICTED    = Pattern.compile("\\brk_live_[A-Za-z0-9]{24,99}\\b");

    public static final Pattern SENDGRID             = Pattern.compile(
            "\\bSG\\.[A-Za-z0-9\\-_]{22}\\.[A-Za-z0-9\\-_]{43}\\b");

    public static final Pattern TWILIO_SID           = Pattern.compile("\\bAC[a-f0-9]{32}\\b");

    public static final Pattern OPENAI_KEY           = Pattern.compile("\\bsk-[A-Za-z0-9]{48}\\b");
    public static final Pattern OPENAI_PROJECT       = Pattern.compile(
            "\\bsk-proj-[A-Za-z0-9\\-_]{48,120}\\b");
    public static final Pattern ANTHROPIC_KEY        = Pattern.compile(
            "\\bsk-ant-api\\d{2}-[A-Za-z0-9\\-_]{93,}\\b");

    public static final Pattern SHOPIFY_TOKEN        = Pattern.compile("\\bshpat_[a-fA-F0-9]{32}\\b");
    public static final Pattern SHOPIFY_SECRET       = Pattern.compile("\\bshpss_[a-fA-F0-9]{32}\\b");
    public static final Pattern SHOPIFY_CUSTOM       = Pattern.compile("\\bshpca_[a-fA-F0-9]{32}\\b");

    public static final Pattern HUBSPOT_TOKEN        = Pattern.compile(
            "\\bpat-[a-z]{2,3}-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\\b");
    public static final Pattern MAILCHIMP            = Pattern.compile("\\b[a-f0-9]{32}-us\\d{1,2}\\b");
    public static final Pattern DATABRICKS           = Pattern.compile("\\bdapi[a-f0-9]{32}\\b");

    public static final Pattern GOOGLE_KEY           = Pattern.compile("AIza[0-9A-Za-z_\\-]{35}");
    // Covers all IAM principal key ID prefixes: AKIA (user), ASIA (session), AROA (role), AIDA (group)
    public static final Pattern AWS_ACCESS_KEY       = Pattern.compile("\\b(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}\\b");
    // Mapbox access tokens are always JWTs — their payload starts with "eyJ" (base64-encoded "{").
    // "tk." is a common JS variable/namespace prefix, NOT a Mapbox token prefix — exclude it.
    public static final Pattern MAPBOX               = Pattern.compile("(?:pk|sk)\\.eyJ[A-Za-z0-9_\\-]{20,}");

    public static final Pattern PEM_PRIVATE_KEY      = Pattern.compile(
            "-----BEGIN\\s+(?:RSA\\s+|EC\\s+|DSA\\s+|OPENSSH\\s+)?PRIVATE\\s+KEY-----",
            Pattern.CASE_INSENSITIVE);

    // =========================================================================
    // EXTENDED VENDOR TOKENS
    // =========================================================================

    // HashiCorp Vault service token (hvs. + 90+ base62url chars)
    public static final Pattern VAULT_SERVICE_TOKEN  = Pattern.compile("\\bhvs\\.[A-Za-z0-9_\\-]{90,}\\b");

    // Pulumi access token
    public static final Pattern PULUMI_TOKEN         = Pattern.compile("\\bpul-[a-f0-9]{40}\\b");

    // Linear API key
    public static final Pattern LINEAR_API_KEY       = Pattern.compile("\\blin_api_[A-Za-z0-9]{40}\\b");

    // Notion integration token (old: secret_... / new: ntn_...)
    public static final Pattern NOTION_TOKEN         = Pattern.compile("\\bsecret_[A-Za-z0-9]{43}\\b");
    public static final Pattern NOTION_TOKEN_NEW     = Pattern.compile("\\bntn_[A-Za-z0-9]{38}\\b");

    // Netlify personal access token
    public static final Pattern NETLIFY_TOKEN        = Pattern.compile("\\bnfp_[A-Za-z0-9]{36,}\\b");

    // Firebase FCM server key (AAAA + 7 base62url chars + colon + 140 chars)
    public static final Pattern FIREBASE_FCM_KEY     = Pattern.compile(
            "\\bAAAA[A-Za-z0-9_\\-]{7}:[A-Za-z0-9_\\-]{140}\\b");

    // Airtable Personal Access Token
    public static final Pattern AIRTABLE_PAT         = Pattern.compile(
            "\\bpat[A-Za-z0-9]{14}\\.[A-Za-z0-9]{64}\\b");

    // WooCommerce REST API consumer key / secret
    public static final Pattern WOOCOMMERCE_CK       = Pattern.compile("\\bck_[a-z0-9]{40}\\b");
    public static final Pattern WOOCOMMERCE_CS       = Pattern.compile("\\bcs_[a-z0-9]{40}\\b");

    // Discord bot token (M/N/O prefix + two dot-separated base62url segments)
    public static final Pattern DISCORD_BOT_TOKEN    = Pattern.compile(
            "\\b[MNO][A-Za-z0-9]{23,25}\\.[A-Za-z0-9_\\-]{6}\\.[A-Za-z0-9_\\-]{27,38}\\b");

    // Discord incoming webhook URL
    public static final Pattern DISCORD_WEBHOOK      = Pattern.compile(
            "https://discord(?:app)?\\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9_\\-]{60,68}");

    // Slack incoming webhook URL
    public static final Pattern SLACK_WEBHOOK        = Pattern.compile(
            "https://hooks\\.slack\\.com/services/T[A-Za-z0-9_]{8,11}/B[A-Za-z0-9_]{8,11}/[A-Za-z0-9_]{24}");

    // Twitter/X app bearer token (AAA...AAA + 40–130 mixed chars).
    // Upper bound rejects WebAssembly/binary lookup tables which are hundreds–thousands of A's.
    // Real Twitter bearer tokens are 60–120 chars total.
    public static final Pattern TWITTER_BEARER       = Pattern.compile(
            "\\bAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%_\\-]{40,130}\\b");

    // New Relic license key and Insights insert key
    public static final Pattern NEWRELIC_LICENSE_KEY = Pattern.compile("\\bNRAK-[A-Z0-9]{27}\\b");
    public static final Pattern NEWRELIC_INGEST_KEY  = Pattern.compile("\\bNRII-[A-Za-z0-9_\\-]{32}\\b");

    // Dynatrace API token (dt0 + 2-letter type code + 2 digits + dot + 24 + dot + 64)
    public static final Pattern DYNATRACE_TOKEN      = Pattern.compile(
            "\\bdt0[a-zA-Z]{2}[0-9]{2}\\.[A-Za-z0-9]{24}\\.[A-Za-z0-9]{64}\\b");

    // Telegram bot API token (numeric bot id + :AA + 33-char key)
    public static final Pattern TELEGRAM_BOT_TOKEN   = Pattern.compile(
            "\\b[0-9]{8,10}:AA[A-Za-z0-9_\\-]{33}\\b");

    // Mailgun API key
    public static final Pattern MAILGUN_API_KEY      = Pattern.compile("\\bkey-[a-f0-9]{32}\\b");

    // PagerDuty REST API key (rk.) and user key (uk.)
    public static final Pattern PAGERDUTY_KEY        = Pattern.compile("\\b[ru]k\\.[A-Za-z0-9_\\-]{18}\\b");

    // Age encryption secret key (bech32 encoded)
    public static final Pattern AGE_SECRET_KEY       = Pattern.compile(
            "\\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JNCLHB]{58}\\b");

    // Alibaba Cloud Access Key ID
    public static final Pattern ALIBABA_ACCESS_KEY   = Pattern.compile("\\bLTAI[A-Za-z0-9]{20}\\b");

    // Atlassian API token (ATATT / ATCTT prefix — new format)
    public static final Pattern ATLASSIAN_API_TOKEN  = Pattern.compile(
            "\\b(?:ATATT|ATCTT)[A-Za-z0-9_\\-]{100,250}\\b");

    // Contentful Content Management API token
    public static final Pattern CONTENTFUL_TOKEN     = Pattern.compile(
            "\\bCFPAT-[A-Za-z0-9_\\-]{43}\\b");

    // DigitalOcean personal access token / OAuth token
    public static final Pattern DO_ACCESS_TOKEN      = Pattern.compile("\\bdop_v1_[a-f0-9]{64}\\b");
    public static final Pattern DO_OAUTH_TOKEN       = Pattern.compile("\\bdoo_v1_[a-f0-9]{64}\\b");

    // Doppler service token
    public static final Pattern DOPPLER_TOKEN        = Pattern.compile("\\bdp\\.pt\\.[A-Za-z0-9]{43}\\b");

    // Duffel travel API access token
    public static final Pattern DUFFEL_TOKEN         = Pattern.compile(
            "\\bduffel_(?:test|live)_[A-Za-z0-9_\\-]{43}\\b");

    // EasyPost API keys (live + test)
    public static final Pattern EASYPOST_KEY         = Pattern.compile("\\bEZAK[A-Za-z0-9]{54}\\b");
    public static final Pattern EASYPOST_TEST_KEY    = Pattern.compile("\\bEZTK[A-Za-z0-9]{54}\\b");

    // Flutterwave payment keys (public + secret, with optional _TEST variant)
    public static final Pattern FLUTTERWAVE_PUB      = Pattern.compile(
            "\\bFLWPUBK(?:_TEST)?-[a-fA-F0-9]{32}-X\\b");
    public static final Pattern FLUTTERWAVE_SEC      = Pattern.compile(
            "\\bFLWSECK(?:_TEST)?-[a-fA-F0-9]{32}-X\\b");

    // Frame.io API token
    public static final Pattern FRAMEIO_TOKEN        = Pattern.compile(
            "\\bfio-u-[A-Za-z0-9\\-_=]{64}\\b");

    // Grafana service account token and cloud access token
    public static final Pattern GRAFANA_SA_TOKEN     = Pattern.compile(
            "\\bglsa_[A-Za-z0-9]{32}_[A-Za-z0-9]{8}\\b");
    public static final Pattern GRAFANA_CLOUD_TOKEN  = Pattern.compile("\\bglc_[A-Za-z0-9+/]{32,}\\b");

    // PlanetScale database credentials
    public static final Pattern PLANETSCALE_PW       = Pattern.compile(
            "\\bpscale_pw_[A-Za-z0-9\\-_.]{43}\\b");
    public static final Pattern PLANETSCALE_TOKEN    = Pattern.compile(
            "\\bpscale_tkn_[A-Za-z0-9\\-_.]{43}\\b");

    // Postman API key
    public static final Pattern POSTMAN_API_KEY      = Pattern.compile(
            "\\bPMAK-[a-fA-F0-9]{24}-[A-Za-z0-9]{34}\\b");

    // PyPI upload token
    public static final Pattern PYPI_TOKEN           = Pattern.compile(
            "\\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\\-_]{50,200}\\b");

    // SendinBlue / Brevo API key
    public static final Pattern SENDINBLUE_API_KEY   = Pattern.compile(
            "\\bxkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}\\b");

    // Shippo shipping API token
    public static final Pattern SHIPPO_TOKEN         = Pattern.compile(
            "\\bshippo_(?:live|test)_[a-f0-9]{40}\\b");

    // Azure Storage connection string (very distinctive multi-field format)
    // The character class includes '\' because JSON serialisers often escape '/' as '\/',
    // so the Base64 AccountKey may appear as "abc\/xyz" in raw HTML/JS source text.
    public static final Pattern AZURE_CONN_STR       = Pattern.compile(
            "DefaultEndpointsProtocol=https?;AccountName=[^;]{1,100};AccountKey=[A-Za-z0-9+/=\\\\]{60,}",
            Pattern.CASE_INSENSITIVE);

    // Rubygems API token
    public static final Pattern RUBYGEMS_TOKEN       = Pattern.compile("\\brubygems_[a-f0-9]{48}\\b");

    // ── Additional vendor tokens ───────────────────────────────────────────────

    // Hugging Face user/org API token
    public static final Pattern HUGGINGFACE_TOKEN    = Pattern.compile("\\bhf_[A-Za-z0-9]{34}\\b");

    // Groq API key
    public static final Pattern GROQ_API_KEY         = Pattern.compile("\\bgsk_[A-Za-z0-9]{52}\\b");

    // Replicate API token
    public static final Pattern REPLICATE_API_KEY    = Pattern.compile("\\br8_[A-Za-z0-9]{40}\\b");

    // xAI / Grok API key
    public static final Pattern XAI_API_KEY          = Pattern.compile("\\bxai-[A-Za-z0-9]{80}\\b");

    // Buildkite access token
    public static final Pattern BUILDKITE_TOKEN      = Pattern.compile("\\bbkua_[A-Za-z0-9]{40}\\b");

    // Tailscale API key
    public static final Pattern TAILSCALE_API_KEY    = Pattern.compile("\\btskey-api-[A-Za-z0-9_\\-]{32}\\b");

    // Fly.io bearer token (FlyV1 prefix)
    public static final Pattern FLYIO_AUTH_TOKEN     = Pattern.compile("\\bFlyV1\\s+[A-Za-z0-9+/=_\\-]{40,}");

    // LangSmith / LangChain personal API key
    public static final Pattern LANGSMITH_API_KEY    = Pattern.compile("\\blsv2_pt_[A-Za-z0-9]{47}\\b");

    // Langfuse secret key (sk-lf- + UUID)
    public static final Pattern LANGFUSE_SECRET_KEY  = Pattern.compile(
            "\\bsk-lf-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\b");

    // =========================================================================
    // NEW VENDORS — SecretSifter parity additions
    // =========================================================================

    // Okta SSWS API Token — real format is "SSWS " followed by 40-48 alphanumeric chars
    public static final Pattern OKTA_SSWS_TOKEN      = Pattern.compile("\\bSSWS\\s+[A-Za-z0-9_\\-]{40,48}\\b");

    // CircleCI Personal API Token — "ccipat_" prefix + 40+ alphanumeric chars
    public static final Pattern CIRCLECI_TOKEN       = Pattern.compile("\\bccipat_[A-Za-z0-9]{40,}\\b");

    // Terraform Cloud API Token — "at." prefix + 90+ alphanumeric chars
    public static final Pattern TERRAFORM_CLOUD      = Pattern.compile("\\bat\\.[A-Za-z0-9]{90,}\\b");

    // Sentry Auth Token — "sntrys_" prefix + 64+ alphanumeric chars
    public static final Pattern SENTRY_AUTH_TOKEN    = Pattern.compile("\\bsntrys_[A-Za-z0-9]{64,}\\b");

    // Figma Personal Access Token — "figd_" prefix + 43 chars
    public static final Pattern FIGMA_TOKEN          = Pattern.compile("\\bfigd_[A-Za-z0-9_\\-]{43}\\b");

    // Dropbox Access Token — "sl." prefix + 130+ chars
    public static final Pattern DROPBOX_TOKEN        = Pattern.compile("\\bsl\\.[A-Za-z0-9\\-_]{130,}\\b");

    // Square Access Token — "sq0atp-" prefix + 22+ chars
    public static final Pattern SQUARE_ACCESS_TOKEN  = Pattern.compile("\\bsq0atp-[A-Za-z0-9\\-_]{22,}\\b");

    // Stripe Publishable Key (Live) — informational: confirms live Stripe integration
    public static final Pattern STRIPE_PK_LIVE       = Pattern.compile("\\bpk_live_[A-Za-z0-9]{24,99}\\b");

    // Cloudinary API URL — contains API key + secret embedded in URL
    public static final Pattern CLOUDINARY_URL       = Pattern.compile(
            "cloudinary://[0-9]{6,}:[A-Za-z0-9_\\-]{20,}@[a-z][a-z0-9]{1,}");

    // Microsoft Teams Incoming Webhook URL
    public static final Pattern TEAMS_WEBHOOK        = Pattern.compile(
            "https://[a-z0-9]+\\.webhook\\.office\\.com/webhookb2/[A-Za-z0-9\\-@/]{20,}");

    // JSON Web Token (JWT) — three base64url segments separated by dots
    // Gated by minimum segment lengths to avoid matching short nonces/UUIDs
    public static final Pattern JWT_TOKEN            = Pattern.compile(
            "\\beyJ[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,}\\b");

    // SQL Server / ADO.NET / MySQL semicolon-delimited connection strings
    // Format: "Server=host;Database=db;...;Password=secret" or "Data Source=host;...;Pwd=secret"
    // Captures the password value in group 1.
    // Requires at least one "Key=Value;" pair BEFORE the password to avoid matching
    // bare "Password=xxx" variable assignments (which are caught by scanGenericKV).
    public static final Pattern DOTNET_CONN_STR      = Pattern.compile(
            "(?:[A-Za-z][A-Za-z\\s_]{0,40}=[^;\"'\\r\\n]{1,150};){1,15}" +
            "(?:password|pwd)\\s*=\\s*([^;\"'\\r\\n,\\s]{4,200})",
            Pattern.CASE_INSENSITIVE);

    // =========================================================================
    // SECRETSIFTER PARITY — TIER A ADDITIONS
    // =========================================================================

    // Apify API token
    public static final Pattern APIFY_API_TOKEN      = Pattern.compile("\\bapify_api_[A-Za-z0-9]{40}\\b");

    // Asana Personal Access Token — 1/numericId:32hexchars
    public static final Pattern ASANA_PAT            = Pattern.compile("\\b1\\/[0-9]{15,20}:[a-f0-9]{32}\\b");

    // Elastic Cloud / Enterprise API key — "ApiKey " + base64
    public static final Pattern ELASTIC_API_KEY      = Pattern.compile("\\bApiKey\\s+[A-Za-z0-9+/]{20,}={0,2}");

    // Google OAuth 2.0 Client ID (apps.googleusercontent.com)
    public static final Pattern GOOGLE_OAUTH_CLIENT_ID = Pattern.compile(
            "\\b[0-9]{12}-[a-z0-9]{32}\\.apps\\.googleusercontent\\.com\\b");

    // Square OAuth token — "sq0idp-" prefix (distinct from sq0atp- access token)
    public static final Pattern SQUARE_OAUTH_TOKEN   = Pattern.compile("\\bsq0idp-[A-Za-z0-9\\-_]{22}\\b");

    // Azure Application Insights connection string
    public static final Pattern AZURE_APP_INSIGHTS_CONN = Pattern.compile(
            "InstrumentationKey=[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            Pattern.CASE_INSENSITIVE);

    // GCP service account e-mail (client_email field in service account JSON)
    public static final Pattern GCP_SA_CLIENT_EMAIL  = Pattern.compile(
            "\\b[a-z0-9\\-]+@[a-z0-9\\-]+\\.iam\\.gserviceaccount\\.com\\b");

    // =========================================================================
    // ADDITIONAL VENDOR TOKEN PATTERNS
    // =========================================================================

    // Razorpay live key
    public static final Pattern RAZORPAY_LIVE        = Pattern.compile("\\brzp_live_[A-Za-z0-9]{20}\\b");

    // Razorpay test key
    public static final Pattern RAZORPAY_TEST        = Pattern.compile("\\brzp_test_[A-Za-z0-9]{20}\\b");

    // Supabase Personal Access Token
    public static final Pattern SUPABASE_PAT         = Pattern.compile("\\bsbp_[a-f0-9]{40}\\b");

    // Braintree OAuth access token (production + sandbox)
    public static final Pattern BRAINTREE_TOKEN      = Pattern.compile(
            "\\baccess_token\\$(?:production|sandbox)\\$[a-f0-9]{16}\\$[a-f0-9]{32}\\b");

    // Klaviyo private API key — pk_ prefix + 34 hex chars (MEDIUM: short prefix has moderate FP risk)
    public static final Pattern KLAVIYO_API_KEY      = Pattern.compile("\\bpk_[a-f0-9]{34}\\b");

    // Stripe Webhook Signing Secret — whsec_ prefix + 40 base62 chars
    public static final Pattern STRIPE_WEBHOOK_SECRET = Pattern.compile("\\bwhsec_[A-Za-z0-9]{40}\\b");

    // =========================================================================
    // GAP-CLOSING PATTERNS
    // =========================================================================

    // DeepSeek API key — sk- + 32 lowercase hex (distinct from OpenAI sk- + 48 alphanumeric)
    public static final Pattern DEEPSEEK_API_KEY        = Pattern.compile("\\bsk-[a-f0-9]{32}\\b");

    // GCP OAuth2 short-lived access token — ya29. prefix (returned after OAuth2 token exchange)
    public static final Pattern GCP_OAUTH2_TOKEN        = Pattern.compile("\\bya29\\.[A-Za-z0-9_\\-]{30,}\\b");

    // Twitch stream key — live_{8-12 digit accountId}_{30-36 alnum}
    public static final Pattern TWITCH_STREAM_KEY       = Pattern.compile("\\blive_\\d{8,12}_[A-Za-z0-9]{30,36}\\b");

    // Paystack API key — sk_live_ or sk_test_ + 40 uppercase base62
    public static final Pattern PAYSTACK_LIVE_KEY       = Pattern.compile("\\bsk_live_[A-Z0-9]{40}\\b");
    public static final Pattern PAYSTACK_TEST_KEY       = Pattern.compile("\\bsk_test_[A-Z0-9]{40}\\b");

    // 1Password Service Account Token — ops_eyJ prefix (base64url-encoded JWT header)
    public static final Pattern ONEPASSWORD_SAT         = Pattern.compile("\\bops_eyJ[A-Za-z0-9_\\-]{80,500}\\b");

    // Harness Personal Access Token — pat.{22upper}.{24hex}.{20upper}
    public static final Pattern HARNESS_PAT             = Pattern.compile("\\bpat\\.[A-Z0-9]{22}\\.[0-9a-f]{24}\\.[A-Z0-9]{20}\\b");

    // Scalingo API token — tk-us- prefix + 48 base62
    public static final Pattern SCALINGO_TOKEN          = Pattern.compile("\\btk-us-[A-Za-z0-9_\\-]{48}\\b");

    // Adafruit IO key — aio_ prefix + 28 alphanumeric
    public static final Pattern ADAFRUIT_IO_KEY         = Pattern.compile("\\baio_[A-Za-z0-9]{28}\\b");

    // SonarQube / SonarCloud user token (v9.x+) — squ_ or sqp_ prefix + 40 hex
    public static final Pattern SONARQUBE_TOKEN         = Pattern.compile("\\b(?:squ|sqp)_[a-f0-9]{40}\\b");

    // bcrypt password hash — indicates hashed credentials exposed in response
    public static final Pattern BCRYPT_HASH             = Pattern.compile("\\$2[abxy]\\$\\d{1,2}\\$[./A-Za-z0-9]{53}");

    // =========================================================================
    // GENERIC PATTERNS
    // =========================================================================

    // Exclude JSON boundary characters from user/pass groups to avoid cross-boundary matches
    // e.g. prevents matching password=""care"` from React env-var blocks in minified JSON
    public static final Pattern URL_WITH_CREDS       = Pattern.compile(
            "(?i)\\bhttps?://([^/\\s:@\"'{}]+):([^/\\s@\"'{}]+)@([A-Za-z0-9.\\-]+)");

    public static final Pattern DB_CONN_STRING       = Pattern.compile(
            "(?i)(mongodb(?:\\+srv)?|postgresql|postgres|mysql|mssql|sqlserver|" +
            "redis|rediss|amqp|amqps|jdbc:[a-z]+)://" +
            "([^/\\s:@]{1,100}):([^/\\s@]{1,200})@([A-Za-z0-9.\\-_]{3,})");

    // =========================================================================
    // PII PATTERNS
    // =========================================================================

    public static final Pattern SSN                  = Pattern.compile(
            "\\b(?!000|666|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0000)\\d{4}\\b");

    public static final Pattern SSN_CONTEXT          = Pattern.compile(
            "(?i)\\b(ssn|social[_\\-]?security([_\\-]?number)?|sin|" +
            "tax[_\\-]?id(entification)?|tin|itin|national[_\\-]?id([_\\-]?number)?" +
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
    public static final Pattern GENERIC_KV           = Pattern.compile(
            "(?i)(?:[\"']([A-Za-z0-9_\\-]+(?:\\s[A-Za-z0-9_\\-]+){0,2})[\"']|([A-Za-z0-9_\\-]+))\\s*[:=]\\s*[\"']([^\"'\\r\\n]{6,500})[\"']");

    /** XML element value extractor — matches &lt;tagName&gt;value&lt;/tagName&gt; in API responses. */
    public static final Pattern XML_ELEMENT          = Pattern.compile(
            "<([A-Za-z][A-Za-z0-9_\\-]{1,49})(?:\\s[^>]*)?>([^<]{4,})<\\/\\1>");

    public static final Pattern NOISE_KEYNAMES       = Pattern.compile(
            "(?i)^(class|classname|cellclass|headername|tooltip|placeholder|label|title|" +
            "description|desc|message|text|subject|applicationname|module|component|" +
            "template|style|font|icon|filterby|weekdays|months|rfc1123|locale|" +
            "format|date|time|color|colour|width|height|size|margin|padding)$" +
            // Keys whose suffix indicates UI strings, validation patterns, policy text, or hostnames — never credentials
            "|(?i)^.+(?:msg|errormsg|regex|pattern|policy|caption|hint|domain|url|uri|host|path|endpoint|baseurl|homepage|website)$");

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
            "(?:smtp|mail|imap|pop3|ftp|sftp|ldap)[_\\-]?(?:user(?:name)?|pass(?:word)?|login|auth(?:entication)?))"); // SMTPUser, smtp_password, mailUsername, ldap_auth

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
            "[\"']([A-Za-z0-9_.+=|?#~@!$%^&*-]{20,512})[\"']");

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
            "apim[_\\-]?subscription[_\\-]?key)\\b");

    /**
     * Extracts the last key name immediately before a value assignment
     * on the same line (used for key name recovery in entropy scanner).
     */
    public static final Pattern KEY_BEFORE_VALUE     = Pattern.compile(
            "([A-Za-z][A-Za-z0-9_\\-]{2,50})\\s*[:=]\\s*[\"']?\\s*$");

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
            "clientid", "client_id", "tenantid", "tenant_id",
            "csrf", "csrftoken", "xsrf", "xsrftoken",
            "x-csrf-token", "x-xsrf-token", "xsrf-token", "csrf-token",
            "_csrf", "csrfmiddlewaretoken", "__requestverificationtoken",
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
            "sdkextension", "sdkversion", "instrumentationkey"
    );

    // =========================================================================
    // HTML PARSING — inline script extraction and script-src following
    // =========================================================================

    /** Matches <script src="..."> or <script src='...'> — captures the src value. */
    public static final Pattern SCRIPT_SRC = Pattern.compile(
            "<script[^>]+\\bsrc\\s*=\\s*[\"']([^\"'\\s>]+)[\"'][^>]*>",
            Pattern.CASE_INSENSITIVE);

    /**
     * Matches inline <script> blocks that do NOT have a src attribute.
     * Captures the script body in group 1.
     */
    public static final Pattern INLINE_SCRIPT = Pattern.compile(
            "<script(?![^>]*\\bsrc\\s*=)[^>]*>([\\s\\S]*?)</script>",
            Pattern.CASE_INSENSITIVE);

    /**
     * Matches {@code <frame src="...">} and {@code <iframe src="...">} tags.
     * Captures the src value in group 1.  Used to follow classic frameset pages
     * where the real content (and its &lt;script src&gt; references) lives in a child frame.
     */
    public static final Pattern FRAME_SRC = Pattern.compile(
            "<i?frame[^>]+\\bsrc\\s*=\\s*[\"']([^\"'\\s>]+)[\"'][^>]*>",
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
            "<meta\\b(?=[^>]*\\bhttp-equiv\\s*=\\s*[\"']refresh[\"'])[^>]*\\bcontent\\s*=\\s*[\"'][^\"']*\\burl\\s*=\\s*([^\"'\\s>][^\"']{0,300})[\"']",
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
            "[\"']((?:/[^\"'\\s]*)?[a-zA-Z0-9._-]+\\.(?:chunk|bundle|min)\\.js)[\"']");

    /**
     * Matches &lt;link rel="preload" as="script" href="..."&gt; in either attribute order.
     * Used to discover JS chunks that are eagerly preloaded by SPAs.
     */
    public static final Pattern PRELOAD_JS_LINK = Pattern.compile(
            "<link(?=[^>]*\\bas\\s*=\\s*[\"']script[\"'])[^>]*\\bhref\\s*=\\s*[\"']([^\"'\\s>]+)[\"'][^>]*/?>",
            Pattern.CASE_INSENSITIVE);

    /**
     * Matches &lt;script type="application/json"&gt; blocks.
     * Next.js and other SPAs embed __NEXT_DATA__, page props, and server config
     * as JSON script tags rather than window.* assignments.
     * Captures the JSON body in group 1.
     */
    public static final Pattern JSON_SCRIPT_TAG = Pattern.compile(
            "<script[^>]+type\\s*=\\s*[\"']application/(?:json|ld\\+json)[\"'][^>]*>([\\s\\S]*?)</script>",
            Pattern.CASE_INSENSITIVE);

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
            String  severity   // "HIGH" or "MEDIUM" — Montoya has no CRITICAL
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
            String severity
    ) {}

    public static final List<CtxRule> CONTEXT_GATED_RULES = List.of(
            // AWS Secret Access Key — 40-char base62 after aws_secret keyword
            new CtxRule(Pattern.compile(
                    "(?i)aws[_\\-]?secret[_\\-]?(?:access[_\\-]?)?key[^\"'<>\\n]{0,30}[=:]\\s*[\"']?([A-Za-z0-9+/]{40})[\"']?"),
                    1, "aws_secret_access_key", "AWS_KEY_002", "AWS Secret Access Key", "HIGH"),

            // Azure DevOps PAT — 52-char base64 near azure devops / dev.azure.com
            new CtxRule(Pattern.compile(
                    "(?i)(?:azure[_\\-]?devops|dev\\.azure\\.com|vsts)[^\"'<>\\n]{0,60}[=:]\\s*[\"']?([A-Za-z0-9+/=]{52})[\"']?"),
                    1, "azure_devops_pat", "AZURE_DEVOPS_KEY_001", "Azure DevOps Personal Access Token", "HIGH"),

            // Snowflake credential — password/token near snowflake keyword
            new CtxRule(Pattern.compile(
                    "(?i)snowflake[_\\-]?(?:password|token|private[_\\-]?key)[^\"'<>\\n]{0,30}[=:]\\s*[\"']?([A-Za-z0-9+/=_\\-]{20,})[\"']?"),
                    1, "snowflake_credential", "SNOWFLAKE_KEY_001", "Snowflake Credential", "HIGH"),

            // Jira API token — 24-char base64 near jira/atlassian keyword
            new CtxRule(Pattern.compile(
                    "(?i)(?:jira[^\"'<>\\n]{0,40}(?:api[_\\-]?token|password)|atlassian\\.net[^\"'<>\\n]{0,60}(?:api[_\\-]?token|password))[^\"'<>\\n]{0,30}[=:]\\s*[\"']?([A-Za-z0-9+/=]{24})[\"']?"),
                    1, "jira_api_token", "JIRA_KEY_001", "Jira API Token", "HIGH"),

            // Salesforce OAuth access token — 00D orgId + ! separator + token body
            new CtxRule(Pattern.compile(
                    "(?i)(?:salesforce|sfdc|instance_url)[^\"'<>\\n]{0,60}[=:]\\s*[\"']?(00D[A-Za-z0-9]{15}![A-Za-z0-9._\\-]{20,})[\"']?"),
                    1, "salesforce_oauth_token", "SALESFORCE_KEY_001", "Salesforce OAuth Access Token", "HIGH"),

            // --- SecretSifter parity: Tier B additions ---

            // Datadog API / App key — 32-40 hex after DD_API_KEY / DD_APP_KEY / datadog keyword
            new CtxRule(Pattern.compile(
                    "(?i)(?:DD_API_KEY|DD_APP_KEY|datadog[_\\-]?(?:api|app)[_\\-]?key)\\s*[:=]\\s*[\"']?([a-f0-9]{32,40})[\"']?"),
                    1, "datadog_api_key", "DATADOG_KEY_001", "Datadog API Key", "HIGH"),

            // Heroku API key — UUID near heroku / HEROKU_API_KEY keyword
            new CtxRule(Pattern.compile(
                    "(?i)(?:heroku[^\"'\\n]{0,80}[=:\\s]+[\"']?|HEROKU_API_KEY\\s*[=:]\\s*[\"']?)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"),
                    1, "heroku_api_key", "HEROKU_KEY_001", "Heroku API Key", "HIGH"),

            // LaunchDarkly SDK key — sdk- prefix after launchdarkly / LD_SDK_KEY keyword
            new CtxRule(Pattern.compile(
                    "(?i)(?:launchdarkly|LD_SDK_KEY)[^\"'<>\\n]{0,80}[=:\\s]+[\"']?(sdk-[A-Za-z0-9\\-_]{40,})[\"']?"),
                    1, "launchdarkly_sdk_key", "LAUNCHDARKLY_KEY_001", "LaunchDarkly SDK Key", "HIGH"),

            // MessageBird API key — 25 alnum after messagebird keyword
            new CtxRule(Pattern.compile(
                    "(?i)messagebird[^\"'<>\\n]{0,60}[=:]\\s*[\"']?([A-Za-z0-9]{25})[\"']?"),
                    1, "messagebird_api_key", "MESSAGEBIRD_KEY_001", "MessageBird API Key", "HIGH"),

            // Splunk HEC token — UUID after splunk / HEC_TOKEN / hec_token keyword
            new CtxRule(Pattern.compile(
                    "(?i)(?:splunk|HEC_TOKEN|hec[_\\-]?token)[^\"'<>\\n]{0,60}[=:]\\s*[\"']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[\"']?"),
                    1, "splunk_hec_token", "SPLUNK_KEY_001", "Splunk HEC Token", "HIGH"),

            // Twilio Auth Token — 32 lowercase hex after twilio...auth_token / authToken keyword
            new CtxRule(Pattern.compile(
                    "(?i)(?:twilio[^\"']{0,30}auth[_\\-]?token|authToken)\\s*[:=]\\s*[\"']([a-z0-9]{32})[\"']"),
                    1, "twilio_auth_token", "TWILIO_AUTH_001", "Twilio Auth Token", "HIGH"),

            // Webex bot / access token — 85+ chars after webex...token keyword
            new CtxRule(Pattern.compile(
                    "(?i)(?:webex|WEBEX)[^\"'<>\\n]{0,80}(?:access[_\\-]?token|bot[_\\-]?token)[^\"'<>\\n]{0,30}[=:]\\s*[\"']?([A-Za-z0-9_\\-]{85,})[\"']?"),
                    1, "webex_bot_token", "WEBEX_KEY_001", "Webex Bot Token", "HIGH"),

            // Azure APIM subscription key — 32-64 alnum after Ocp-Apim-Subscription-Key header
            new CtxRule(Pattern.compile(
                    "(?i)(?:Ocp-?Apim-?Subscription-?Key|ocp[_\\-]?apim[_\\-]?subscription[_\\-]?key)\\s*[:=]\\s*[\"']?([A-Za-z0-9]{32,64})[\"']?"),
                    1, "azure_apim_subscription_key", "AZURE_APIM_001", "Azure APIM Subscription Key", "HIGH"),

            // Azure App Insights instrumentation key (bare UUID) — requires keyword context
            // (AZURE_APP_INSIGHTS_CONN in AnchoredRules catches the full connection string)
            new CtxRule(Pattern.compile(
                    "(?i)[\"']?(?:instrumentation[_\\-]?key|APPINSIGHTS_INSTRUMENTATIONKEY)[\"']?\\s*[:=]\\s*[\"']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[\"']?"),
                    1, "azure_app_insights_ikey", "AZURE_APPINSIGHTS_001", "Azure App Insights Instrumentation Key", "LOW"),

            // Azure Shared Access Signature token — sig= or SharedAccessSignature keyword
            new CtxRule(Pattern.compile(
                    "(?i)(?:SharedAccessSignature|sig=)([A-Za-z0-9%+/=]{30,})"),
                    1, "azure_sas_token", "AZURE_SAS_001", "Azure Shared Access Signature Token", "HIGH"),

            // --- Additional vendor token patterns ---

            // Algolia application ID + API key pair — 10-char uppercase app ID near algolia keyword
            new CtxRule(Pattern.compile(
                    "(?i)algolia[^\"'<>\\n]{0,80}[=:\\s]+[\"']?([A-Z0-9]{10})[\"']?"),
                    1, "algolia_app_id", "ALGOLIA_KEY_001", "Algolia Application ID", "LOW"),

            // Algolia API key — 32 hex after algolia...api_key / ALGOLIA_API_KEY keyword
            new CtxRule(Pattern.compile(
                    "(?i)(?:algolia[^\"'<>\\n]{0,60}(?:api[_\\-]?key|search[_\\-]?key|admin[_\\-]?key)|ALGOLIA_API_KEY)\\s*[:=]\\s*[\"']?([a-f0-9]{32})[\"']?"),
                    1, "algolia_api_key", "ALGOLIA_KEY_002", "Algolia API Key", "HIGH"),

            // Cloudflare API token — 40-char base62url after cloudflare / CF_API_TOKEN keyword
            new CtxRule(Pattern.compile(
                    "(?i)(?:cloudflare[^\"'<>\\n]{0,60}(?:api[_\\-]?token|token)|CF_API_TOKEN)\\s*[:=]\\s*[\"']?([A-Za-z0-9_\\-]{40})[\"']?"),
                    1, "cloudflare_api_token", "CLOUDFLARE_KEY_001", "Cloudflare API Token", "HIGH"),

            // Zendesk API token — 40-char base62 after zendesk / ZENDESK_API_TOKEN keyword
            new CtxRule(Pattern.compile(
                    "(?i)(?:zendesk[^\"'<>\\n]{0,60}(?:api[_\\-]?token|token)|ZENDESK_API_TOKEN)\\s*[:=]\\s*[\"']?([A-Za-z0-9]{40})[\"']?"),
                    1, "zendesk_api_token", "ZENDESK_KEY_001", "Zendesk API Token", "HIGH"),

            // Zoom JWT app secret / OAuth client secret — 24-char base62 after zoom keyword
            new CtxRule(Pattern.compile(
                    "(?i)(?:zoom[^\"'<>\\n]{0,60}(?:api[_\\-]?secret|client[_\\-]?secret|jwt[_\\-]?secret)|ZOOM_(?:API_SECRET|CLIENT_SECRET))\\s*[:=]\\s*[\"']?([A-Za-z0-9]{24,32})[\"']?"),
                    1, "zoom_secret", "ZOOM_KEY_001", "Zoom API / OAuth Secret", "HIGH"),

            // Intercom access token — 64-char base62 after intercom keyword
            new CtxRule(Pattern.compile(
                    "(?i)(?:intercom[^\"'<>\\n]{0,60}(?:access[_\\-]?token|token)|INTERCOM_ACCESS_TOKEN)\\s*[:=]\\s*[\"']?([A-Za-z0-9]{64})[\"']?"),
                    1, "intercom_access_token", "INTERCOM_KEY_001", "Intercom Access Token", "HIGH"),

            // Azure AD / APIM client secret — 20-50 chars alphanumeric + ~._-
            // Catches aPIMSecretKey, apim_secret_key, azure_client_secret, aadClientSecret etc.
            // Uses CtxRule (runs on full JS body before size-cap truncation) so it works in large
            // bundles where scanGenericKV only sees the first 1 MB + last 512 KB.
            new CtxRule(Pattern.compile(
                    "(?i)(?:apim[_\\-]?secret[_\\-]?key|apim[_\\-]?client[_\\-]?secret|" +
                    "azure[_\\-]?(?:ad[_\\-]?)?client[_\\-]?secret|aad[_\\-]?client[_\\-]?secret|" +
                    "b2c[_\\-]?client[_\\-]?secret)\\s*[:=]\\s*[\"']([A-Za-z0-9~._\\-]{20,60})[\"']"),
                    1, "apim_secret_key", "AZURE_APIM_002", "Azure AD / APIM Client Secret", "HIGH"),

            // Azure AD / APIM client ID — UUID format
            // Catches aPIMclientId, apim_client_id, aadClientId, azure_client_id etc.
            new CtxRule(Pattern.compile(
                    "(?i)(?:apim[_\\-]?client[_\\-]?id|azure[_\\-]?(?:ad[_\\-]?)?client[_\\-]?id|" +
                    "aad[_\\-]?client[_\\-]?id|b2c[_\\-]?client[_\\-]?id)\\s*[:=]\\s*[\"']" +
                    "([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})[\"']"),
                    1, "apim_client_id", "AZURE_APIM_003", "Azure AD / APIM Client ID", "LOW"),

            // CryptoJS / OpenSSL AES encrypted blob — value starts with U2FsdGVkX1 (base64 of "Salted__")
            // Catches appKey, apimSubscriptionKey, clientId, appId etc. encrypted with CryptoJS.AES.
            // Using a CtxRule (runs at LIGHT+) bypasses the hasHighEntropy() /‐slash rejection
            // that silently drops all standard base64 values containing '/' characters.
            new CtxRule(Pattern.compile(
                    "(?<key>[\"']?[A-Za-z_$][A-Za-z0-9_$]*[\"']?)\\s*[:=]\\s*[\"'](U2FsdGVkX1[A-Za-z0-9+/]{20,}={0,2})[\"']"),
                    2, "cryptojs_encrypted_blob", "CRYPTOJS_BLOB_001", "CryptoJS AES Encrypted Blob (client-side encryption)", "HIGH"),

            // Azure APIM subscription key stored as encrypted env config variable —
            // catches apimSubscriptionKey, apimSubscriptionKeyC360, apimSubscriptionKeyProd, etc.
            // Value is either a CryptoJS blob or a raw alphanumeric APIM subscription key.
            new CtxRule(Pattern.compile(
                    "(?i)(?<key>[\"']?apim[_\\-]?subscription[_\\-]?key[A-Za-z0-9]*[\"']?)\\s*[:=]\\s*[\"']([A-Za-z0-9+/=~._\\-]{20,512})[\"']"),
                    2, "apim_subscription_key_env", "AZURE_APIM_004", "Azure APIM Subscription Key (env config)", "HIGH"),

            // =========================================================================
            // TITUS PARITY — CI/CD, security tools, infrastructure
            // =========================================================================

            // Snyk API token — uppercase UUID (8-4-4-4-12) near snyk keyword
            new CtxRule(Pattern.compile(
                    "(?i)snyk[^\"'<>\\n]{0,32}(?:secret|private|access|key|token)[^\"'<>\\n]{0,32}" +
                    "[=:\\s]+[\"']?([A-Z0-9]{8}-(?:[A-Z0-9]{4}-){3}[A-Z0-9]{12})[\"']?"),
                    1, "snyk_api_token", "SNYK_KEY_001", "Snyk API Token", "HIGH"),

            // Auth0 client secret — AUTH0_CLIENT_SECRET keyword + 32-80 char value
            new CtxRule(Pattern.compile(
                    "(?i)AUTH0_CLIENT_SECRET\\s*[=:]\\s*[\"']?([A-Za-z0-9_\\-]{32,80})[\"']?"),
                    1, "auth0_client_secret", "AUTH0_KEY_001", "Auth0 Client Secret", "HIGH"),

            // Jenkins API token or crumb — 32-36 hex near jenkins keyword
            new CtxRule(Pattern.compile(
                    "(?i)jenkins[^\"'<>\\n]{0,40}(?:crumb|token|api[_\\-]?key)[^\"'<>\\n]{0,20}" +
                    "[=:\\s]+[\"']?([0-9a-f]{32,36})[\"']?"),
                    1, "jenkins_api_token", "JENKINS_KEY_001", "Jenkins API Token", "HIGH"),

            // DroneCI access token — 32-64 hex near drone keyword
            new CtxRule(Pattern.compile(
                    "(?i)drone[^\"'<>\\n]{0,32}(?:secret|token|access|key)[^\"'<>\\n]{0,16}" +
                    "[=:\\s]+[\"']?([a-f0-9]{32,64})[\"']?"),
                    1, "droneci_token", "DRONECI_KEY_001", "DroneCI Access Token", "HIGH"),

            // Travis CI token — 22-char uppercase+dash token near travis keyword
            new CtxRule(Pattern.compile(
                    "(?i)travis[^\"'<>\\n]{0,32}(?:secret|private|access|key|token)[^\"'<>\\n]{0,16}" +
                    "[=:\\s]+[\"']?([A-Z\\-_0-9]{22})[\"']?"),
                    1, "travisci_token", "TRAVISCI_KEY_001", "Travis CI Token", "HIGH"),

            // Vercel API token — 24 uppercase alphanumeric near vercel keyword
            new CtxRule(Pattern.compile(
                    "(?i)vercel[^\"'<>\\n]{0,32}(?:secret|token|api[_\\-]?key|access)[^\"'<>\\n]{0,16}" +
                    "[=:\\s]+[\"']?([A-Z0-9]{24})[\"']?"),
                    1, "vercel_api_token", "VERCEL_KEY_001", "Vercel API Token", "HIGH"),

            // Freshdesk API key — alphanumeric near freshdesk keyword
            new CtxRule(Pattern.compile(
                    "(?i)freshdesk[^\"'<>\\n]{0,64}(?:api[_\\-]?key|secret|token|key)[^\"'<>\\n]{0,16}" +
                    "[=:\\s]+[\"']?([A-Za-z0-9]{20,40})[\"']?"),
                    1, "freshdesk_api_key", "FRESHDESK_KEY_001", "Freshdesk API Key", "HIGH"),

            // Monday.com API token — JWT-style eyJ near monday keyword
            new CtxRule(Pattern.compile(
                    "(?i)monday[^\"'<>\\n]{0,40}(?:secret|token|api[_\\-]?key|access)[^\"'<>\\n]{0,16}" +
                    "[=:\\s]+[\"']?(eyJ[A-Za-z0-9_\\-]{10,200}\\.eyJ[A-Za-z0-9_\\-]{50,1000}\\.[A-Za-z0-9_\\-]{20,500})[\"']?"),
                    1, "monday_api_token", "MONDAY_KEY_001", "Monday.com API Token", "HIGH"),

            // Coinbase access token — 32 lowercase alnum near coinbase keyword
            new CtxRule(Pattern.compile(
                    "(?i)coinbase[^\"'<>\\n]{0,32}(?:secret|token|access|key)[^\"'<>\\n]{0,16}" +
                    "[=:\\s]+[\"']?([a-z0-9\\-]{32})[\"']?"),
                    1, "coinbase_access_token", "COINBASE_KEY_001", "Coinbase Access Token", "HIGH"),

            // PayPal OAuth2 client ID — A + 78-99 uppercase near paypal keyword
            new CtxRule(Pattern.compile(
                    "(?i)paypal[^\"'<>\\n]{0,40}(?:client[_\\-]?id|client|id|user)[^\"'<>\\n]{0,16}" +
                    "[=:\\s]+[\"']?(A[A-Z0-9_\\-]{78,99})[\"']?"),
                    1, "paypal_client_id", "PAYPAL_KEY_001", "PayPal OAuth2 Client ID", "MEDIUM"),

            // IBM Cloud API key — 42-44 chars (alphanumeric + _-) near ibm/bx keyword
            new CtxRule(Pattern.compile(
                    "(?i)(?:ibm(?:cloud)?|bx)[^\"'<>\\n]{0,40}(?:secret|private|access|key|token)[^\"'<>\\n]{0,32}" +
                    "[=:\\s]+[\"']?([0-9A-Za-z_\\-]{42,44})[\"']?"),
                    1, "ibm_cloud_api_key", "IBM_KEY_001", "IBM Cloud API Key", "HIGH"),

            // Cohere API key — 40 alphanumeric near cohere keyword
            new CtxRule(Pattern.compile(
                    "(?i)cohere[^\"'<>\\n]{0,32}(?:secret|api[_\\-]?key|key|token)[^\"'<>\\n]{0,16}" +
                    "[=:\\s]+[\"']?([A-Za-z0-9]{40})[\"']?"),
                    1, "cohere_api_key", "COHERE_KEY_001", "Cohere API Key", "HIGH"),

            // Mistral AI API key — 32 alphanumeric near mistral keyword
            new CtxRule(Pattern.compile(
                    "(?i)mistral[^\"'<>\\n]{0,32}(?:secret|api[_\\-]?key|key|token)[^\"'<>\\n]{0,16}" +
                    "[=:\\s]+[\"']?([A-Za-z0-9]{32})[\"']?"),
                    1, "mistral_api_key", "MISTRAL_KEY_001", "Mistral AI API Key", "HIGH"),

            // Spotify access token — 100+ char opaque token near spotify keyword
            new CtxRule(Pattern.compile(
                    "(?i)spotify[^\"'<>\\n]{0,40}(?:token|access|bearer|auth)[^\"'<>\\n]{0,16}" +
                    "[=:\\s]+[\"']?([A-Za-z0-9_\\-]{100,})[\"']?"),
                    1, "spotify_access_token", "SPOTIFY_KEY_001", "Spotify Access Token", "HIGH"),

            // SonarQube user token (older pre-9.x format) — 40 hex near sonar keyword
            new CtxRule(Pattern.compile(
                    "(?i)sonar[^\"'<>\\n]{0,40}(?:login|token|key)[^\"'<>\\n]{0,16}" +
                    "[=:\\s]+[\"']?([a-f0-9]{40})[\"']?"),
                    1, "sonarqube_user_token_hex", "SONAR_KEY_002", "SonarQube User Token (hex)", "MEDIUM"),

            // WireGuard private key — base64 key value following PrivateKey = in .conf files
            new CtxRule(Pattern.compile(
                    "\\bPrivateKey\\s*=\\s*([A-Za-z0-9+/]{43}=)"),
                    1, "wireguard_private_key", "WIREGUARD_KEY_001", "WireGuard Private Key", "HIGH"),

            // HashiCorp Vault legacy service token (< v1.10) — s. + 24-128 base62 near vault context
            new CtxRule(Pattern.compile(
                    "(?i)(?:hashicorp|vault|VAULT_TOKEN|vault[_\\-]?(?:token|client|secret|key))" +
                    "[^\"'<>\\n]{0,20}[\"':=\\s]{1,5}\\b(s\\.[A-Za-z0-9_\\-]{24,128})\\b"),
                    1, "vault_legacy_token", "VAULT_TOKEN_002", "HashiCorp Vault Legacy Service Token", "HIGH"),

            // GCP Service Account JSON blob — unique field present in every GCP SA key file
            new CtxRule(Pattern.compile("\"auth_provider_x509_cert_url\""),
                    0, "gcp_service_account_json", "GCP_KEY_002", "GCP Service Account JSON Key File", "HIGH"),

            // Kubernetes bootstrap token — {6 alnum}.{16 alnum} format near token/bootstrap
            new CtxRule(Pattern.compile(
                    "(?i)(?:token|bootstrap)[^\"'<>\\n]{0,16}[\"':=\\s]{1,5}([a-z0-9]{6}\\.[a-z0-9]{16})\\b"),
                    1, "kubernetes_bootstrap_token", "K8S_KEY_001", "Kubernetes Bootstrap Token", "HIGH")
    );

    // =========================================================================
    // ANCHORED RULES TABLE — iterated in SecretScanner.scanAnchoredTokens()
    // =========================================================================

    public static final List<AnchoredRule> ANCHORED_RULES = List.of(
            new AnchoredRule(GITHUB_PAT_CLASSIC,  "github_pat_classic",     "GITHUB_PAT_001",    "GitHub PAT (Classic)",              "HIGH"),
            new AnchoredRule(GITHUB_OAUTH,         "github_oauth_token",     "GITHUB_PAT_002",    "GitHub OAuth Token",                "HIGH"),
            new AnchoredRule(GITHUB_ACTIONS,       "github_actions_token",   "GITHUB_PAT_003",    "GitHub Actions Token",              "HIGH"),
            new AnchoredRule(GITHUB_REFRESH,       "github_refresh_token",   "GITHUB_PAT_004",    "GitHub Refresh Token",              "HIGH"),
            new AnchoredRule(GITHUB_FINE_PAT,      "github_fine_pat",        "GITHUB_PAT_005",    "GitHub Fine-Grained PAT",           "HIGH"),
            new AnchoredRule(GITLAB_PAT,           "gitlab_pat",             "GITLAB_PAT_001",    "GitLab Personal Access Token",      "HIGH"),
            new AnchoredRule(GITLAB_DEPLOY,        "gitlab_deploy_token",    "GITLAB_PAT_002",    "GitLab Deploy Token",               "HIGH"),
            new AnchoredRule(NPM_TOKEN,            "npm_access_token",       "NPM_TOKEN_001",     "npm Access Token",                  "HIGH"),
            new AnchoredRule(SLACK_BOT,            "slack_bot_token",        "SLACK_TOKEN_001",   "Slack Bot Token",                   "HIGH"),
            new AnchoredRule(SLACK_USER,           "slack_user_token",       "SLACK_TOKEN_002",   "Slack User Token",                  "HIGH"),
            new AnchoredRule(SLACK_APP,            "slack_app_token",        "SLACK_TOKEN_003",   "Slack App Token",                   "HIGH"),
            new AnchoredRule(SLACK_CONFIG,         "slack_config_token",     "SLACK_TOKEN_004",   "Slack Config Token",                "HIGH"),
            new AnchoredRule(STRIPE_SECRET_LIVE,   "stripe_secret_key",      "STRIPE_KEY_001",    "Stripe Secret Key (Live)",          "HIGH"),
            new AnchoredRule(STRIPE_SECRET_TEST,   "stripe_test_key",        "STRIPE_KEY_002",    "Stripe Secret Key (Test)",          "LOW"),
            new AnchoredRule(STRIPE_RESTRICTED,    "stripe_restricted_key",  "STRIPE_KEY_003",    "Stripe Restricted Key",             "HIGH"),
            new AnchoredRule(SENDGRID,             "sendgrid_api_key",       "SENDGRID_KEY_001",  "SendGrid API Key",                  "HIGH"),
            new AnchoredRule(TWILIO_SID,           "twilio_account_sid",     "TWILIO_SID_001",    "Twilio Account SID",                "LOW"),
            new AnchoredRule(OPENAI_KEY,           "openai_api_key",         "OPENAI_KEY_001",    "OpenAI API Key",                    "HIGH"),
            new AnchoredRule(OPENAI_PROJECT,       "openai_project_key",     "OPENAI_KEY_002",    "OpenAI Project API Key",            "HIGH"),
            new AnchoredRule(ANTHROPIC_KEY,        "anthropic_api_key",      "ANTHROPIC_KEY_001", "Anthropic API Key",                 "HIGH"),
            new AnchoredRule(SHOPIFY_TOKEN,        "shopify_access_token",   "SHOPIFY_KEY_001",   "Shopify Access Token",              "HIGH"),
            new AnchoredRule(SHOPIFY_SECRET,       "shopify_shared_secret",  "SHOPIFY_KEY_002",   "Shopify Shared Secret",             "HIGH"),
            new AnchoredRule(SHOPIFY_CUSTOM,       "shopify_custom_app",     "SHOPIFY_KEY_003",   "Shopify Custom App Token",          "HIGH"),
            new AnchoredRule(HUBSPOT_TOKEN,        "hubspot_private_app",    "HUBSPOT_KEY_001",   "HubSpot Private App Token",         "HIGH"),
            new AnchoredRule(MAILCHIMP,            "mailchimp_api_key",      "MAILCHIMP_KEY_001", "Mailchimp API Key",                 "HIGH"),
            new AnchoredRule(DATABRICKS,           "databricks_token",       "DATABRICKS_KEY_001","Databricks API Token",              "HIGH"),
            new AnchoredRule(GOOGLE_KEY,           "google_api_key",         "GOOGLE_KEY_001",    "Google API Key",                    "HIGH"),
            new AnchoredRule(AWS_ACCESS_KEY,       "aws_access_key_id",      "AWS_KEY_001",       "AWS Access Key ID",                 "HIGH"),
            new AnchoredRule(PEM_PRIVATE_KEY,      "pem_private_key",        "PEM_PRIVKEY_001",   "PEM Private Key",                   "HIGH"),

            // ── Extended vendor tokens ──────────────────────────────────────
            new AnchoredRule(VAULT_SERVICE_TOKEN,  "vault_service_token",    "VAULT_TOKEN_001",   "HashiCorp Vault Service Token",     "HIGH"),
            new AnchoredRule(PULUMI_TOKEN,         "pulumi_access_token",    "PULUMI_TOKEN_001",  "Pulumi Access Token",               "HIGH"),
            new AnchoredRule(LINEAR_API_KEY,       "linear_api_key",         "LINEAR_KEY_001",    "Linear API Key",                    "HIGH"),
            new AnchoredRule(NOTION_TOKEN,         "notion_integration_token","NOTION_KEY_001",   "Notion Integration Token",          "HIGH"),
            new AnchoredRule(NOTION_TOKEN_NEW,     "notion_api_token",       "NOTION_KEY_002",    "Notion Internal Integration Token", "HIGH"),
            new AnchoredRule(NETLIFY_TOKEN,        "netlify_access_token",   "NETLIFY_KEY_001",   "Netlify Personal Access Token",     "HIGH"),
            new AnchoredRule(FIREBASE_FCM_KEY,     "firebase_fcm_server_key","FIREBASE_KEY_001",  "Firebase FCM Server Key",           "HIGH"),
            new AnchoredRule(AIRTABLE_PAT,         "airtable_pat",           "AIRTABLE_KEY_001",  "Airtable Personal Access Token",    "HIGH"),
            new AnchoredRule(WOOCOMMERCE_CK,       "woocommerce_ck",         "WOOCOMMERCE_KEY_001","WooCommerce Consumer Key",         "HIGH"),
            new AnchoredRule(WOOCOMMERCE_CS,       "woocommerce_cs",         "WOOCOMMERCE_KEY_002","WooCommerce Consumer Secret",      "HIGH"),
            new AnchoredRule(DISCORD_BOT_TOKEN,    "discord_bot_token",      "DISCORD_TOKEN_001", "Discord Bot Token",                 "HIGH"),
            new AnchoredRule(DISCORD_WEBHOOK,      "discord_webhook_url",    "DISCORD_TOKEN_002", "Discord Incoming Webhook URL",      "HIGH"),
            new AnchoredRule(SLACK_WEBHOOK,        "slack_webhook_url",      "SLACK_TOKEN_005",   "Slack Incoming Webhook URL",        "HIGH"),
            new AnchoredRule(TWITTER_BEARER,       "twitter_bearer_token",   "TWITTER_KEY_001",   "Twitter/X App Bearer Token",        "MEDIUM"),
            new AnchoredRule(NEWRELIC_LICENSE_KEY, "newrelic_license_key",   "NEWRELIC_KEY_001",  "New Relic License / Ingest Key",    "HIGH"),
            new AnchoredRule(NEWRELIC_INGEST_KEY,  "newrelic_ingest_key",    "NEWRELIC_KEY_002",  "New Relic Insights Insert Key",     "HIGH"),
            new AnchoredRule(DYNATRACE_TOKEN,      "dynatrace_api_token",    "DYNATRACE_KEY_001", "Dynatrace API Token",               "HIGH"),
            new AnchoredRule(TELEGRAM_BOT_TOKEN,   "telegram_bot_token",     "TELEGRAM_KEY_001",  "Telegram Bot API Token",            "HIGH"),
            new AnchoredRule(MAILGUN_API_KEY,      "mailgun_api_key",        "MAILGUN_KEY_001",   "Mailgun API Key",                   "HIGH"),
            new AnchoredRule(PAGERDUTY_KEY,        "pagerduty_api_key",      "PAGERDUTY_KEY_001", "PagerDuty API Key",                 "HIGH"),
            new AnchoredRule(AGE_SECRET_KEY,       "age_secret_key",         "AGE_KEY_001",       "Age Encryption Secret Key",         "HIGH"),
            new AnchoredRule(ALIBABA_ACCESS_KEY,   "alibaba_access_key_id",  "ALIBABA_KEY_001",   "Alibaba Cloud Access Key ID",       "HIGH"),
            new AnchoredRule(ATLASSIAN_API_TOKEN,  "atlassian_api_token",    "ATLASSIAN_KEY_001", "Atlassian API Token",               "HIGH"),
            new AnchoredRule(CONTENTFUL_TOKEN,     "contentful_cma_token",   "CONTENTFUL_KEY_001","Contentful CMA Token",              "HIGH"),
            new AnchoredRule(DO_ACCESS_TOKEN,      "digitalocean_pat",       "DO_KEY_001",        "DigitalOcean Personal Access Token","HIGH"),
            new AnchoredRule(DO_OAUTH_TOKEN,       "digitalocean_oauth",     "DO_KEY_002",        "DigitalOcean OAuth Token",          "HIGH"),
            new AnchoredRule(DOPPLER_TOKEN,        "doppler_service_token",  "DOPPLER_KEY_001",   "Doppler Service Token",             "HIGH"),
            new AnchoredRule(DUFFEL_TOKEN,         "duffel_access_token",    "DUFFEL_KEY_001",    "Duffel Access Token",               "HIGH"),
            new AnchoredRule(EASYPOST_KEY,         "easypost_api_key",       "EASYPOST_KEY_001",  "EasyPost API Key (Live)",           "HIGH"),
            new AnchoredRule(EASYPOST_TEST_KEY,    "easypost_test_key",      "EASYPOST_KEY_002",  "EasyPost API Key (Test)",           "LOW"),
            new AnchoredRule(FLUTTERWAVE_PUB,      "flutterwave_pub_key",    "FLUTTERWAVE_KEY_001","Flutterwave Public Key",           "LOW"),
            new AnchoredRule(FLUTTERWAVE_SEC,      "flutterwave_sec_key",    "FLUTTERWAVE_KEY_002","Flutterwave Secret Key",           "HIGH"),
            new AnchoredRule(FRAMEIO_TOKEN,        "frameio_api_token",      "FRAMEIO_KEY_001",   "Frame.io API Token",                "HIGH"),
            new AnchoredRule(GRAFANA_SA_TOKEN,     "grafana_sa_token",       "GRAFANA_KEY_001",   "Grafana Service Account Token",     "HIGH"),
            new AnchoredRule(GRAFANA_CLOUD_TOKEN,  "grafana_cloud_token",    "GRAFANA_KEY_002",   "Grafana Cloud Access Token",        "HIGH"),
            new AnchoredRule(PLANETSCALE_PW,       "planetscale_password",   "PSQL_KEY_001",      "PlanetScale Database Password",     "HIGH"),
            new AnchoredRule(PLANETSCALE_TOKEN,    "planetscale_token",      "PSQL_KEY_002",      "PlanetScale API Token",             "HIGH"),
            new AnchoredRule(POSTMAN_API_KEY,      "postman_api_key",        "POSTMAN_KEY_001",   "Postman API Key",                   "HIGH"),
            new AnchoredRule(PYPI_TOKEN,           "pypi_upload_token",      "PYPI_KEY_001",      "PyPI Upload Token",                 "HIGH"),
            new AnchoredRule(SENDINBLUE_API_KEY,   "sendinblue_api_key",     "SENDINBLUE_KEY_001","SendinBlue / Brevo API Key",        "HIGH"),
            new AnchoredRule(SHIPPO_TOKEN,         "shippo_api_token",       "SHIPPO_KEY_001",    "Shippo Shipping API Token",         "HIGH"),
            new AnchoredRule(AZURE_CONN_STR,       "azure_storage_conn_str", "AZURE_CONN_001",    "Azure Storage Connection String",   "HIGH"),
            new AnchoredRule(RUBYGEMS_TOKEN,       "rubygems_api_token",     "RUBYGEMS_KEY_001",  "RubyGems API Token",                "HIGH"),

            // ── Additional vendor tokens ─────────────────────────────────────
            new AnchoredRule(HUGGINGFACE_TOKEN,    "huggingface_api_token",  "HF_KEY_001",        "Hugging Face API Token",            "HIGH"),
            new AnchoredRule(GROQ_API_KEY,         "groq_api_key",           "GROQ_KEY_001",      "Groq API Key",                      "HIGH"),
            new AnchoredRule(REPLICATE_API_KEY,    "replicate_api_key",      "REPLICATE_KEY_001", "Replicate API Token",               "HIGH"),
            new AnchoredRule(XAI_API_KEY,          "xai_api_key",            "XAI_KEY_001",       "xAI / Grok API Key",                "HIGH"),
            new AnchoredRule(BUILDKITE_TOKEN,      "buildkite_access_token", "BUILDKITE_KEY_001", "Buildkite Access Token",            "HIGH"),
            new AnchoredRule(TAILSCALE_API_KEY,    "tailscale_api_key",      "TAILSCALE_KEY_001", "Tailscale API Key",                 "HIGH"),
            new AnchoredRule(FLYIO_AUTH_TOKEN,     "flyio_auth_token",       "FLYIO_KEY_001",     "Fly.io Auth Token",                 "HIGH"),
            new AnchoredRule(LANGSMITH_API_KEY,    "langsmith_api_key",      "LANGSMITH_KEY_001", "LangSmith API Key",                 "MEDIUM"),
            new AnchoredRule(LANGFUSE_SECRET_KEY,  "langfuse_secret_key",    "LANGFUSE_KEY_001",  "Langfuse Secret Key",               "MEDIUM"),

            // --- SecretSifter parity: new vendor additions ---
            new AnchoredRule(OKTA_SSWS_TOKEN,      "okta_ssws_token",        "OKTA_KEY_001",      "Okta SSWS API Token",               "HIGH"),
            new AnchoredRule(CIRCLECI_TOKEN,       "circleci_token",         "CIRCLECI_KEY_001",  "CircleCI Personal API Token",       "HIGH"),
            new AnchoredRule(TERRAFORM_CLOUD,      "terraform_cloud_token",  "TERRAFORM_KEY_001", "Terraform Cloud API Token",         "HIGH"),
            new AnchoredRule(SENTRY_AUTH_TOKEN,    "sentry_auth_token",      "SENTRY_KEY_001",    "Sentry Auth Token",                 "HIGH"),
            new AnchoredRule(FIGMA_TOKEN,          "figma_token",            "FIGMA_KEY_001",     "Figma Personal Access Token",       "HIGH"),
            new AnchoredRule(DROPBOX_TOKEN,        "dropbox_token",          "DROPBOX_KEY_001",   "Dropbox Access Token",              "HIGH"),
            new AnchoredRule(SQUARE_ACCESS_TOKEN,  "square_access_token",    "SQUARE_KEY_001",    "Square Access Token",               "HIGH"),
            new AnchoredRule(STRIPE_PK_LIVE,       "stripe_pub_key_live",    "STRIPE_KEY_004",    "Stripe Publishable Key (Live)",     "MEDIUM"),
            new AnchoredRule(CLOUDINARY_URL,       "cloudinary_api_url",     "CLOUDINARY_KEY_001","Cloudinary API URL",                "HIGH"),
            new AnchoredRule(TEAMS_WEBHOOK,        "teams_webhook_url",      "TEAMS_WEBHOOK_001", "Microsoft Teams Webhook URL",       "HIGH"),
            new AnchoredRule(JWT_TOKEN,            "jwt_token",              "JWT_TOKEN_001",     "JSON Web Token (JWT)",              "MEDIUM"),

            // --- SecretSifter parity: Tier A additions ---
            new AnchoredRule(MAPBOX,               "mapbox_access_token",    "MAPBOX_KEY_001",    "Mapbox Access Token",               "HIGH"),
            new AnchoredRule(APIFY_API_TOKEN,      "apify_api_token",        "APIFY_KEY_001",     "Apify API Token",                   "HIGH"),
            new AnchoredRule(ASANA_PAT,            "asana_pat",              "ASANA_KEY_001",     "Asana Personal Access Token",       "HIGH"),
            new AnchoredRule(ELASTIC_API_KEY,      "elastic_api_key",        "ELASTIC_KEY_001",   "Elastic API Key",                   "HIGH"),
            new AnchoredRule(GOOGLE_OAUTH_CLIENT_ID,"google_oauth_client_id","GOOGLE_KEY_002",    "Google OAuth 2.0 Client ID",        "LOW"),
            new AnchoredRule(SQUARE_OAUTH_TOKEN,   "square_oauth_token",     "SQUARE_KEY_002",    "Square OAuth Token",                "HIGH"),
            new AnchoredRule(AZURE_APP_INSIGHTS_CONN,"azure_app_insights_conn","AZURE_CONN_002",  "Azure App Insights Connection String","LOW"),
            new AnchoredRule(GCP_SA_CLIENT_EMAIL,  "gcp_sa_client_email",    "GCP_KEY_001",       "GCP Service Account Email",         "LOW"),

            // --- Additional vendor token patterns ---
            new AnchoredRule(RAZORPAY_LIVE,        "razorpay_live_key",      "RAZORPAY_KEY_001",  "Razorpay Live Key",                 "HIGH"),
            new AnchoredRule(RAZORPAY_TEST,        "razorpay_test_key",      "RAZORPAY_KEY_002",  "Razorpay Test Key",                 "LOW"),
            new AnchoredRule(SUPABASE_PAT,         "supabase_pat",           "SUPABASE_KEY_001",  "Supabase Personal Access Token",    "HIGH"),
            new AnchoredRule(BRAINTREE_TOKEN,      "braintree_access_token", "BRAINTREE_KEY_001", "Braintree OAuth Access Token",      "HIGH"),
            new AnchoredRule(KLAVIYO_API_KEY,      "klaviyo_api_key",        "KLAVIYO_KEY_001",   "Klaviyo Private API Key",           "MEDIUM"),
            new AnchoredRule(STRIPE_WEBHOOK_SECRET,"stripe_webhook_secret",  "STRIPE_KEY_005",    "Stripe Webhook Signing Secret",     "HIGH"),

            // --- Titus parity: gap-closing anchored rules ---
            new AnchoredRule(DEEPSEEK_API_KEY,     "deepseek_api_key",       "DEEPSEEK_KEY_001",  "DeepSeek API Key",                  "HIGH"),
            new AnchoredRule(GCP_OAUTH2_TOKEN,     "gcp_oauth2_access_token","GCP_KEY_003",       "GCP OAuth2 Access Token",           "HIGH"),
            new AnchoredRule(TWITCH_STREAM_KEY,    "twitch_stream_key",      "TWITCH_KEY_001",    "Twitch Stream Key",                 "MEDIUM"),
            new AnchoredRule(PAYSTACK_LIVE_KEY,    "paystack_live_key",      "PAYSTACK_KEY_001",  "Paystack Live API Key",             "HIGH"),
            new AnchoredRule(PAYSTACK_TEST_KEY,    "paystack_test_key",      "PAYSTACK_KEY_002",  "Paystack Test API Key",             "LOW"),
            new AnchoredRule(ONEPASSWORD_SAT,      "onepassword_service_token","ONEPASSWORD_KEY_001","1Password Service Account Token", "HIGH"),
            new AnchoredRule(HARNESS_PAT,          "harness_pat",            "HARNESS_KEY_001",   "Harness Personal Access Token",     "HIGH"),
            new AnchoredRule(SCALINGO_TOKEN,       "scalingo_api_token",     "SCALINGO_KEY_001",  "Scalingo API Token",                "HIGH"),
            new AnchoredRule(ADAFRUIT_IO_KEY,      "adafruit_io_key",        "ADAFRUIT_KEY_001",  "Adafruit IO Key",                   "HIGH"),
            new AnchoredRule(SONARQUBE_TOKEN,      "sonarqube_token",        "SONAR_KEY_001",     "SonarQube / SonarCloud Token",      "MEDIUM"),
            new AnchoredRule(BCRYPT_HASH,          "bcrypt_password_hash",   "PWHASH_KEY_001",    "bcrypt Password Hash (Credential Exposure)", "HIGH")
    );
}
