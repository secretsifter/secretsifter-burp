# Changelog

All notable changes to SecretSifter are documented here.

## [1.0.1] — 2026-04-26

### New features
- **Custom rules only (raw) mode** — new toggle in Settings → Custom Rules. When enabled, the proxy and bulk-scan paths run *only* user-supplied custom rules and bypass the false-positive filters; every regex match is reported as-is. Built-in scanners are skipped. Allow/blocklist/CDN list still apply. Burp's audit (Issues panel) is unaffected.
- **NOISE marking** — Severity and Confidence dropdowns now include a `NOISE` option. Rows marked NOISE are rendered in light gray with dimmed text and excluded from HTML / CSV / ZIP exports. The row stays visible in the table for manual unmarking.
- **Target Status CSV bundled into report ZIPs** — the per-target reachability/auth status (which URLs were scanned, failed, or hit SSO) is now automatically included in the **All-in-one** and **Per-Domain** ZIP exports as a third file.
- **Multi-file import for custom rules** — Ctrl/Cmd+click to select multiple `.txt` files; content is appended, not replaced.
- **Enable custom rules toggle** — keep imported rules stored without running them during scans.
- **Custom rules now run on all scan tiers** (FAST, LIGHT, FULL) — previously only on FULL.

### Bug fixes
- **Per-occurrence reporting in minified bundles** — same key/value at different file offsets (or different lines) now produces a separate finding row. Previously, dedup keys ignored byte offset and collapsed N matches at `lineNumber=1` into one row.
- **Multi-target attribution** — when scanning multiple targets concurrently, a target's own assets always attribute to that target row, regardless of which scan thread fetched the URL first via cross-origin chunk discovery. Previously, race conditions on the shared `seenUrls` set could attribute one target's findings to another.
- **AES_KEY / AES_IV detection** — added case-transition heuristic to `isProbableSecretValue()` so 32-char alphanumeric AES keys are no longer rejected as identifiers. `iv`, `nonce`, `salt` keys are now gated by a recognised crypto prefix (`aes`, `hmac`, `encrypt`, `cipher`, …).
- **Webpack content hash suppression** — exactly 16- and 20-char lowercase hex values no longer surface as findings; these match webpack's default `[contenthash:20]` chunk-hash format.
- **Homogeneity check** — repeated-character strings (e.g. `AAAAAAAAAAAAAAAA`) no longer match anchored token patterns. Any value where a single character accounts for >60% of the string is rejected as noise.
- **Session identifier suppression** — `sessionId`, `session_id`, `jsessionid`, `phpsessid`, `asp.net_sessionid`, `sessid`, `sessionstate`, and variants added to the noise key filter.
- **PEM private key — header-only constants suppressed** — bare `-----BEGIN RSA PRIVATE KEY-----` string literals (no key body) no longer produce findings.
- **Opaque Bearer token suppression** — `Authorization: Bearer <token>` in request headers is suppressed unless the token starts with a known vendor prefix (`ghp_`, `sk-`, `SG.`, `shpat_`, etc.).
- **Structural key suffix filter** — key names ending in `Type`, `Error`, `State`, or `Kind` are now excluded from the generic KV and entropy scanners.
- **JS code-fragment value guard** — values containing `this.`, `),`, `)}`, or `){` are rejected as minified JavaScript code fragments.
- **Settings tooltip rendering** — the *Custom rules only (raw)* tooltip is now plain text. Previously the multi-line HTML version rendered as literal markup in some Burp/Swing variants.
- **Community rules — 8 noisy patterns fixed** — `SumoLogicAccessId`, `SumoLogicAccessKey`, `DroneCIToken`, `MessageBirdApiKey`, `NetlifyAccessToken`, `CodecovAccessToken`, `OktaApiToken` tightened with vendor-prefix or keyword context; duplicate `CohereApiKey` removed.

### UI
- Settings panel filter row reorganised into three columns (CDN Blocklist / Key Name Blocklist / Key Name Allowlist), freeing vertical space for the Custom Rules textarea.

---

## [1.0.0] — 2026-03-19

### Initial release

**Passive scanning**
- Registers a `ScanCheck` with Burp's Scanner API (Pro); fires on every proxied response
- Sitemap sweep on load: scans all existing site-map responses immediately after extension loads
- Proxy handler fires for all traffic regardless of target scope (like JSMiner)
- Findings injected as `AuditIssue` into Dashboard → Issue Activity and Target → Site map

**Active scanning**
- Right-click context menu item "Rescan for Secrets" in Proxy History, Repeater, Logger, Site Map
- Expands selection to full site-map coverage for the selected host(s)
- Results shown in a resizable dialog; optionally save an HTML report

**Bulk Scan tab**
- Paste / import URL lists (`.txt`, `.csv`)
- HAR file import — scan responses from `.har` files (handles auth-walled targets offline)
- Follows `<script src>` references in HTML responses
- Follows webpack / Next.js chunk references (depth 1)
- Scope Monitor: passively routes proxy findings for watched hosts into the results table
- Cross-origin API tracking via `Referer`/`Origin` headers (opt-in)
- Headless Browse: launches Chrome/Chromium or Microsoft Edge through Burp proxy to capture dynamic XHR/Fetch calls; requires user consent dialog on first use; persists consent via Burp preferences
- 1–50 concurrent worker threads (default 25)
- URL-based dedup: same URL never scanned twice per session
- Per-finding dedup: same (ruleId, value) pair not duplicated between headless and active fetch paths
- Site-map index built at scan start: prefers authenticated site-map bodies over unauthenticated active-fetch bodies for SSO-protected targets

**Detection rules**
- 100+ format-anchored vendor token patterns (near-zero FP): GitHub PAT/OAuth/Actions/Refresh/Fine-grained, GitLab PAT/Deploy, NPM, Slack Bot/User/App/Config/Webhook, Stripe (Live/Test/Restricted/PK/Webhook), SendGrid, Twilio, OpenAI, OpenAI Project, Anthropic, Shopify, HubSpot, Mailchimp, Databricks, Google Maps/API key, AWS AKIA/ASIA/AROA/AIDA, Mapbox, PEM private keys, HashiCorp Vault, Pulumi, Linear, Notion (old+new), Netlify, Firebase FCM, Airtable, WooCommerce, Discord Bot/Webhook, Twitter/X Bearer, New Relic License/Ingest, Dynatrace, Telegram Bot, Mailgun, PagerDuty, Age Encryption, Alibaba Cloud, Atlassian API, Contentful, DigitalOcean Personal/OAuth, Doppler, Duffel, EasyPost (live+test), Flutterwave (pub+sec), Frame.io, Grafana SA/Cloud, PlanetScale PW/Token, Postman, PyPI, SendinBlue/Brevo, Shippo, Azure Storage Connection String, Rubygems, Hugging Face, Groq, Replicate, xAI/Grok, Buildkite, Tailscale, Fly.io, LangSmith, Langfuse, Okta SSWS, CircleCI, Terraform Cloud, Sentry, Figma, Dropbox, Square Access/OAuth, Cloudinary, Teams Webhook, Azure App Insights, GCP Service Account Email, GCP OAuth2 Token, Razorpay (live+test), Supabase, Braintree, Klaviyo, Stripe Webhook Secret, DeepSeek, Twitch Stream Key, Paystack (live+test), 1Password Service Account, Harness PAT, Scalingo, Adafruit IO, SonarQube/SonarCloud, bcrypt hash, Google OAuth2 Client ID, Asana PAT, Elastic ApiKey, Apify
- 40+ context-gated rules: high-entropy scanner with configurable threshold (default 3.5 bits/char), generic key=value scanner (REAL_SECRET_KEYNAME set), SSR state blob walker (Next.js `__NEXT_DATA__`, Nuxt, Redux), JSON deep walker (depth 20, 50-finding cap), DB connection strings (MongoDB, PostgreSQL, MySQL, Redis, AMQP, JDBC), URL-embedded credentials, .NET/ADO.NET connection strings

**PII detection (FULL tier)**
- Social Security Numbers with structural exclusions (000/666/9xx prefix, 00 middle, 0000 suffix)
- Credit card numbers: Visa, Mastercard, Amex, Discover, Diners, JCB — Luhn-validated

**Request header scanning (opt-in)**
- Scans custom credential-bearing headers: `X-API-Key`, `Api-Key`, `X-Auth-Token`, `X-Access-Token`, `Ocp-Apim-Subscription-Key`, `X-Service-Account-Token`, `App-Key`, `Resource`, `Authorization` (non-JWT values only), `X-Amz-Security-Token`, `X-Goog-Api-Key`
- Semantic key detection: compound identifier contains a secret-domain prefix AND a secret-type suffix
- Per-session dedup: same credential value not reported again after first request finding

**JWT intelligence**
- JWTs in `Authorization: Bearer` headers are never reported (normal authenticated traffic)
- JWTs in responses to requests that carry non-JWT credentials are upgraded to HIGH (token-issuance endpoint pattern)
- JWTs in responses to JWT-authenticated requests are suppressed (normal API response noise)
- JWTs in response bodies on unauthenticated endpoints are reported at MEDIUM (unexpected token leakage)

**False-positive mitigations**
- `isPlaceholder()` filter: suppresses values containing "example", "placeholder", "your_", "insert_", "xxxx", "test123", "changeme", "dummy", and similar documentation stand-ins
- UUID rejection: entropy scanner ignores `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` format values
- Noise key filter: 60+ key names excluded by default (`client_id`, `redirect_uri`, `nonce`, `state`, `tenant_id`, UI component names, date/time fields, etc.)
- CDN blocklist: pre-populated with Google Tag Manager, Google Analytics, Segment, Mixpanel, Amplitude, Hotjar, FullStory, DoubleClick, Facebook, Intercom, and others
- Angular/Vue directive filter: framework attribute prefixes excluded from KV scanner
- CC floating-point guard: rejects credit-card-shaped numbers where surrounding digits suggest a floating-point literal
- Blockchain hash rejection: `tx`, `txid`, `block`, `eth`, `wallet` key names excluded from entropy scanner
- Key name blocklist: user-configurable substring suppression (persisted to Burp preferences)
- Key name allowlist: user-configurable force-report for project-specific credential patterns

**Export**
- HTML report: self-contained, all findings, filterable by severity, CSV download button
- Per-domain ZIP: one HTML report file per hostname, zipped for easy sharing
- CSV export: spreadsheet-compatible, all finding fields

**Settings (persisted across sessions)**
- Global enable/disable toggle
- Scan tier selector (FAST / LIGHT / FULL)
- Shannon entropy threshold (0.0–6.0, step 0.1; default 3.5)
- PII detection toggle
- Request header scanning toggle
- CDN blocklist (one hostname per line)
- Key name blocklist (substring patterns)
- Key name allowlist (substring patterns)

**Architecture**
- Full Montoya API (2024.7+) — not the legacy Extender API
- Community Edition compatible: Scanner API registration gracefully skipped; all other features work
- Stateless scanner core: `scanText()` is safe for concurrent calls
- Background thread pools: proxy pipeline never blocked by pattern-matching work
- Clean unloading (BApp criterion #6): all three executor services shut down on extension unload; `ScopeMonitor` listener cleared; sitemap sweep thread interrupted
- macOS EDT fix: `api.siteMap().requestResponses()` always called on the Swing EDT via `SwingUtilities.invokeAndWait()` — prevents silent empty-list return on macOS
- Cross-platform Chrome detection: macOS (Chrome + Chromium + Edge), Windows (Chrome + Edge in standard Program Files + LocalAppData paths, with `where` PATH fallback), Linux (`google-chrome`, `google-chrome-stable`, `chromium`, `chromium-browser` with `which` fallback)
- Isolated Chrome profile per scan thread (`--user-data-dir` in system temp) — prevents profile lock conflicts when Chrome is already running
