# SecretSifter — BApp Store Description

## Short description (≤ 160 characters)

Detects exposed API keys, credentials, and PII in HTTP traffic. 100+ vendor token rules, entropy scanning, Bulk Scan, and HTML reports.

---

## Full description (plain text for BApp Store form)

SecretSifter detects exposed secrets, API keys, credentials, and PII in HTTP traffic passing through Burp Suite.

**Passive scanning** fires automatically on every proxied response. On load, the extension also sweeps all responses already recorded in Burp's site map — no manual configuration needed.

**Detection coverage:**
- 100+ anchored vendor token rules: GitHub, GitLab, AWS, Stripe, OpenAI, Slack, Azure, GCP, and more
- 40+ context-gated rules: Algolia, Cloudflare, Salesforce, Auth0, Supabase, and more
- Request header scanning: App_key, Resource, Ocp-Apim-Subscription-Key, and other credential headers
- Generic key-value and high-entropy scanner for unlisted vendor tokens
- PII: SSN and credit card detection (Luhn-validated)
- Database connection strings with embedded credentials

**Bulk Scan tab:** paste or import a list of URLs, follow script-src and webpack chunks, optionally launch Chrome headless for dynamic JS capture. Export findings as CSV or interactive HTML report (all-in-one or per-domain ZIP).

**Custom regex rules:** Import your own `Rule Name | regex | severity` lines via Settings → Custom Rules. Optional raw mode skips built-in scanners and FP filters for pure pattern matching.

**False positive reduction:** CDN blocklist, 60+ noise key filter, JWT suppression, UUID rejection, Angular/Vue directive filter, configurable key blocklist and allowlist.

Works in Burp Suite Professional (findings appear in Dashboard → Issue Activity) and Community Edition (findings in Bulk Scan table and HTML/CSV export).

---

## Category

`Passive scanning` / `Information gathering`

---

## Minimum Burp Suite version

`2024.7`

---

## Author

Hemanth Gorijala

