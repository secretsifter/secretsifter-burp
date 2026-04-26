# Why SecretSifter — purpose, scope, and how it differs from existing options

## What it does

SecretSifter is a passive + active secret-detection extension. It scans HTTP responses (and, when enabled, request bodies and headers) for hardcoded credentials, API keys, JWTs, OAuth tokens, cloud-vendor identifiers, database connection strings, and PII. Findings appear both in Burp's native Issues panel (via Montoya `AuditIssue`) and in a dedicated **SecretSifter** tab that supports bulk URL scanning, filtered triage, and CSV / HTML report export.

Three scan tiers control the depth/noise tradeoff:

| Tier | Scanners run |
| --- | --- |
| FAST | Anchored vendor tokens only |
| LIGHT | + DB connection strings + context-gated rules |
| FULL | + Generic key/value extractor + entropy analyzer + SSR state blob extractor + recursive JSON walk + PII (SSN / credit card) |

## The gap this fills

Burp's built-in active scanner finds runtime vulnerabilities — XSS, SQLi, path traversal, SSRF. It does not look for *static* secrets embedded in JavaScript bundles, JSON config blobs, error pages, sourcemaps, or `__INITIAL_STATE__` blocks. That's a different problem class. The closest existing BApps focus on adjacent problems:

| BApp | Primary focus | Secret coverage |
| --- | --- | --- |
| **JS Miner** | JS file static analysis (endpoints, comments, dependencies, secrets) | Regex-based, JS-only |
| **JS Link Finder** | URL/endpoint discovery in JS | None — endpoints, not secrets |
| **Reflector++ / Param Miner** | Parameter discovery / cache poisoning | None |
| **Burp built-in** | Runtime vulnerabilities | None for static keys |

SecretSifter sits next to JS Miner: complementary, not redundant. The differentiating decisions:

### 1. Secret detection runs across all content types, not just JS

`text/html`, `application/json`, `application/xml`, sourcemaps, response headers, request headers, request bodies (when enabled), and Server-Side Rendering state blobs (`window.__INITIAL_STATE__`, `__NEXT_DATA__`, etc.) are all scanned with the same rule corpus. Many real-world leaks live in HTML inline `<script>` blocks or in JSON config endpoints — not `.js` files.

### 2. Three-tier scanning so users control noise

The same engine can run as a tight passive scan (FAST: anchored tokens only, low FP rate, suitable for always-on browsing) or as a deep audit (FULL: entropy + KV + JSON walk, higher recall on a per-target basis). Most secret scanners give you one mode and force you to live with whatever FP rate it produces.

### 3. Context-gated rules, not just regex

Anchored vendor tokens (Stripe `sk_live_…`, AWS `AKIA…`, Slack `xoxb-…`) are matched verbatim. Generic patterns (a UUID near the word `clientSecret`, a hex string near `aesKey`) require both a structural value match *and* a recognized credential keyword within a bounded window. This catches the credentials that escape pure-anchored scanners while keeping the scan FP rate low enough that the Issues panel stays usable.

### 4. False-positive engineering, not just regex

Substantial code is dedicated to *not* reporting:
- Webpack `[contenthash:20]` chunk hashes (lowercase hex of 16/20/32 chars)
- SRI integrity hashes (`sha256-...`, `sha384-...`)
- Microsoft i18n resource string keys
- ASP.NET ViewState, Salesforce Org IDs
- React/Angular module manifest keys
- DOM identifiers (`domRootId`, `domContainerId`)
- All-alpha or short pure-alphanumeric identifiers (typically class/field names)
- Mendix `metadata` and `microflow` JSON keys

Each suppression has a reason recorded in the source. Users who want everything regardless can flip to **Custom rules only (raw)** mode.

### 5. Bulk Scan tab — batch coverage of known URL lists

Most extensions are passive-only. SecretSifter adds a tab that takes a pasted URL list (or HAR file), fetches each URL through the user's configured proxy, and runs the full rule set on each response. Findings are written to a sortable table; users can mark severity / confidence / `NOISE` per row, then export HTML + CSV reports either as one combined report or one report per host. Useful for retrospective sweeps over a previously-recorded engagement, or pre-engagement reconnaissance from a known asset list.

### 6. Custom rules (CSV-style imports) with optional raw mode

Users can paste or import their own regex rules (`Rule Name | regex | severity` format). Two modes:

- **Default**: custom rules run alongside built-in rules and share the same FP-suppression gates — useful for organisations who want to extend coverage with proprietary token formats while keeping noise filtered.
- **Raw mode** (toggle in Settings → Custom Rules): proxy + bulk scan run *only* user rules and bypass the FP gates. Every regex match becomes a finding. The use case is live investigation when the user already knows the exact format they're hunting and wants to see all of it.

### 7. Unobfuscated, reproducible build

The submitted JAR is built from this repository with `./gradlew shadowJar`. `preserveFileTimestamps = false` and `reproducibleFileOrder = true` are set so reviewers can produce a byte-identical artifact for SHA-256 verification.

## What's intentionally out of scope

- **Active exploitation.** Findings are reported; nothing is replayed, exfiltrated, or used to authenticate.
- **Outbound network from the extension itself.** Network calls are made only when the user (a) initiates a bulk scan or (b) launches headless Chrome from the bulk scan tab. No telemetry, no auto-update, no phone-home.
- **Listening sockets.** None. The extension binds no ports.
- **Disk persistence outside Burp's `Preferences`.** The only files written are user-initiated exports (CSV / HTML report) at user-chosen paths, plus user-initiated rule import/export.

## Compliance notes for BApp Store review

- **Listening sockets**: none. The extension does not bind any ports.
- **Reflection / dynamic class loading**: none.
- **Outbound HTTP**: gated behind explicit user actions (bulk scan with user-supplied URL list).
- **File system writes**: user-initiated only, via Swing `JFileChooser`.
- **Process execution**: only when the user enables "Headless Browse" in the Bulk Scan tab — launches Chrome/Chromium for sites that require JS execution to render. Path lookup uses `where`/`which` and respects `PATH`.
- **Dependencies**: Gson 2.10.1 (Apache 2.0). Montoya API and JUnit are `compileOnly` / `testImplementation` only — neither is bundled into the JAR.
- **License**: MIT. See [LICENSE](LICENSE).

## Repository layout

```
src/main/java/com/secretscanner/
├── SecretScannerExtension.java   ← BurpExtension entry point
├── SecretScanner.java            ← detection engine
├── Patterns.java                 ← anchored token + context-gated rule definitions
├── ScanSettings.java             ← persisted user preferences
├── SecretScanCheck.java          ← Burp passive scan integration (AuditIssue)
├── SecretProxyHandler.java       ← live proxy traffic scanning
├── SecretContextMenu.java        ← right-click "Rescan for Secrets" menu
├── BulkScanPanel.java            ← Bulk Scan tab UI
├── SettingsPanel.java            ← Settings tab UI
├── ScopeMonitor.java             ← passive proxy capture for watched hosts
├── SitemapDeduplicator.java      ← group findings before pushing to AuditIssue
├── HtmlReportGenerator.java     ← HTML report builder
├── SecretSifterTab.java          ← inline response editor tab
└── ToggleSwitch.java             ← Swing toggle widget
```

To build:

```bash
./gradlew shadowJar
# output: build/libs/secretsifter-bapp-<version>.jar
```
