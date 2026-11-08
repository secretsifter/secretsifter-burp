# Snapshot corpus

Fixed inputs for `SnapshotTest`, which records every finding the engine produces and fails
if a refactor changes any of them. This is a regression fixture, not a benchmark.

| Folder | Source | Notes |
|---|---|---|
| `insecureshield/` | `github.com/secretsifter/insecureshield-demo` @ 581db9e, `public/` (without `.original/`) | Demo app with planted, non-functional secrets; inflated bundles are 0.5-3 MB |
| `libs/` | npm packages from the same demo's `node_modules` (express, jsonwebtoken, jws, qs, iconv-lite, mime-db, semver, path-to-regexp, send, body-parser, cookie, object-inspect, debug, ipaddr.js, http-errors) | Real library code with no secrets; used as noise. Each package keeps its own MIT licence |

Regenerate the golden file only when a findings change is intended:
`./gradlew test --tests com.secretscanner.SnapshotTest -Dsnapshot.update=true`
