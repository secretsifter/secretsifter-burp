# Per-tool run configuration

Every rule-extensible scanner received the same six-rule overlay in
[`six_rule_overlay.yaml`](six_rule_overlay.yaml), applied identically with no
per-tool tuning. Findings were matched to ground truth by exact-value substring
lookup with no other post-processing. The full protocol is in the companion
study; this file records the invocations so the workflow is inspectable.

Environment: macOS (Darwin), Burp Suite Professional hosting the Burp-extension
scanners (SecretSifter, JSMiner, Sensitive Discoverer), Python 3.12.

## SecretSifter
Built-in configuration. Field-deployment scan output exported via the
SecretSifter REST API (`/api/findings`).

## TruffleHog
Filesystem scan of the bundle set with the six-rule overlay added as custom
regex detectors:
```
trufflehog filesystem <bundles-dir> --config six_rule_overlay.yaml --json
```

## SecretFinder / Titus
Run against each bundle with the same six patterns added to the tool's
user-rule set; no built-in rule removed.

## JSluice
The six patterns translated to the JSluice user-pattern JSON schema:
```
jsluice secrets --patterns six_rules.json <bundle>.js
```
The built-in JSluice secret rules produce zero output on the minified webpack
bundles in this corpus; the user-pattern overlay is what surfaces its recall.

## Nuclei
URL-mode JavaScript-spider configuration. Bundles served over a local HTTP
server; scanned with the secret-scanning template categories and tags:
```
python3 -m http.server 9101 &   # serve bundles
nuclei -u http://127.0.0.1:9101/<bundle>.js \
  -t http/exposures/tokens -t http/exposures/apis -t http/exposures/keys \
  -tags secret,token,key,exposure
```
File-mode Nuclei produces zero findings on raw `.js` files because its
secret-scanning templates are HTTP-response-oriented, not file-content-oriented.

## JSMiner
Exposes no user-rule API in its Burp distribution, so it was reimplemented in
Python as a faithful clone of the published Trustwave SpiderLabs detection logic
(21 keyword anchors plus Shannon-entropy scoring at the same Firm/Tentative
thresholds) and run over the corpus.

## Cariddi
Built-in default secret-detection configuration, no overlay (its primary mode is
web-crawling and endpoint enumeration; secret detection is secondary).

## Claude Opus (oracle)
The LLM used to construct ground truth. Reported as a labeling reference in the
matrix, not a competing scanner. Every label was independently validated by a
different-vendor LLM (GPT-5.5).
