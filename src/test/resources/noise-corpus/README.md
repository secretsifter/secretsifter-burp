# Noise corpus

Unmodified third-party front-end library bundles that contain no secrets. `NoiseCorpusTest`
scans each one at FULL tier and fails if anything above INFORMATION is reported, so a rule or
gate change that starts flagging framework internals (for example React's
`"__reactResources$" + randomKey`) breaks the build instead of shipping.

| File | Library | Version | Licence | Form |
|---|---|---|---|---|
| react-dom_client.vite.js | react-dom (client) | 19.3.1 | MIT, Copyright (c) Meta Platforms, Inc. and affiliates | Vite dev pre-bundle |
| react.vite-chunk.js | react (shared chunk) | 19.3.1 | MIT, Copyright (c) Meta Platforms, Inc. and affiliates | Vite dev pre-bundle |
| framer-motion.vite.js | framer-motion | 12.43.0 | MIT, Copyright (c) 2018 Framer B.V. | Vite dev pre-bundle |
| react-router-dom.vite.js | react-router-dom | 7.18.4 | MIT, Copyright (c) React Training LLC / Remix Software Inc. | Vite dev pre-bundle |
| lodash.js | lodash | 4.17.23 | MIT, Copyright OpenJS Foundation and other contributors | npm package build |
| vue.global.js / vue.global.prod.js | vue | 3.5.44 | MIT, Copyright (c) 2018-present Yuxi (Evan) You | npm dist (dev / minified) |
| angular-core.fesm2022.mjs / angular-core.debug-node-chunk.mjs | @angular/core | 22.2.3 | MIT, Copyright (c) 2010-2026 Google LLC | npm fesm2022 |
| jquery.js / jquery.min.js | jquery | 4.0.0 | MIT, Copyright OpenJS Foundation and other contributors | npm dist (dev / minified) |
| moment.js / moment-with-locales.min.js | moment | 2.31.0 | MIT, Copyright (c) OpenJS Foundation and other contributors | npm (dev / minified with locales) |
| chart.js / chart.umd.min.js | chart.js | 4.6.1 | MIT, Copyright (c) 2014-2024 Chart.js Contributors | npm dist (ESM / minified UMD) |
| three.module.js / three.core.js | three | 0.186.1 | MIT, Copyright (c) 2010-2026 three.js authors | npm build |

npm packages were fetched with `npm pack` at the pinned versions above (no install scripts run).
Used for testing only; not shipped in any JAR. Add bundles here when a false positive from a
library is fixed, so it stays fixed.
