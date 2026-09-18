# Verifier rendering tests

The standalone HTML page has no runtime dependencies. Its regression tests use
Node >= 20 and Playwright to exercise the actual page in a headless browser:

```sh
cd verifier
npm install
npx playwright install chromium
npm test
```

To use an installed Chrome instead, set `BROWSER_CHANNEL=chrome` (PowerShell:
`$env:BROWSER_CHANNEL = "chrome"`) and run `npm test`; the browser download is
then unnecessary. `VERIFIER_HTML` can point to an absolute HTML file path to
check a previous version against the regressions.

The tests load local files and use a harmless `onerror` marker with a data URL;
they need no server or network. They cover the three formerly unescaped fields
(`stub.seq`, `stub.kind`, event `seq`) with valid and invalid signatures, every
event-detail branch (including each external-evidence display field), metadata,
process context, timestamp rendering, repeated
loads, and the file input. They require literal text, no injected elements, and
no handler execution. Signature-valid attack fixtures only establish signature
validity; their internal validation failures are intentional.

Both conformance manifests are checked with the reference verifier, and all
28 golden packets are rendered in the browser. Browser checks preserve existing
messages and rendering; they do not add validation rules or claim that the HTML
verifier enforces the session-chain draft's migration guards.

## Why a real browser

The injection assertions depend on HTML parsing and event-handler execution.
A minimal DOM that stores `innerHTML` as a string cannot exercise either, so an
inert execution marker there would not demonstrate that a packet is safe to
render. These tests check both literal DOM text and the execution marker in a
real browser, and fail against the vulnerable HTML.

Use this runner for additional HTML-verifier coverage: it already loads both
conformance manifests and runs the actual page with WebCrypto. Add verification
assertions to the golden-vector test or rendering cases as subtests rather than
introducing another simulated DOM. Playwright is used only for development;
the shipped verifier and the reference conformance verifier remain dependency-free.
