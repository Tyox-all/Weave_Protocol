# 🌐 Weave Browser Guard

**Browser extension for Chrome and Firefox.** Detects indirect prompt injection (IPI) in web pages — read-only inspection of pages your AI agent (or you) might be ingesting.

> *The same 33-pattern IPI scanner that powers [`@weave_protocol/browser`](../browser), packaged as a browser extension so anyone can see what's hiding on the pages they visit.*

---

## What it does

- Scans every web page you visit for indirect prompt injection patterns
- Shows a badge on the toolbar icon when threats are detected
- Click the icon to see threat details, severity, evidence excerpts
- Three sensitivity modes (strict / standard / lenient)
- 100% local — nothing leaves your browser, no telemetry, no phone home

**What it does NOT do** (by design):
- Block pages or content (read-only)
- Modify the DOM
- Intercept requests
- Capture your data
- Require any account or login

---

## Install (development / unpacked)

Until the extension is on the Chrome Web Store and Firefox AMO (in review), you load it manually:

### Chrome / Edge / Brave

1. Open `chrome://extensions/`
2. Toggle **Developer mode** on (top-right)
3. Click **Load unpacked**
4. Select the `browser-extension/` directory from this repo
5. Pin the extension to your toolbar

### Firefox

1. Open `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on**
3. Select `browser-extension/manifest.json`

Note: Firefox temporary add-ons unload when you restart Firefox. For permanent install, the extension will need to be signed via AMO (planned).

---

## How it works

1. **Content script** runs on every HTTP(S) page at `document_idle` (after the page's own JS has had a chance to run, so hidden content injected by JS is also scanned)
2. **Scanner** runs the same 33 IPI patterns from `@weave_protocol/browser` against the rendered HTML
3. **Background worker** receives the result, updates the toolbar badge per tab, and stores the result for the popup
4. **Popup** displays the findings when you click the icon

### Badge meanings

| Badge | Risk level | What it means |
|---|---|---|
| (none) | none | No IPI patterns detected. Page appears clean. |
| `!` amber | medium | Suspicious patterns. Worth a look. |
| `✗` red | high | High-risk content. Agent could be manipulated. |
| `☠` purple | critical | Hostile instructions explicitly target AI agents. |

The badge only appears for the risk levels matching your **sensitivity** setting (default: high+critical).

---

## Sensitivity settings

Open the extension's options page to adjust:

- **Strict** — badge shows on any threat (low+). Best for security researchers and red-teamers who want to see every pattern.
- **Standard (default)** — badge shows on high or critical threats. Best for general use.
- **Lenient** — badge shows only on critical threats. Best for low-noise use.

The popup always shows all findings regardless of sensitivity — sensitivity only affects when the badge appears.

---

## Patterns detected

33 patterns across 20 threat categories. Mirrors the scanner shipped in `@weave_protocol/browser`. Updated as new in-the-wild IPI patterns are documented.

- Trigger phrases (9): "ignore previous instructions", role hijack, chat tokens
- Action directives (4, critical): "send email to X", "transfer $Y", "execute:"
- Payment specifications (1, critical): recipient + amount in proximity
- Hidden CSS content (6): display:none, white-on-white (Brave/Comet pattern)
- HTML structural (5): comments, noscript, aria-hidden, meta, alt text
- Encoding obfuscation (3): base64 near decode keywords, Unicode zero-width
- Tool-call mimicry (2): JSON/XML resembling LLM tool calls
- DoS / suppression (2): false copyright claims, "do not summarize"
- SVG + script (1): combined XSS + IPI vector

See [`browser/README.md`](../browser/README.md) for full pattern documentation.

---

## Privacy and permissions

The extension declares the minimum permissions needed:

- **`storage`** — saves your sensitivity preference locally
- **`activeTab`** — needed for the popup to interact with the current tab when you click the icon

The extension does NOT request:
- `tabs` (the broad read-all-tabs permission)
- `cookies`
- `webRequest` (request interception)
- Any host permissions beyond the content_scripts matches

The content script runs on `<all_urls>` (necessary to scan arbitrary pages) but is excluded from major sign-in flows and banking sites in the manifest. The scanner runs entirely in-page; results are sent only to the extension's background worker (same-origin from the extension's perspective).

**No data leaves your browser.** No telemetry. No analytics. No remote logging.

---

## Sites excluded by default

The content script doesn't run on:

- Google sign-in (`accounts.google.com`)
- Microsoft sign-in (`login.microsoftonline.com`)
- Bank of America, Chase

This isn't because these sites are unsafe — it's so the extension doesn't even *touch* pages where any inspection feels intrusive.

To suggest additions, file an issue.

---

## Building / packaging for store distribution

```bash
# In the browser-extension/ directory:

# 1. Make sure icons are rendered (only needed once or after icon.svg changes)
node scripts/build-icons.js  # uses sharp; install with: npm install sharp

# 2. Pack for Chrome Web Store
cd browser-extension
zip -r ../weave-browser-guard-chrome.zip . -x "*.DS_Store" "node_modules/*" "icons/icon.svg"

# 3. Submit at https://chrome.google.com/webstore/devconsole
# 4. For Firefox: submit the same .zip at https://addons.mozilla.org/developers/
```

---

## Roadmap

**v0.1 (this release):**
- ✅ Manifest V3 (Chrome + Firefox compatible)
- ✅ Read-only IPI scanning on all pages
- ✅ Badge with severity color + icon
- ✅ Popup with full threat breakdown
- ✅ Options page with sensitivity control
- ✅ Sensitive-site exclusions

**v0.2 (planned):**
- [ ] In-page threat highlighting (scroll-to-finding from popup)
- [ ] Per-domain whitelist / blacklist
- [ ] Export findings (JSON, CSV) for security teams
- [ ] Pattern update feed (auto-pull new patterns as the npm package updates)
- [ ] Optional integration with `@weave_protocol/api` dashboard

**v1.0 (future):**
- Real-time alert when an AI browser (Comet, Atlas, Claude for Chrome) is about to ingest a flagged page
- Custom user-defined pattern packs
- Sigstore-style provenance for the pattern catalog itself

---

## License

Apache 2.0 — same as the rest of [Weave Protocol](https://github.com/Tyox-all/Weave_Protocol).
