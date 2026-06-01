---
name: weave-browser
description: Use this skill when the user is building, securing, or auditing a browser-based AI agent (Playwright, Puppeteer, Stagehand, browser-use, or custom browser automation). Triggers on requests to "secure my browser agent", "detect prompt injection in web pages", "block my agent from visiting bad URLs", "scan this page for hidden instructions", "stop my agent from being tricked by web content", or anything involving indirect prompt injection (IPI), agent web scraping security, or WardBrowserGuard. Also useful when reviewing an agent's code that uses page.goto / page.content / response handling for missing IPI defense, and when the user encounters suspicious page content their agent ingested.
---

# Browser-agent security (Weave Protocol)

The `@weave_protocol/browser` package enforces WARD.md policies inside browser-based AI agents and detects indirect prompt injection (IPI) in page content. It's the fifth WARD enforcement surface (after MCP, Claude Code, Antigravity, and MSAF).

## When to use

- User is building a browser agent with Playwright, Puppeteer, Stagehand, browser-use, or similar
- User's agent fetches and reasons about web content (scraping, research, automation)
- User wants to detect indirect prompt injection (IPI) in pages before ingestion
- User wants navigation gating (which URLs the agent may visit)
- User wants download gating (block executables, scripts, etc.)
- User wants to elevate scrutiny on agent actions taken after ingesting untrusted content

## Primary API

```typescript
import { WardBrowserGuard } from '@weave_protocol/browser';

const guard = new WardBrowserGuard({
  // wardPath: './WARD.md'        // explicit; otherwise auto-resolves
  // ipiSensitivity: 'strict' | 'standard' | 'lenient'   // default: 'standard'
  // failMode: 'open' | 'closed'  // default: 'open'
});

// Four enforcement methods:
await guard.checkNavigation(url, sessionId);         // gate URL fetch
await guard.scanForInjection(html, { url, sessionId, isHtml: true });
await guard.checkDownload({ url, filename, mimeType });
await guard.checkAction(capability, sessionId);      // gate tool calls post-ingestion

// One-line Playwright integration:
guard.wrapPlaywrightPage(page, sessionId);
```

## What it detects

33 IPI patterns across these categories:
- **Trigger phrases** (9): "ignore previous", role hijack, chat-template tokens
- **Action directives** (4, critical): send email/payment/exec to X
- **Payment specifications** (1, critical): recipient + amount in proximity (Atlan autonomous-fraud pattern)
- **Hidden CSS content** (6): display:none, visibility:hidden, white-on-white (Brave/Comet pattern), off-screen
- **HTML injection** (5): comments, noscript, aria-hidden, meta tags, alt text
- **Encoding obfuscation** (3): base64, Unicode zero-width, data:text/html
- **Tool-call mimicry** (2): JSON or XML resembling LLM tool calls
- **DoS / suppression** (2): false copyright claims, "do not summarize"
- **SVG + script** (1): XSS+IPI combination

## Decision rules

| Situation | Action |
|---|---|
| User has a Playwright agent | Show `guard.wrapPlaywrightPage(page, sessionId)` one-liner |
| User has a Puppeteer or Stagehand agent | Show the manual hook pattern from README |
| User wants to block specific URLs | WARD `## Network` deny rule + `checkNavigation` |
| User wants to detect IPI | `scanForInjection` — pure detection, no LLM in the loop |
| User worried about agent being tricked into exfiltrating data | Use `checkAction` after ingestion — tainted sessions require approval |
| User worried about malicious downloads | `checkDownload` with custom `blockedExtensions` / `blockedMimeTypes` |
| User wants to dry-run | `weave-browser test-url <url>` or `weave-browser scan <file-or-url>` |
| User has high false-positive tolerance | `ipiSensitivity: 'strict'` |
| User has low false-positive tolerance | `ipiSensitivity: 'lenient'` (only critical blocks) |

## CLI

```bash
weave-browser init [--framework=playwright|puppeteer|stagehand]
weave-browser status
weave-browser test-url <url>
weave-browser scan <file-or-url>
```

## Errors to catch

- `WardBrowserDeniedError` — navigation, download, or action denied by policy
- `IpiDetectedError` — IPI detected at the sensitivity threshold (carries the full scan result)

## Pairs with

- `@weave_protocol/ward` — the policy format being enforced
- Other harness adapters (claudecode, antigravity, msaf) — same WARD.md, different runtimes
- `@weave_protocol/mund` — threat scanner (could feed updated patterns to the browser scanner)
- `@weave_protocol/hundredmen` — MCP-layer enforcement (complementary)

## Anti-patterns

- **Don't use an LLM to detect IPI.** That's vulnerable to the same attack class. This package uses deterministic pattern matching specifically because the scanner itself can't be jailbroken by its input.
- **Don't strip the IPI detector and just allowlist URLs.** Even fully-trusted domains can serve injected content (compromised CDN, user-generated comments, etc.). URL allowlist + content scan is defense-in-depth.
- **Don't ignore `tainted` sessions.** The agent fetching a page with hidden instructions is the *easy* attack; the bug is the agent later acting on those instructions. Use `checkAction` to gate tool calls in tainted sessions.
- **Don't disable `failMode: 'closed'` in production.** If WARD.md is missing in prod, you want the agent to fail loudly, not silently allow everything.

## Real-world incidents this package addresses

- **Brave + Comet OTP exfil (2025)** — hidden white-on-white text → `hidden_text_color` pattern
- **EchoLeak CVE-2025-32711** (Microsoft 365 Copilot zero-click) — `trigger_phrase` + tainted action gating
- **AI ad-review bypass (Dec 2025)** — `trigger_phrase` in product listings
- **Atlan autonomous-fraud (Dec 2025)** — `payment_specification` pattern
- **Forcepoint false-copyright DoS (April 2026)** — `denial_of_service` pattern

If a user reports their agent did something unexpected after browsing a page, the first diagnostic is `weave-browser scan <url>` against that page.
