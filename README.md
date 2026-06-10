# 🕸️ Weave Protocol

> **Four runtimes. Three vendors. One policy file.**
> *Agent security that travels with your policy, not your harness.*

[![npm](https://img.shields.io/npm/v/@weave_protocol/full?label=%40weave_protocol%2Ffull&color=000000&style=flat-square)](https://www.npmjs.com/package/@weave_protocol/full)
[![PyPI](https://img.shields.io/pypi/v/weave-protocol-llamaindex?label=PyPI&color=000000&style=flat-square)](https://pypi.org/project/weave-protocol-llamaindex/)
[![License](https://img.shields.io/badge/license-Apache--2.0-000000?style=flat-square)](LICENSE)
[![Dependabot](https://img.shields.io/badge/dependabot-enabled-000000?style=flat-square)](https://github.com/Tyox-all/Weave_Protocol/blob/main/.github/dependabot.yml)

Weave Protocol is an enterprise security suite for AI agents. **One WARD.md policy file** is enforced by five independent runtimes — across MCP servers, three major vendor harnesses (Anthropic, Google, Microsoft), and browser-based agents — so security travels with the policy, not the harness.

---

## 🚀 Quick start

```bash
# Install the full suite (all 15 packages bundled)
npm install -g @weave_protocol/full

# Initialize a WARD.md policy
npx @weave_protocol/ward init

# Install the harness adapters relevant to your stack
npx @weave_protocol/adapter-claudecode   install   # Anthropic
npx @weave_protocol/adapter-antigravity  install   # Google
npx @weave_protocol/adapter-msaf         install   # Microsoft
```

Visit [http://localhost:3000/dashboard](http://localhost:3000/dashboard) after running `npx @weave_protocol/api` for live monitoring.

---

## 🏛️ Architecture

```
                  ┌──────────────────┐
                  │     WARD.md      │
                  │  policy standard │
                  └────────┬─────────┘
                           │
       ┌───────────┬───────┼───────┬───────────┐
       │           │       │       │           │
  ┌────▼────┐ ┌────▼────┐ ┌▼────┐ ┌▼───────┐ ┌─▼──────┐
  │Hundred- │ │ adapter │ │adptr│ │adapter │ │browser │
  │  men    │ │claude-  │ │anti-│ │  msaf  │ │  +     │
  │ (MCP)   │ │  code   │ │grav.│ │        │ │  IPI   │
  └─────────┘ └─────────┘ └─────┘ └────────┘ └────────┘
   MCP layer   Anthropic   Google  Microsoft  Playwright
```

**The bet:** Standardize the policy file, not the SDK. Make every major agent runtime obey the same rules without needing to change how the agent is built.

---

## 📦 Packages

### npm (`@weave_protocol/` scope)

| Package | Version | Purpose |
|---|---|---|
| [`@weave_protocol/full`](https://www.npmjs.com/package/@weave_protocol/full) | 0.2.1 | Meta-package bundling all 13 below |
| [`@weave_protocol/ward`](https://www.npmjs.com/package/@weave_protocol/ward) | 0.1.1 | WARD.md spec, parser, validator, CLI |
| [`@weave_protocol/api`](https://www.npmjs.com/package/@weave_protocol/api) | 1.1.0 | HTTP API + **live dashboard v2** |
| [`@weave_protocol/cli`](https://www.npmjs.com/package/@weave_protocol/cli) | 0.1.0 | Unified `weave` command |
| **MCP layer** | | |
| [`@weave_protocol/hundredmen`](https://www.npmjs.com/package/@weave_protocol/hundredmen) | 1.1.1 | MCP interceptor — WARD enforcement at the MCP layer |
| [`@weave_protocol/mund`](https://www.npmjs.com/package/@weave_protocol/mund) | 0.2.3 | Threat scanning, auth, origin validation |
| [`@weave_protocol/hord`](https://www.npmjs.com/package/@weave_protocol/hord) | 0.1.7 | Secure storage, attestations, sandboxes |
| [`@weave_protocol/domere`](https://www.npmjs.com/package/@weave_protocol/domere) | 1.3.5 | Intent threading, drift detection, blockchain anchoring |
| [`@weave_protocol/witan`](https://www.npmjs.com/package/@weave_protocol/witan) | 1.0.3 | Consensus + governance |
| [`@weave_protocol/tollere`](https://www.npmjs.com/package/@weave_protocol/tollere) | 0.2.3 | Supply chain scanning |
| **Harness adapters** | | |
| [`@weave_protocol/adapter-claudecode`](https://www.npmjs.com/package/@weave_protocol/adapter-claudecode) | 0.1.0 | Anthropic — Claude Code hook |
| [`@weave_protocol/adapter-antigravity`](https://www.npmjs.com/package/@weave_protocol/adapter-antigravity) | 0.1.0 | Google — Antigravity desktop + CLI + SDK |
| [`@weave_protocol/adapter-msaf`](https://www.npmjs.com/package/@weave_protocol/adapter-msaf) | 0.1.0 | Microsoft — Agent Framework middleware |
| [`@weave_protocol/browser`](https://www.npmjs.com/package/@weave_protocol/browser) | 0.1.0 | Browser agents — Playwright/Puppeteer + 33-pattern IPI scanner |
| **Framework integrations** | | |
| [`@weave_protocol/langchain`](https://www.npmjs.com/package/@weave_protocol/langchain) | 1.0.1 | LangChain integration |

### PyPI

| Package | Version | Purpose |
|---|---|---|
| [`weave-protocol-llamaindex`](https://pypi.org/project/weave-protocol-llamaindex/) | 0.1.0 | LlamaIndex integration (Python) |

### Browser extension (Chrome + Firefox)

| Package | Status | Purpose |
|---|---|---|
| [`weave-browser-guard`](browser-extension/) | preview | End-user IPI detection — see what hostile content is targeting AI agents on the pages you visit |

---

## 🛡️ WARD.md — the policy file

WARD.md is a portable, vendor-neutral standard for agent security policy. **One file, enforced everywhere:**

```yaml
---
ward: "1.0"
agent: my-research-agent
name: Research Agent Security Policy
---

## Network
allow:
  - url: "https://api.github.com/**"
  - url: "https://docs.python.org/**"
deny:
  - url: "https://**/credentials.*"
default: deny

## Capabilities
allow:
  - file_read
  - file_write
requireApproval:
  - http_request
  - send_email
deny:
  - shell_exec
  - file_delete
default: deny

## Behavioral Limits
maxIterations: 25
maxRuntimeSeconds: 300
maxCostUSD: 5.00
```

10 policy domains: Filesystem, Network, Capabilities, Data Boundaries, Behavioral Limits, Multi-Agent, Compliance, Verification, Threat Model, Incident Response.

[📖 Full WARD.md specification →](ward/README.md)

---

## 🔒 Five enforcement surfaces

Every surface reads the same WARD.md and enforces the same rules at its own layer:

| Surface | Layer | What it gates |
|---|---|---|
| **Hundredmen** (MCP) | MCP server interception | Any tool call routed through an MCP server |
| **adapter-claudecode** (Anthropic) | PreToolUse hook in `~/.claude/settings.json` | Bash, Read, Write, Edit, WebFetch, etc. |
| **adapter-antigravity** (Google) | Hook in `~/.gemini/antigravity-cli/settings.json` | Desktop + agy CLI + SDK |
| **adapter-msaf** (Microsoft) | Library middleware (programmatic) | Agent Framework tool invocations |
| **browser** | Playwright/Puppeteer wrapping | Navigation, content scanning, downloads, tainted-session actions |

Set up one. Two. All five. Same policy file works everywhere.

---

## 🌐 Dashboard v2 — live operator monitoring

```bash
npx @weave_protocol/api
# → http://localhost:3000/dashboard
```

The dashboard shows the **five enforcement surfaces as a live hierarchy**, fed by WARD.md at the top:

- **Live state per surface** — events today, delta vs yesterday, status badge (LIVE / IDLE / OFF)
- **Dimmed visualization** — unused surfaces appear but greyed out (so you can see what's configured vs what's available)
- **Real-time activity feed** — allows, denies, IPI detections, approvals across all surfaces
- **WARD policy panel** — currently loaded source, agent, network/capability rule counts, behavioral limits
- **24-hour statistics** — decisions, allows, denies, approvals, IPI detected, URLs scanned

Auto-refreshes every 5 seconds. Monochrome design (black/grey/white + red accent for threats) — built for ops rooms, not marketing decks.

---

## 🌐 Browser security (`@weave_protocol/browser`)

The fifth enforcement surface — protection for browser agents specifically, where **indirect prompt injection (IPI)** lives.

**33 IPI patterns across 20 threat categories**, all deterministic regex + HTML structural inspection (no LLM in the loop — the scanner itself can't be prompt-injected):

- **Trigger phrases** (9) — "ignore previous instructions", role hijack, chat-template tokens
- **Action directives** (4, critical) — "send email to X", "transfer $Y", "execute:"
- **Payment specifications** (1, critical) — recipient+amount in proximity (Atlan autonomous-fraud pattern)
- **Hidden CSS** (6) — display:none, visibility:hidden, white-on-white (Brave/Comet pattern)
- **HTML structural** (5) — comments, noscript, aria-hidden, meta, alt text
- **Encoding obfuscation** (3) — base64 near decode keywords, Unicode zero-width, data:text/html
- **Tool-call mimicry** (2) — JSON/XML resembling LLM tool calls
- **DoS / suppression** (2) — false copyright, "do not summarize"
- **SVG + script** (1) — combined XSS+IPI vector

```typescript
import { WardBrowserGuard } from '@weave_protocol/browser';
import { chromium } from 'playwright';

const guard = new WardBrowserGuard(); // auto-loads ./WARD.md
const browser = await chromium.launch();
const page = await (await browser.newContext()).newPage();
guard.wrapPlaywrightPage(page, 'session-1');  // navigation + content + downloads auto-gated

await page.goto('https://example.com');  // IPI scan + WARD network check happens transparently
```

**Companion browser extension** (Chrome + Firefox): same 33 IPI patterns, but as an end-user inspection tool. Browse normally, see threats on the pages you visit, no developer setup required. [Install / load unpacked →](browser-extension/)

---

## 📚 Skills

Skills are portable instruction sets that work across Claude Code, Antigravity, and other harnesses. Install paths shown for both:

```bash
# Claude Code
ln -s ~/Desktop/Weave_Protocol/<package>/SKILL.md ~/.claude/skills/<package>.md

# Antigravity
cp ~/Desktop/Weave_Protocol/<package>/SKILL.md ~/.antigravity/skills/
```

Skills are documented per-package. See each package's `SKILL.md`.

---

## 🤖 Automation

- **Dependabot** — weekly Monday updates, grouped (TypeScript, ESLint, AWS SDK, MCP SDK), auto-merge for patch/minor
- **Trusted publishing** — npm and PyPI via GitHub Actions (no API tokens stored)
- **Publish workflow** — `.github/workflows/publish-all.yml` covers all 15 npm packages in a matrix

---

## 📖 Links

- [GitHub repo](https://github.com/Tyox-all/Weave_Protocol)
- [npm packages](https://www.npmjs.com/~tyox-all)
- [PyPI](https://pypi.org/project/weave-protocol-llamaindex/)
- [MCP Registry](https://registry.modelcontextprotocol.io)

---

## 📄 License

Apache 2.0 — see [LICENSE](LICENSE).
