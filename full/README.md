# 🕸️ @weave_protocol/full

[![npm version](https://img.shields.io/npm/v/@weave_protocol/full.svg)](https://www.npmjs.com/package/@weave_protocol/full)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/full.svg)](https://www.npmjs.com/package/@weave_protocol/full)
[![license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**The complete Weave Protocol security suite — one install.**

```bash
npm install @weave_protocol/full
```

That's it. You now have every Weave Protocol package installed:

| Package | What it does |
|---------|--------------|
| 🛡️ [@weave_protocol/mund](https://www.npmjs.com/package/@weave_protocol/mund) | Security scanner — secrets, PII, injection, MCP vetting, threat intel |
| 🏛️ [@weave_protocol/hord](https://www.npmjs.com/package/@weave_protocol/hord) | Encrypted vault with Yoxallismus cipher |
| ⚖️ [@weave_protocol/domere](https://www.npmjs.com/package/@weave_protocol/domere) | Compliance (SOC2/HIPAA/PCI-DSS/GDPR/CCPA) + blockchain anchoring |
| 👥 [@weave_protocol/witan](https://www.npmjs.com/package/@weave_protocol/witan) | Multi-agent consensus & governance |
| 🔍 [@weave_protocol/hundredmen](https://www.npmjs.com/package/@weave_protocol/hundredmen) | Real-time MCP proxy with drift detection |
| 🛂 [@weave_protocol/tollere](https://www.npmjs.com/package/@weave_protocol/tollere) | Supply chain security — npm, Docker, IDE extensions |
| 🔗 [@weave_protocol/langchain](https://www.npmjs.com/package/@weave_protocol/langchain) | LangChain.js security callbacks |
| 🔌 [@weave_protocol/api](https://www.npmjs.com/package/@weave_protocol/api) | REST API + monitoring dashboard |
| 📜 [@weave_protocol/ward](https://www.npmjs.com/package/@weave_protocol/ward) | WARD.md policy standard and the shared tool-call evaluator |
| 🌐 [@weave_protocol/browser](https://www.npmjs.com/package/@weave_protocol/browser) | Browser-agent guard: navigation, downloads, prompt-injection scanning |
| 🕸️ [@weave_protocol/cli](https://www.npmjs.com/package/@weave_protocol/cli) | `weave init`, audit and dashboard commands |
| 🛡️ Harness adapters | WARD.md enforcement in [Claude Code](https://www.npmjs.com/package/@weave_protocol/adapter-claudecode), [Antigravity](https://www.npmjs.com/package/@weave_protocol/adapter-antigravity), [Microsoft Agent Framework](https://www.npmjs.com/package/@weave_protocol/adapter-msaf), [Gemini CLI](https://www.npmjs.com/package/@weave_protocol/adapter-geminicli), [Codex CLI](https://www.npmjs.com/package/@weave_protocol/adapter-codex), [OpenCode](https://www.npmjs.com/package/@weave_protocol/adapter-opencode) and [Cursor](https://www.npmjs.com/package/@weave_protocol/adapter-cursor). Installing them doesn't turn them on; run each adapter's `init`. |

---

## 🆕 What's new

**0.5.0** brings in the November security releases. The seven harness adapters enforce WARD.md's session and spend limits (Ward 0.3.6). They also run a payment guard and check what each call sends. This release also includes Mund 0.5.3's detection and Witan 1.2.2's fix for WARD.md spending caps.

**0.4.0** adds the Gemini CLI, Codex, OpenCode and Cursor adapters and the browser guard, so one install now includes every defensive package. Each component is a regular dependency, so a fresh install picks up its patch releases, such as Ward 0.3.3's self-protection and Mund 0.5.2's detection.

## Usage

You can import from the bundle:

```typescript
import { mund, hord, tollere } from '@weave_protocol/full';

const scan = await mund.scan("My API key is sk-1234...");
const risk = await tollere.scanPackage("axios", "1.7.2");
```

Or from individual packages — same effect:

```typescript
import { scan } from '@weave_protocol/mund';
import { scanPackage } from '@weave_protocol/tollere';
```

---

## Want a guided setup?

For framework detection, scaffolding, and config generation, use [`@weave_protocol/cli`](https://www.npmjs.com/package/@weave_protocol/cli):

```bash
npx @weave_protocol/cli init
```

It detects whether you're using LangChain, LlamaIndex, MCP, OpenAI, or Anthropic SDKs and scaffolds the right security middleware for your stack.

---

## Why a bundle?

Some users want to evaluate the whole suite or build something that uses several packages together. Installing everything via one dependency keeps `package.json` clean and ensures version compatibility across the suite.

If you only need a few packages, install them individually — the bundle is purely additive.

---

## 🕸️ Part of Weave Protocol

One [WARD.md](https://github.com/Tyox-all/Weave_Protocol) policy for every agent you run, locally or at scale, plus the tools around it.

| Package | What it does |
|---|---|
| [Ward](https://www.npmjs.com/package/@weave_protocol/ward) | The WARD.md policy standard and the tool-call evaluator every adapter shares |
| [Mund](https://www.npmjs.com/package/@weave_protocol/mund) | Scans content for prompt injection, secrets, PII and exfiltration |
| [Hord](https://www.npmjs.com/package/@weave_protocol/hord) | Encrypted vaults, PII tokenization, sandboxes, capability tokens, attestations |
| [Dōmere](https://www.npmjs.com/package/@weave_protocol/domere) | Audit threads, compliance checkpoints, GDPR and CCPA records, anchoring |
| [Witan](https://www.npmjs.com/package/@weave_protocol/witan) | Multi-agent consensus and spending caps |
| [Hundredmen](https://www.npmjs.com/package/@weave_protocol/hundredmen) | MCP proxy that enforces WARD.md on tool calls |
| [Tollere](https://www.npmjs.com/package/@weave_protocol/tollere) | Supply-chain checks: typosquats, CVEs, suspicious version diffs |
| [Browser](https://www.npmjs.com/package/@weave_protocol/browser) | WARD.md and injection scanning for Playwright browser agents |
| Adapters | WARD.md in [Claude Code](https://www.npmjs.com/package/@weave_protocol/adapter-claudecode), [Antigravity](https://www.npmjs.com/package/@weave_protocol/adapter-antigravity), [MSAF](https://www.npmjs.com/package/@weave_protocol/adapter-msaf), [Gemini CLI](https://www.npmjs.com/package/@weave_protocol/adapter-geminicli), [Codex](https://www.npmjs.com/package/@weave_protocol/adapter-codex), [OpenCode](https://www.npmjs.com/package/@weave_protocol/adapter-opencode) and [Cursor](https://www.npmjs.com/package/@weave_protocol/adapter-cursor) |
| [Adversary](https://www.npmjs.com/package/@weave_protocol/adversary) · [AgentSecBench](https://www.npmjs.com/package/@weave_protocol/agentsecbench) | Red-team engine and locked benchmark |
| [API](https://www.npmjs.com/package/@weave_protocol/api) · [CLI](https://www.npmjs.com/package/@weave_protocol/cli) · [LangChain](https://www.npmjs.com/package/@weave_protocol/langchain) | REST API and dashboard, setup CLI, LangChain.js integration |
| [full](https://www.npmjs.com/package/@weave_protocol/full) | Every defensive package in one install |
| [Yoxallismus](https://www.npmjs.com/package/@weave_protocol/yoxallismus) | Post-quantum hybrid cipher (experimental beta) |

---

## License

Apache 2.0 — See [LICENSE](https://github.com/Tyox-all/Weave_Protocol/blob/main/LICENSE)
