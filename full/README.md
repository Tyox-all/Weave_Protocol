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

## License

Apache 2.0 — See [LICENSE](https://github.com/Tyox-all/Weave_Protocol/blob/main/LICENSE)
