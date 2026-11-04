# 🕸️ @weave_protocol/cli

[![npm version](https://img.shields.io/npm/v/@weave_protocol/cli.svg)](https://www.npmjs.com/package/@weave_protocol/cli)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/cli.svg)](https://www.npmjs.com/package/@weave_protocol/cli)
[![license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**The `weave` command-line tool — one command to set up, audit, and run Weave Protocol security for AI agent projects.**

```bash
npx @weave_protocol/cli init
```

That's it. The CLI detects your stack (LangChain, LlamaIndex, MCP server, OpenAI SDK, Anthropic SDK, or generic), asks which Weave Protocol packages you want, and scaffolds the right security middleware for your project.

Part of the [Weave Protocol Security Suite](https://github.com/Tyox-all/Weave_Protocol).

---

## 🆕 What's new

**0.2.0: scaffolds that compile.**
- Generated code no longer calls APIs that don't exist. Earlier scaffolds used Hord's deprecated cipher, an unexported Dōmere class and Mund fields that aren't there.
- Generated JavaScript no longer contains TypeScript.
- Every `npx` hint names the scoped `@weave_protocol` package. Plain `npx weave` runs an unrelated package.

The CLI now has 43 tests.

## Commands

```bash
weave init                        # Set up Weave Protocol in the current project
weave audit [path]                # Scan dependencies for supply chain risk
weave dashboard [--port=3000]     # Launch the API server + open the monitoring dashboard
weave doctor                      # Check environment for common config issues
weave version                     # Show CLI + installed package versions
weave help                        # Show help
```

---

## What `weave init` does

1. **Detects your framework** by inspecting `package.json` and source imports
2. **Asks you to confirm** the framework choice (or pick a different one)
3. **Lets you select** which Weave Protocol packages to enable (with sensible defaults per framework)
4. **Generates a `weave-security.ts` (or `.js`) middleware file** appropriate for your stack
5. **Writes a `.weaverc`** config file that other Weave tools can read
6. **Prints the install command** for your package manager (npm/pnpm/yarn/bun)

### Framework-specific scaffolding

| Framework | Generated middleware |
|-----------|---------------------|
| **LangChain.js** | `WeaveSecurityCallback` ready to drop into any chain or agent |
| **MCP Server** | `secureToolHandler()` wrapper that scans inputs and outputs of every tool call |
| **OpenAI SDK** | `secureChatCompletion()` wrapper for `openai.chat.completions.create` |
| **Anthropic SDK** | `secureMessages()` wrapper for `anthropic.messages.create` |
| **Vercel AI / AI SDK** | OpenAI-style wrapper |
| **Generic / Raw** | No code generation — just installs packages and writes `.weaverc` |

---

## Example: setting up a new LangChain project

```bash
$ cd my-langchain-app
$ npx @weave_protocol/cli init

🕸️  Weave Protocol CLI

Detected
────────────────────────────────────────────────────────────
  • Project root:  /Users/me/my-langchain-app
  • Language:      typescript
  • Framework:     LangChain.js
  • Also detected: OpenAI SDK

? Which framework should we configure for?
  ● 1. LangChain.js (detected)
  ○ 2. Anthropic SDK
  ○ 3. OpenAI SDK
  ○ 4. MCP Server
  ○ 5. None / generic
  (1) > 

? Which Weave Protocol packages do you want? (comma-separated)
  ☑ 1. 🛂 Tollere    — Supply chain security
  ☑ 2. 🛡️ Mund       — Input/output threat scanning
  ☐ 3. 🏛️ Hord       — Encrypted vault for secrets
  ☐ 4. ⚖️ Domere     — Compliance + blockchain anchoring
  ☐ 5. 👥 Witan      — Multi-agent consensus
  ☐ 6. 🔍 Hundredmen — Real-time MCP proxy + drift detection
  ☑ 7. 🔗 Langchain  — LangChain.js callbacks
  ☐ 8. 🔌 API        — REST API + monitoring dashboard
  (1,2,7) > 

Plan
────────────────────────────────────────────────────────────
  • Install 3 package(s):
     • @weave_protocol/langchain
     • @weave_protocol/tollere
     • @weave_protocol/mund
  • Create 1 file(s):
     • weave-security.ts — Security middleware module
  • Write .weaverc configuration file

? Proceed? (Y/n) y

  ✓ Wrote weave-security.ts
  ✓ Wrote .weaverc

Install
────────────────────────────────────────────────────────────
  Run:
    npm install @weave_protocol/langchain @weave_protocol/tollere @weave_protocol/mund

Next steps
────────────────────────────────────────────────────────────
  → Import the security callback in your chains
  → Add it to any chain's `callbacks` array
  → Run `npx @weave_protocol/cli audit` before each deploy

✨  Weave Protocol initialized!
```

---

## `weave audit`

Delegates to [Tollere](https://www.npmjs.com/package/@weave_protocol/tollere) to scan your `package.json` for typosquats, CVEs, low-reputation maintainers, and suspicious version diffs.

```bash
weave audit
weave audit ./apps/api/package.json
```

Exit codes: `0` = clean, `1` = warnings (review), `2` = critical (install blocked). Wire this into your CI pipeline.

---

## `weave dashboard`

Launches the [API package](https://www.npmjs.com/package/@weave_protocol/api) and opens the monitoring dashboard in your browser:

```bash
weave dashboard
weave dashboard --port=4000
```

Live activity feed, threat intel status, compliance frameworks, MCP server reputation.

---

## `weave doctor`

Quick environment check:

- Node.js version >= 18
- `package.json` present
- `.weaverc` present
- At least one Weave Protocol package installed
- Claude Desktop MCP servers configured (if applicable)

```bash
weave doctor
```

Exit code: `0` if all checks pass, `1` if any fail.

---

## Programmatic API

The CLI's internals are also exported as a library, in case you want to build tooling on top:

```typescript
import { detectFramework, getScaffold } from "@weave_protocol/cli";

const detection = detectFramework(process.cwd());
const scaffold = getScaffold(detection.primary, {
  language: "typescript",
  selectedPackages: ["tollere", "mund"],
  framework: detection.primary,
});

console.log(scaffold.files[0].content);
```

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

Apache 2.0
