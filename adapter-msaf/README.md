# 🛡️ @weave_protocol/adapter-msaf

[![npm version](https://img.shields.io/npm/v/@weave_protocol/adapter-msaf.svg)](https://www.npmjs.com/package/@weave_protocol/adapter-msaf)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/adapter-msaf.svg)](https://www.npmjs.com/package/@weave_protocol/adapter-msaf)
[![license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**WARD.md enforcement for [Microsoft Agent Framework](https://devblogs.microsoft.com/agent-framework/) (MSAF) via the middleware pipeline.**

> *AGENTS.md tells your agent what to do. SKILL.md tells your agent how to do it. **WARD.md tells your agent what it can't.** This package makes Microsoft Agent Framework listen.*

Part of the [Weave Protocol](https://github.com/Tyox-all/Weave_Protocol) security suite. Third cross-platform harness adapter (after [adapter-claudecode](../adapter-claudecode) and [adapter-antigravity](../adapter-antigravity)).

---

## 🆕 What's new

**0.3.0: decisions on the dashboard.** Set `WEAVE_DASHBOARD_URL` and each allow and deny goes to a local [Weave API](https://www.npmjs.com/package/@weave_protocol/api) dashboard. It's off by default.

**0.2.0: whole-call checks ([WARD-2026-001](https://github.com/Tyox-all/Weave_Protocol/blob/main/ward/SECURITY_ADVISORIES.md)).** Every path and URL argument and every token of a shell command is checked, and an invalid WARD.md blocks instead of switching enforcement off.

With [Ward](https://www.npmjs.com/package/@weave_protocol/ward) 0.3.3 or later, agents also need approval to edit `WARD.md`, MCP config or git hooks.

## What it does

When a Microsoft Agent Framework agent is about to invoke a tool (shell command, file edit, HTTP request, etc.), the WARD middleware fires in the function-middleware layer, reads your project's `WARD.md`, and **throws a `WardDeniedError`** if the call violates the declared policy. MSAF's middleware pipeline short-circuits, the tool never runs.

Because MSAF middleware is registered programmatically (not via a config file), there's no global hook to install — you wire it into your agent setup in one line.

```typescript
import { WardMiddleware } from '@weave_protocol/adapter-msaf';

const ward = new WardMiddleware();   // auto-loads ./WARD.md
agent.useFunctionMiddleware(ward.functionMiddleware());
```

That's it. Every tool call your MSAF agent makes is now gated by your WARD.md.

---

## Why this is shaped differently from the other adapters

| | adapter-claudecode | adapter-antigravity | **adapter-msaf** |
|---|---|---|---|
| Install pattern | `init` writes to `~/.claude/settings.json` | `init` writes to `~/.gemini/antigravity-cli/settings.json` | **You import a class and pass it to your agent** |
| Invocation | CLI subprocess (stdin/stdout) | CLI subprocess (stdin/stdout) | **In-process middleware function** |
| Scope | Global (all Claude Code sessions) | Global (all Antigravity surfaces) | **Per-agent (whichever agents you wire it into)** |

MSAF doesn't have a global config file for hooks — middleware lives in your agent code. That's a deliberate design choice in MSAF (it wants explicit, code-level policy registration). So instead of `init` writing config, it prints the integration snippet for you to paste.

---

## Quick start

```bash
# Install
npm install @weave_protocol/adapter-msaf
```

Then in your MSAF agent setup:

```typescript
import { WardMiddleware } from '@weave_protocol/adapter-msaf';

// Construct — auto-loads WARD.md from cwd, .weave/, or .msaf/
const ward = new WardMiddleware();

// Or explicit path:
//   const ward = new WardMiddleware({ wardPath: './policies/strict.WARD.md' });

// Or inline source (useful for tests):
//   const ward = new WardMiddleware({ wardSource: someMdContent });

// Register
agent.useFunctionMiddleware(ward.functionMiddleware());
```

Drop a `WARD.md` in your project root (`npx @weave_protocol/ward init`) and you're done.

Verify with:

```bash
npx -p @weave_protocol/adapter-msaf weave-msaf status
```

---

## How WARD.md is resolved

When the middleware is constructed (or `weave-msaf status` runs), it looks in this order:

1. Explicit `wardPath` constructor option
2. Explicit `wardSource` constructor option (raw markdown)
3. `$WEAVE_WARD_PATH` env var
4. `<cwd>/WARD.md`
5. `<cwd>/.weave/WARD.md`
6. `<cwd>/.msaf/WARD.md`

First match wins. If nothing is found:
- Default (`failMode: 'open'`): every call is allowed, and a warning is logged
- `failMode: 'closed'`: the constructor throws

A policy that exists but is invalid, or an explicit `wardPath` that doesn't exist, always makes the constructor throw (since 0.2.0). Running without the policy you asked for would be a silent bypass.

---

## Tool mapping

MSAF tool names are user-defined, but several common conventions emerge from the local agent runtime and the Copilot/Claude Code SDK harness integrations. Built-in mappings cover them:

| MSAF tool | WARD capability | Path arg | fs op |
|---|---|---|---|
| `ShellExec` / `Bash` / `RunCommand` | `shell_exec` | (command heuristic) | varies |
| `FileWrite` / `FileEdit` / `EditFile` / `Edit` / `Write` | `file_write` | `path` or `file_path` | `write` |
| `FileRead` / `ReadFile` / `Read` | `file_read` | `path` or `file_path` | `read` |
| `FileDelete` | `file_delete` | `path` | `delete` |
| `ListDirectory` | `file_list` | `path` | `list` |
| `HttpRequest` / `WebFetch` | `http_request` | `url` | — |
| `SendEmail` | `send_email` | — | — |
| `PostMessage` | `send_message` | — | — |
| `CreateIssue` | `create_issue` | — | — |
| `Subagent` | `subagent` | — | — |

Your WARD.md can use either the MSAF tool name or the generic capability. Explicit allow/deny/approval rules beat default decisions.

**Custom mappings:**

```typescript
const ward = new WardMiddleware({
  toolMappings: {
    MyCorpAPI: { capability: 'http_request', urlField: 'endpoint' },
    AzureCLI:  { capability: 'shell_exec',   commandField: 'cmd' },
  }
});
```

The Bash command heuristic also catches Azure CLI credential paths (`~/.azure/`) on top of SSH/AWS/GCP — relevant for MSAF users.

---

## Callbacks for logging and attestation

```typescript
const ward = new WardMiddleware({
  onAllow: (call, result) => {
    log.info('ward.allow', { tool: call.toolName });
  },
  onDeny: async (call, result) => {
    log.warn('ward.deny', { tool: call.toolName, reasons: result.reasons });
    // (Optional) return true to override the deny — emergency escape valve
    // return false;  // (default) — let WARD deny stand
  },
});
```

`onDeny` returning `true` lets you override a WARD decision at runtime (for human-in-the-loop approval, for instance). Logged but allowed. Use sparingly.

---

## CLI

```bash
weave-msaf init [--language=ts|csharp|python]
    Print the integration snippet you paste into your agent code

weave-msaf status
    Show the active WARD policy (resolved from cwd) and built-in mappings

weave-msaf test <tool> [--input=JSON]
    Dry-run a tool call against your WARD.md without invoking MSAF

weave-msaf help
```

### Examples

```bash
# What would happen if my agent tried to exfil Azure creds?
weave-msaf test ShellExec --input='{"command":"cat ~/.azure/credentials"}'

# What about a forbidden HTTP endpoint?
weave-msaf test HttpRequest --input='{"url":"https://evil.example.com"}'

# Get the integration snippet
weave-msaf init --language=ts
```

---

## Catching denials

The middleware throws `WardDeniedError` (a named class) so callers can handle WARD failures distinctly:

```typescript
import { WardDeniedError } from '@weave_protocol/adapter-msaf';

try {
  await agent.run(userPrompt);
} catch (err) {
  if (err instanceof WardDeniedError) {
    console.warn(`Agent action blocked by WARD: ${err.reasons.join(', ')}`);
    // Optionally surface to user, route to human-in-the-loop, etc.
  } else {
    throw err;
  }
}
```

---

## A sample WARD.md for an MSAF agent

```markdown
---
ward: "1.0"
agent: msaf-coding-agent
---

# WARD.md

## Filesystem

allow:
  - read: /Users/me/projects/**
  - write: /Users/me/projects/**
deny:
  - read: ~/.ssh/**
  - read: ~/.azure/**
  - read: ~/.aws/**
  - write: /etc/**
default: deny

## Network

allow:
  - url: "https://api.github.com/**"
  - url: "https://management.azure.com/**"
  - url: "https://*.openai.azure.com/**"
default: deny

## Capabilities

allow:
  - file_read
  - file_write
  - file_list
requireApproval:
  - shell_exec
  - http_request
  - subagent
deny:
  - file_delete
default: deny

## Behavioral Limits

maxIterations: 50
maxCostUSD: 5.00
maxRuntimeSeconds: 600
```

With this, the MSAF agent can work inside your projects directory but can't read SSH/AWS/Azure credentials, requires approval for shell or HTTP, and is hard-blocked from spawning subagents or deleting files.

---

## Roadmap

Shipped:
- ✅ TypeScript middleware library + CLI
- ✅ Function middleware (per-tool gating)
- ✅ Agent middleware (turn-level hook, pass-through scaffold)
- ✅ 20-tool built-in mappings (MSAF local runtime + Copilot SDK + Claude Code SDK patterns)
- ✅ Bash command heuristic includes Azure credential paths
- ✅ Allow/deny callbacks for logging and override
- ✅ `WardDeniedError` typed exception
- ✅ Whole-call checks through Ward's shared evaluator (0.2.0)
- ✅ Decision reporting to the Weave dashboard (0.3.0)

Planned:
- [ ] Native .NET package (NuGet) for first-class C# integration
- [ ] Native Python package (PyPI) — for MSAF Python users
- [ ] Behavioral-limit enforcement in agent middleware (iteration / cost caps)
- [ ] Domere attestation integration in `onAllow`/`onDeny`
- [ ] Chat middleware variant (gate at the model-call layer)

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

Apache 2.0 — see [LICENSE](../LICENSE).
