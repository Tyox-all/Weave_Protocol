# 🛡️ @weave_protocol/adapter-codex

> Enforce [WARD.md](https://github.com/Tyox-all/Weave_Protocol/tree/main/ward) in **OpenAI Codex CLI** with its `PreToolUse` hook. Every shell command, file edit and MCP call is checked against your policy before it runs.

[![npm](https://img.shields.io/npm/v/@weave_protocol/adapter-codex?color=000&style=flat-square)](https://www.npmjs.com/package/@weave_protocol/adapter-codex)

The same WARD.md you use with Claude Code, Antigravity, Microsoft Agent Framework and Gemini CLI.

## Quick start

```bash
npm i -g @weave_protocol/adapter-codex
weave-ward-codex init        # adds the hook to ~/.codex/hooks.json
```

Then, in Codex, run **`/hooks`** and trust **"Weave: checking WARD.md"**. Codex skips new or changed hooks until you trust them. Add a `WARD.md` to your project (`npx @weave_protocol/ward init`), or a user-wide one at `~/.codex/WARD.md`.

The command is `weave-ward-codex`, not `weave-codex`. The `weave-codex` npm name belongs to W&B Weave's Codex integration, which is a different product.

## What it checks

The hook uses Ward's shared evaluator (`evaluateToolCall`), so the rules match the other adapters exactly:

- **Shell commands** (`Bash`, including unified exec): the `shell_exec` capability, plus every URL and every absolute or `~` path in the command.
- **File edits** (`apply_patch`): the files the patch touches, read from its `*** Add File`, `*** Update File`, `*** Move to` and `*** Delete File` lines. Adds, updates and moves are writes; deletes are deletes. Text inside the patch is never treated as a target.
- **MCP tools** (`mcp__<server>__<tool>`): by name, plus their path and URL arguments.
- **`update_plan`** uses the `task_planning` capability, the same one the Gemini CLI adapter uses for planning tools.

Codex's hosted tools, such as web search, don't go through `PreToolUse`. Neither do some specialized paths, as Codex's docs note. Treat the hook as a guardrail, and combine it with Codex's own sandbox and approval settings.

## Decisions

| WARD decision | What Codex sees |
|---|---|
| allow | nothing: the call continues, and Codex's own approvals still apply |
| deny | `permissionDecision: "deny"` with the WARD reason, which the model sees |
| require_approval | a deny whose reason says approval is needed (Codex hooks don't support "ask") |

**Failure modes:**
- **An invalid WARD.md always denies**, so a typo can't silently switch enforcement off.
- **No WARD.md anywhere means no enforcement.**
- **Malformed payloads and evaluator errors** allow by default. `init --fail-closed` makes them deny.

WARD.md is looked up in this order:
1. `$WEAVE_WARD_PATH`
2. `<project>/WARD.md`
3. `<project>/.codex/WARD.md`
4. `<project>/.weave/WARD.md`
5. `$CODEX_HOME/WARD.md` (default `~/.codex/WARD.md`)

## Commands

```bash
weave-ward-codex init [--matcher=REGEX] [--timeout=SECONDS] [--fail-closed]
weave-ward-codex disable
weave-ward-codex status
weave-ward-codex test Bash --input='{"command":"cat secrets/key"}'   # dry run
weave-ward-codex hook pre-tool-use                                    # what Codex runs
```

`init` writes to `$CODEX_HOME/hooks.json` (default `~/.codex/hooks.json`). It backs the file up, edits it atomically, and finds its own entry by its status message, so your other hooks are untouched.

## Dashboard

Set `WEAVE_DASHBOARD_URL` (and `WEAVE_API_KEY`) where you run the agent, and each decision is reported to a local [Weave API](https://github.com/Tyox-all/Weave_Protocol/tree/main/api) dashboard (0.2.0+). Only the decision and the tool name are sent, never command or argument contents. Reporting never changes a decision and gives up after 250 ms.

## Verified

Built against Codex's [hooks documentation](https://developers.openai.com/codex/hooks): the `PreToolUse` payload, deny output, `apply_patch` and MCP tool naming. 13 fixture tests.

Live-checked in Codex CLI 0.166.0, signed in with a ChatGPT account:
- `cat secrets/key` was blocked, and Codex reported `Command blocked by PreToolUse hook: WARD: Denied by filesystem rule …`;
- `cat notes.txt` went through;
- an `apply_patch` adding `secrets/new.txt` was blocked by its file target, and no file was created, even in the `workspace-write` sandbox.

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

Apache-2.0
