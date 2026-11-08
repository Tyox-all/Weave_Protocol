# 🛡️ @weave_protocol/adapter-cursor

> Enforce [WARD.md](https://github.com/Tyox-all/Weave_Protocol/tree/main/ward) in **Cursor** with its agent hooks. Shell commands, file reads and writes, and MCP calls are checked against your policy before they run.

[![npm](https://img.shields.io/npm/v/@weave_protocol/adapter-cursor?color=000&style=flat-square)](https://www.npmjs.com/package/@weave_protocol/adapter-cursor)

The same WARD.md you use with Claude Code, Antigravity, Microsoft Agent Framework, Gemini CLI, Codex CLI and OpenCode.

## 🆕 What's new

**0.3.0: session and spend limits.** WARD.md's limits are now enforced per session, keyed on the Cursor `conversation_id`:
- Behavioral Limits: `maxToolCalls`, `maxRuntimeSeconds` and `maxExternalServices`;
- `spending_limits:` caps: tool calls, and per-tool call counts and USD amounts over a run, hour, day, week or month.

The counts live in a small local ledger (`~/.weave/ledger`, or `$WEAVE_LEDGER_DIR`) because every hook call is a new process. [Ward](https://www.npmjs.com/package/@weave_protocol/ward) 0.3.6's **payment guard** also asks before any call that moves money: payment tools, and wallet or Stripe CLIs in shell commands.

## Quick start

```bash
npm i -g @weave_protocol/adapter-cursor
weave-ward-cursor init        # adds the hook to ~/.cursor/hooks.json
weave-ward-cursor status
```

Cursor reloads `hooks.json` when it changes. Add a `WARD.md` to your project (`npx @weave_protocol/ward init`), or a user-wide one at `~/.cursor/WARD.md`.

## How it hooks in

One command, `weave-ward-cursor hook`, is registered on four of Cursor's [agent hook events](https://cursor.com/docs/agent/hooks). It decides each call with Ward's shared evaluator (`evaluateToolCall`), so the rules match the other adapters exactly:

| Event | Checked |
|---|---|
| `beforeShellExecution` | `shell_exec`, the command's `cwd` (as a read), and every URL and absolute or `~` path in the command |
| `beforeReadFile` | the `file_path` (as a read) |
| `beforeMCPExecution` | `mcp__<server>__<tool>`, plus every path and URL argument in its `tool_input` |
| `preToolUse` | every other tool (`Write`, `Delete`, `Grep`, `Task`, …), by capability and every path-named argument. Shell, Read and MCP are left to the events above, which carry richer fields. |

## Decisions

| WARD decision | What Cursor sees |
|---|---|
| allow | nothing: the call continues, and Cursor's own approval settings still apply |
| deny | `permission: "deny"`, with the reason in `user_message` and `agent_message` |
| require_approval | `permission: "ask"` for shell and MCP calls, where Cursor enforces it. Elsewhere it's a deny whose reason says approval is needed, because `preToolUse` doesn't enforce "ask" and `beforeReadFile` has none. |

**Failure modes:**
- **An invalid WARD.md always denies**, so a typo can't silently switch enforcement off.
- **No WARD.md anywhere means no enforcement.**
- **Malformed payloads and evaluator errors** allow by default. `init --fail-closed` makes them deny.

WARD.md is looked up in this order:
1. `$WEAVE_WARD_PATH`
2. `<workspace>/WARD.md`
3. `<workspace>/.cursor/WARD.md`
4. `<workspace>/.weave/WARD.md`
5. `~/.cursor/WARD.md`

## Commands

```bash
weave-ward-cursor init [--timeout=SECONDS] [--fail-closed]
weave-ward-cursor disable
weave-ward-cursor status
weave-ward-cursor test Read --input='{"file_path":"secrets/key"}'   # dry run
weave-ward-cursor hook                                               # what Cursor runs
```

`init` backs up `hooks.json` and edits it atomically. It adds one entry per event and leaves your other hooks alone. The command is `weave-ward-cursor`, matching `weave-ward-codex` and `weave-ward-opencode`.

## Dashboard

Set `WEAVE_DASHBOARD_URL` (and `WEAVE_API_KEY`) where you run the agent, and each decision is reported to a local [Weave API](https://github.com/Tyox-all/Weave_Protocol/tree/main/api) dashboard (0.2.0+). Only the decision and the tool name are sent, never command or argument contents. Reporting never changes a decision and gives up after 250 ms.

## Verified

Built against Cursor's [agent hooks documentation](https://cursor.com/docs/agent/hooks), with 12 fixture tests.

Live-checked in the Cursor app (3.28.7) with a project-level `.cursor/hooks.json`:
- **Denied read:** the agent's read of `secrets/key` was blocked through `beforeReadFile`, with `WARD: Denied by filesystem rule …`.
- **Allowed read:** `notes.txt` went through.
- **Denied write:** creating `secrets/new.txt` was blocked through `preToolUse`. Cursor sends writes as `tool_name: "Write"` with `tool_input: { file_path, content }`.
- **Reads are decided once:** each read also arrives as a `preToolUse`. The adapter leaves those to `beforeReadFile`, which fires whenever file content is actually read.

Cursor's docs don't say whether the `cursor-agent` CLI runs agent hooks, so this is verified for the app.

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
