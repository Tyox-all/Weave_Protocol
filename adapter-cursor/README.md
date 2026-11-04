# 🛡️ @weave_protocol/adapter-cursor

> Enforce [WARD.md](https://github.com/Tyox-all/Weave_Protocol/tree/main/ward) in **Cursor** with its agent hooks. Shell commands, file reads and writes, and MCP calls are checked against your policy before they run.

[![npm](https://img.shields.io/npm/v/@weave_protocol/adapter-cursor?color=000&style=flat-square)](https://www.npmjs.com/package/@weave_protocol/adapter-cursor)

The same WARD.md you use with Claude Code, Antigravity, Microsoft Agent Framework, Gemini CLI, Codex CLI and OpenCode.

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

Built against Cursor's [agent hooks documentation](https://cursor.com/docs/agent/hooks), with 11 fixture tests. It hasn't been live-checked in Cursor yet. Cursor's docs don't say whether the `cursor-agent` CLI runs agent hooks, so for now treat this as an IDE adapter.

## License

Apache-2.0
