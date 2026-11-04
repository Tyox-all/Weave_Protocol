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

Built against Codex's [hooks documentation](https://developers.openai.com/codex/hooks): the `PreToolUse` payload, deny output, `apply_patch` and MCP tool naming. 12 fixture tests.

## License

Apache-2.0
