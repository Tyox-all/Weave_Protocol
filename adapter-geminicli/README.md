# 🛡️ @weave_protocol/adapter-geminicli

> Enforce [WARD.md](https://github.com/Tyox-all/Weave_Protocol/tree/main/ward) in **Gemini CLI** with its `BeforeTool` hook. Every tool call the agent makes is checked against your policy before it runs.

[![npm](https://img.shields.io/npm/v/@weave_protocol/adapter-geminicli?color=000&style=flat-square)](https://www.npmjs.com/package/@weave_protocol/adapter-geminicli)

The fourth WARD harness adapter, after Claude Code, Antigravity and Microsoft Agent Framework. The same WARD.md works in all of them.

## Quick start

```bash
npm i -g @weave_protocol/adapter-geminicli
weave-gemini init          # adds the hook to ~/.gemini/settings.json
weave-gemini status        # hook installed? which WARD.md is active?
```

Then restart Gemini CLI. Add a `WARD.md` to your project (`npx @weave_protocol/ward init`), or a user-wide one at `~/.gemini/WARD.md`.

## What it checks

The hook uses Ward's shared evaluator (`evaluateToolCall`), so the rules match the other adapters exactly:

- **Capability:** the tool's WARD capability (`run_shell_command` → `shell_exec`, `read_file` → `file_read`, …) or its raw name.
- **Arguments:** every path and URL argument, with `..` and `~` normalized, including every entry of `read_many_files`' `include` list.
- **Shell commands:** every URL and every absolute or `~` path in `run_shell_command`, with relative paths resolved against its `dir_path`.
- **`web_fetch`:** every URL inside its free-text `prompt`.
- **MCP tools** (`mcp_<server>_<tool>`): by name, plus their path and URL arguments.

Gemini CLI's planning and interaction tools (`ask_user`, `write_todos`, plan mode, the task tracker, `update_topic`) share one capability, `task_planning`, so a default-deny policy can allow them in one line:

```yaml
## Capabilities
allow:
  - file_read
  - task_planning
default: deny
```

## Decisions

| WARD decision | What Gemini CLI sees |
|---|---|
| allow | nothing (`{}`): Gemini CLI's own confirmation prompts still apply |
| deny | `{"decision": "deny", "reason": "WARD: …"}`; the reason goes to the agent as the tool error |
| require_approval | a deny whose reason says approval is needed (Gemini CLI hooks have no "ask") |

**Failure modes:**
- **An invalid WARD.md always denies**, so a typo can't silently switch enforcement off.
- **No WARD.md anywhere means no enforcement.**
- **Malformed payloads and evaluator errors** allow by default. `weave-gemini init --fail-closed` makes them deny.

WARD.md is looked up in this order:
1. `$WEAVE_WARD_PATH`
2. `<project>/WARD.md`
3. `<project>/.gemini/WARD.md`
4. `<project>/.weave/WARD.md`
5. `~/.gemini/WARD.md`

## Commands

```bash
weave-gemini init [--matcher=REGEX] [--timeout=MS] [--fail-closed]
weave-gemini disable
weave-gemini status
weave-gemini test read_file --input='{"file_path":"secrets/key"}'   # dry run
weave-gemini hook before-tool                                        # what Gemini CLI runs
```

`init` backs up `settings.json`, edits it atomically, and finds its own entry by the hook name `weave-ward`, so your other hooks are untouched. It installs at user level. Gemini CLI fingerprints project-level hooks and warns when one changes, but a user-level hook covers every project.

## Dashboard

Set `WEAVE_DASHBOARD_URL` (and `WEAVE_API_KEY`) where you run the agent, and each decision is reported to a local [Weave API](https://github.com/Tyox-all/Weave_Protocol/tree/main/api) dashboard (0.2.0+). Only the decision and the tool name are sent, never command or argument contents. Reporting never changes a decision and gives up after 250 ms.

## Verified

Built against the [hooks reference](https://geminicli.com/docs/hooks/reference) and [tools reference](https://geminicli.com/docs/reference/tools). Live-checked in Gemini CLI 0.66.0: a `read_file` of a denied path was blocked with the WARD reason, and an allowed read went through.

## License

Apache-2.0
