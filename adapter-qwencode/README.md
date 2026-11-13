# 🛡️ @weave_protocol/adapter-qwencode

> Enforce [WARD.md](https://github.com/Tyox-all/Weave_Protocol/tree/main/ward) in **Qwen Code** with its `PreToolUse` hook. Every tool call the agent makes is checked against your policy before it runs, whichever model drives it: Qwen, DeepSeek, Kimi, GLM or a local model.

[![npm](https://img.shields.io/npm/v/@weave_protocol/adapter-qwencode?color=000&style=flat-square)](https://www.npmjs.com/package/@weave_protocol/adapter-qwencode)

The eighth WARD harness adapter. The same WARD.md works in Claude Code, Antigravity, Microsoft Agent Framework, Gemini CLI, Codex, OpenCode, Cursor and Qwen Code.

## Quick start

```bash
npm i -g @weave_protocol/adapter-qwencode
weave-qwen init          # adds the hook to ~/.qwen/settings.json
weave-qwen status        # hook installed? which WARD.md is active?
```

Then restart Qwen Code. Add a `WARD.md` to your project (`npx @weave_protocol/ward init`), or a user-wide one at `~/.qwen/WARD.md`.

## What it checks

The hook uses Ward's shared evaluator, so the rules match the other adapters exactly. That includes session and spend limits, the payment guard, outbound-data checks, model endpoints by jurisdiction, signed policies and decision receipts.

- **Capability:** the tool's WARD capability (`run_shell_command` → `shell_exec`, `read_file` → `file_read`, `edit` → `file_write`, …) or its raw name.
- **Arguments:** every path and URL argument, with `..` and `~` normalized.
- **Shell commands:** every URL and every absolute or `~` path in `run_shell_command`, with relative paths resolved against its `directory`.
- **`tool_call`:** Qwen Code reaches its deferred tools through `tool_call`. The hook decides the tool being called, with that tool's arguments, so the wrapper can't hide a call.
- **`exec` (code mode):** its JavaScript source is scanned like a shell command, for URLs, secret references and dangerous commands.
- **MCP tools:** by name, plus their path and URL arguments.

Tools that act on their own or later have their own capabilities, so a default-deny policy keeps them off until you allow them:
- scheduling (`cron_create` → `scheduled_task`);
- subagents (`agent` → `subagent`);
- messaging other agents (`send_message` → `agent_message`);
- pushing PRs (`autofix_pr` → `git_push`).

The planning and interaction tools (`todo_write`, `ask_user_question`, plan mode, the task list, `tool_search`) share one capability, `task_planning`:

```yaml
## Capabilities
allow:
  - file_read
  - task_planning
default: deny
```

## Decisions

| WARD decision | What Qwen Code sees |
|---|---|
| allow | nothing (`{}`): Qwen Code's own permission rules and prompts still apply |
| deny | `permissionDecision: "deny"` with the reason; the agent gets it as the tool result |
| require_approval | `permissionDecision: "ask"`: Qwen Code asks you in the terminal. Headless runs, background subagents and ACP sessions treat it as deny |

**Qwen Code lets a call through if a hook crashes, times out or exits with anything but 2.** So this hook never exits non-zero; every outcome is an explicit decision:
- **An invalid or unreadable WARD.md always denies**, so a typo can't silently switch enforcement off.
- **No WARD.md anywhere means no enforcement.**
- **Malformed payloads and evaluator errors** allow by default, like Weave's other adapters. `weave-qwen init --fail-closed` makes them deny.

WARD.md is looked up in this order:
1. `$WEAVE_WARD_PATH`
2. `<project>/WARD.md`
3. `<project>/.qwen/WARD.md`
4. `<project>/.weave/WARD.md`
5. `~/.qwen/WARD.md`

## Commands

```bash
weave-qwen init [--matcher=REGEX] [--timeout=SECONDS] [--fail-closed]
weave-qwen disable
weave-qwen status
weave-qwen test read_file --input='{"file_path":"secrets/key"}'   # dry run
weave-qwen hook pre-tool-use                                       # what Qwen Code runs
```

`init` backs up `settings.json`, edits it atomically, and finds its own entry by the hook name `weave-ward`, so your other hooks and settings are untouched. It installs at user level, so it covers every project. The default timeout is 10 seconds.

## Dashboard

Set `WEAVE_DASHBOARD_URL` (and `WEAVE_API_KEY`) where you run the agent, and each decision is reported to a local [Weave API](https://github.com/Tyox-all/Weave_Protocol/tree/main/api) dashboard as `qwen-code`. Only the decision and the tool name are sent, never command or argument contents. Reporting never changes a decision and gives up after 250 ms.

## Verified

Built against Qwen Code's [hooks documentation](https://qwenlm.github.io/qwen-code-docs/en/users/features/hooks/), and its tool names and parameter schemas in `packages/core/src/tools`.

Live-checked in Qwen Code 0.26.6. It ran headless against a local scripted model, so no API key or account was involved, and every decision was confirmed by Ward's signed receipts:
- a `read_file` and a `grep_search` of denied paths were blocked, and the model got the WARD reason as the tool result;
- an allowed read and `glob` went through;
- with a user rule in `settings.json` allowing `curl`, Ward still blocked `curl` to an unlisted host and allowed it to a listed one;
- the same calls replayed by Qwen Code's background memory agent were decided too.

## 🕸️ Part of Weave Protocol

One [WARD.md](https://github.com/Tyox-all/Weave_Protocol) policy for every agent you run, locally or at scale, plus the tools around it.

| Package | What it does |
|---|---|
| [Ward](https://www.npmjs.com/package/@weave_protocol/ward) | The WARD.md policy standard and the tool-call evaluator every adapter shares |
| [Mund](https://www.npmjs.com/package/@weave_protocol/mund) | Scans content for prompt injection (English and Chinese), secrets, PII and exfiltration |
| [Hord](https://www.npmjs.com/package/@weave_protocol/hord) | Encrypted vaults, PII tokenization, sandboxes, capability tokens, attestations |
| [Dōmere](https://www.npmjs.com/package/@weave_protocol/domere) | Audit threads, compliance checkpoints, GDPR and CCPA records, anchoring |
| [Witan](https://www.npmjs.com/package/@weave_protocol/witan) | Multi-agent consensus and spending caps |
| [Hundredmen](https://www.npmjs.com/package/@weave_protocol/hundredmen) | MCP proxy that enforces WARD.md on tool calls |
| [Tollere](https://www.npmjs.com/package/@weave_protocol/tollere) | Supply-chain checks: typosquats, CVEs, suspicious version diffs |
| [Browser](https://www.npmjs.com/package/@weave_protocol/browser) | WARD.md and injection scanning for Playwright browser agents |
| Adapters | WARD.md in [Claude Code](https://www.npmjs.com/package/@weave_protocol/adapter-claudecode), [Antigravity](https://www.npmjs.com/package/@weave_protocol/adapter-antigravity), [MSAF](https://www.npmjs.com/package/@weave_protocol/adapter-msaf), [Gemini CLI](https://www.npmjs.com/package/@weave_protocol/adapter-geminicli), [Codex](https://www.npmjs.com/package/@weave_protocol/adapter-codex), [OpenCode](https://www.npmjs.com/package/@weave_protocol/adapter-opencode), [Cursor](https://www.npmjs.com/package/@weave_protocol/adapter-cursor) and Qwen Code |
| [Adversary](https://www.npmjs.com/package/@weave_protocol/adversary) · [AgentSecBench](https://www.npmjs.com/package/@weave_protocol/agentsecbench) | Red-team engine and locked benchmark |
| [API](https://www.npmjs.com/package/@weave_protocol/api) · [CLI](https://www.npmjs.com/package/@weave_protocol/cli) · [LangChain](https://www.npmjs.com/package/@weave_protocol/langchain) | REST API and dashboard, setup CLI, LangChain.js integration |
| [full](https://www.npmjs.com/package/@weave_protocol/full) | Every defensive package in one install |
| [Yoxallismus](https://www.npmjs.com/package/@weave_protocol/yoxallismus) | Post-quantum hybrid cipher (experimental beta) |

---

## License

Apache-2.0
