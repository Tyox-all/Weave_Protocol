# 🛡️ @weave_protocol/adapter-codebuddy

> Enforce [WARD.md](https://github.com/Tyox-all/Weave_Protocol/tree/main/ward) in **CodeBuddy Code**, Tencent's coding agent CLI, with its `PreToolUse` hook. Every tool call the agent makes is checked against your policy before it runs.

[![npm](https://img.shields.io/npm/v/@weave_protocol/adapter-codebuddy?color=000&style=flat-square)](https://www.npmjs.com/package/@weave_protocol/adapter-codebuddy)

This adapter is for CodeBuddy Code only. The same WARD.md works in every Weave adapter.

## Quick start

```bash
npm i -g @weave_protocol/adapter-codebuddy
weave-codebuddy init          # adds the hook to ~/.codebuddy/settings.json
weave-codebuddy status        # hook installed? which WARD.md is active?
```

Then open `/hooks` in CodeBuddy Code and approve the new hook. CodeBuddy Code doesn't load edited hooks until you review them there. Add a `WARD.md` to your project (`npx @weave_protocol/ward init`), or a user-wide one at `~/.codebuddy/WARD.md`.

## What it checks

The hook uses Ward's shared evaluator, so the rules match the other adapters exactly. That includes session and spend limits, the payment guard, outbound-data checks, model endpoints by jurisdiction, signed policies and decision receipts.

- **Capability:** the tool's WARD capability (`Bash` → `shell_exec`, `Read` → `file_read`, `Write`/`Edit` → `file_write`, …) or its raw name.
- **Arguments:** every path and URL argument, with `..` and `~` normalized.
- **Shell commands:** every URL and every absolute or `~` path in `Bash`.
- **MCP tools** (`mcp__<server>__<tool>`): by name, plus their path and URL arguments.

CodeBuddy Code runs PreToolUse hooks before its own permission prompts. An explicit `allow` would skip those prompts, so this adapter never sends one; your permission rules still apply to every call Ward allows.

## Decisions

| WARD decision | What CodeBuddy Code sees |
|---|---|
| allow | nothing (`{}`): CodeBuddy Code's own permission rules and prompts still apply |
| deny | `permissionDecision: "deny"` with the reason; the agent gets it as the tool result |
| require_approval | `permissionDecision: "ask"`: you're asked to confirm |

**CodeBuddy Code lets a call through if a hook crashes, times out or exits with anything but 2.** So this hook never exits non-zero; every outcome is an explicit decision:
- **An invalid or unreadable WARD.md always denies**, so a typo can't silently switch enforcement off.
- **No WARD.md anywhere means no enforcement.**
- **Malformed payloads and evaluator errors** allow by default, like Weave's other adapters. `weave-codebuddy init --fail-closed` makes them deny.

WARD.md is looked up in this order:
1. `$WEAVE_WARD_PATH`
2. `<project>/WARD.md`
3. `<project>/.codebuddy/WARD.md`
4. `<project>/.weave/WARD.md`
5. `~/.codebuddy/WARD.md`

## Commands

```bash
weave-codebuddy init [--matcher=REGEX] [--timeout=SECONDS] [--fail-closed]
weave-codebuddy disable
weave-codebuddy status
weave-codebuddy test Read --input='{"file_path":"secrets/key"}'   # dry run
weave-codebuddy hook pre-tool-use                                   # what CodeBuddy Code runs
```

`init` backs up the config file and edits it atomically. It finds its own entry by its command, so your other hooks and settings are untouched. The default timeout is 10 seconds.

## Dashboard

Set `WEAVE_DASHBOARD_URL` (and `WEAVE_API_KEY`) where you run the agent, and each decision is reported to a local [Weave API](https://github.com/Tyox-all/Weave_Protocol/tree/main/api) dashboard as `codebuddy`. Only the decision and the tool name are sent, never command or argument contents. Reporting never changes a decision and gives up after 250 ms.

## Verified

Built against CodeBuddy Code's [hooks reference](https://www.codebuddy.ai/docs/cli/hooks).

Live-checked in CodeBuddy Code 2.180.0. It ran headless (`-p`) against a local scripted model configured in `~/.codebuddy/models.json`, so no login or API key was involved, and every decision was confirmed by Ward's signed receipts:
- a `Read` of a denied path and a `Grep` into it were blocked, and the model got the WARD reason ("PreToolUse:Read hook blocked this tool call: WARD: …");
- an allowed `Read` went through;
- with a user rule in `settings.json` allowing `curl`, Ward still blocked `curl` to an unlisted host and allowed it to a listed one.

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
| Adapters | WARD.md in [Claude Code](https://www.npmjs.com/package/@weave_protocol/adapter-claudecode), [Antigravity](https://www.npmjs.com/package/@weave_protocol/adapter-antigravity), [MSAF](https://www.npmjs.com/package/@weave_protocol/adapter-msaf), [Gemini CLI](https://www.npmjs.com/package/@weave_protocol/adapter-geminicli), [Codex](https://www.npmjs.com/package/@weave_protocol/adapter-codex), [OpenCode](https://www.npmjs.com/package/@weave_protocol/adapter-opencode), [Cursor](https://www.npmjs.com/package/@weave_protocol/adapter-cursor), [Qwen Code](https://www.npmjs.com/package/@weave_protocol/adapter-qwencode), [CodeBuddy Code](https://www.npmjs.com/package/@weave_protocol/adapter-codebuddy), [Qoder](https://www.npmjs.com/package/@weave_protocol/adapter-qoder) and [TRAE](https://www.npmjs.com/package/@weave_protocol/adapter-trae) |
| [Adversary](https://www.npmjs.com/package/@weave_protocol/adversary) · [AgentSecBench](https://www.npmjs.com/package/@weave_protocol/agentsecbench) | Red-team engine and locked benchmark |
| [API](https://www.npmjs.com/package/@weave_protocol/api) · [CLI](https://www.npmjs.com/package/@weave_protocol/cli) · [LangChain](https://www.npmjs.com/package/@weave_protocol/langchain) | REST API and dashboard, setup CLI, LangChain.js integration |
| [full](https://www.npmjs.com/package/@weave_protocol/full) | Every defensive package in one install |
| [Yoxallismus](https://www.npmjs.com/package/@weave_protocol/yoxallismus) | Post-quantum hybrid cipher (experimental beta) |

---

## License

Apache-2.0
