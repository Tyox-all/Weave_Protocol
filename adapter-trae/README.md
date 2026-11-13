# 🛡️ @weave_protocol/adapter-trae

> Enforce [WARD.md](https://github.com/Tyox-all/Weave_Protocol/tree/main/ward) in **TRAE**, ByteDance's AI IDE (v3.5.66 or later), with its `PreToolUse` hook. Every tool call the agent makes is checked against your policy before it runs.

[![npm](https://img.shields.io/npm/v/@weave_protocol/adapter-trae?color=000&style=flat-square)](https://www.npmjs.com/package/@weave_protocol/adapter-trae)

This adapter is for TRAE only. The same WARD.md works in every Weave adapter.

## Quick start

```bash
npm i -g @weave_protocol/adapter-trae
weave-trae init          # adds the hook to ~/.trae/hooks.json
weave-trae status        # hook installed? which WARD.md is active?
```

`init` writes `~/.trae/hooks.json`, and also `~/.trae-cn/hooks.json` if you have TRAE's China build. Then, in TRAE, open **Settings > Hooks**, choose **Global**, and turn on **Configured Hooks**: TRAE ignores the file until you do. For session limits, the spend ledger and receipts in `~/.weave`, set the execution mode to **Run Automatically Locally** (see [Verified](#verified)). Add a `WARD.md` to your project (`npx @weave_protocol/ward init`), or a user-wide one at `~/.trae/WARD.md`.

## What it checks

The hook uses Ward's shared evaluator, so the rules match the other adapters exactly. That includes session and spend limits, the payment guard, outbound-data checks, model endpoints by jurisdiction, signed policies and decision receipts.

- **Capability:** the tool's WARD capability (`RunCommand` → `shell_exec`, `Read` → `file_read`, `Write`/`Edit` → `file_write`, …) or its raw name.
- **Arguments:** every path and URL argument, with `..` and `~` normalized.
- **Shell commands:** every URL and every absolute or `~` path in `RunCommand`.
- **MCP tools** (`mcp__<server>__<tool>`): by name, plus their path and URL arguments.

With several PreToolUse hooks, TRAE takes the strictest answer (deny, then ask, then allow), so another hook can't override a WARD deny. The workspace comes from the payload's `cwd`, then `TRAE_PROJECT_DIR`, then `workspace_roots`.

## Decisions

| WARD decision | What TRAE sees |
|---|---|
| allow | nothing (`{}`): TRAE's own permission rules and prompts still apply |
| deny | `permissionDecision: "deny"` with the reason; the agent gets it as the tool result |
| require_approval | `permissionDecision: "ask"`: you're asked to confirm |

**TRAE lets a call through if a hook crashes, times out or exits with anything but 2.** So this hook never exits non-zero; every outcome is an explicit decision:
- **An invalid or unreadable WARD.md always denies**, so a typo can't silently switch enforcement off.
- **No WARD.md anywhere means no enforcement.**
- **Malformed payloads and evaluator errors** allow by default, like Weave's other adapters. `weave-trae init --fail-closed` makes them deny.

WARD.md is looked up in this order:
1. `$WEAVE_WARD_PATH`
2. `<project>/WARD.md`
3. `<project>/.trae/WARD.md`
4. `<project>/.weave/WARD.md`
5. `~/.trae/WARD.md`

## Commands

```bash
weave-trae init [--matcher=REGEX] [--timeout=SECONDS] [--fail-closed]
weave-trae disable
weave-trae status
weave-trae test Read --input='{"file_path":"secrets/key"}'   # dry run
weave-trae hook pre-tool-use                                   # what TRAE runs
```

`init` backs up the config file and edits it atomically. It finds its own entry by its command, so your other hooks and settings are untouched. The default timeout is 10 seconds.

## Dashboard

Set `WEAVE_DASHBOARD_URL` (and `WEAVE_API_KEY`) where you run the agent, and each decision is reported to a local [Weave API](https://github.com/Tyox-all/Weave_Protocol/tree/main/api) dashboard as `trae`. Only the decision and the tool name are sent, never command or argument contents. Reporting never changes a decision and gives up after 250 ms.

## Verified

Built against TRAE's [hook configuration reference](https://docs.trae.ai/ide/hook-configuration-reference).

Live-checked in TRAE 3.6.13 (free plan, Agent mode), in a throwaway workspace with its own WARD.md and a project hook in `.trae/hooks.json`. Every decision was confirmed by Ward's signed receipts (8 verified: 6 allow, 2 deny):
- `LS` and allowed `Read`s went through, and a `Read` of `secrets/key` was blocked; the agent reported the WARD reason;
- `RunCommand` with `curl` to an unlisted host was blocked, and to a listed one it ran.

That run used **Run in Sandbox**, with the receipt directory set to a temp folder. We haven't checked whether the sandbox lets Ward write to `~/.weave`, so use **Run Automatically Locally** if you rely on session limits, the spend ledger or receipts there.

**TRAE ignores a `hooks.json` until you switch it on.** Our first run, before that, enforced nothing. Writing the file isn't enough: open **Settings > Hooks**, pick **Global** (for `weave-trae init`) or **Project**, turn on **Configured Hooks** and accept the warning. `weave-trae status` can only see the file, not that switch.

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
