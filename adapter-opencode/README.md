# 🛡️ @weave_protocol/adapter-opencode

> Enforce [WARD.md](https://github.com/Tyox-all/Weave_Protocol/tree/main/ward) in **OpenCode** with a plugin. Every tool call is checked against your policy before it runs, whichever model you're using: Claude, GPT, Gemini, DeepSeek, Kimi, Qwen or a local one.

[![npm](https://img.shields.io/npm/v/@weave_protocol/adapter-opencode?color=000&style=flat-square)](https://www.npmjs.com/package/@weave_protocol/adapter-opencode)

The same WARD.md you use with Claude Code, Antigravity, Microsoft Agent Framework, Gemini CLI and Codex CLI.

## 🆕 What's new

**0.3.0: session and spend limits.** WARD.md's limits are now enforced per session, keyed on the OpenCode `sessionID`:
- Behavioral Limits: `maxToolCalls`, `maxRuntimeSeconds` and `maxExternalServices`;
- `spending_limits:` caps: tool calls, and per-tool call counts and USD amounts over a run, hour, day, week or month.

The counts live in a small local ledger (`~/.weave/ledger`, or `$WEAVE_LEDGER_DIR`) because every hook call is a new process. [Ward](https://www.npmjs.com/package/@weave_protocol/ward) 0.3.6's **payment guard** also asks before any call that moves money: payment tools, and wallet or Stripe CLIs in shell commands.

## Quick start

Add the plugin to OpenCode's config, either by hand:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["@weave_protocol/adapter-opencode"]
}
```

or with the CLI, which edits `~/.config/opencode/opencode.json` for you:

```bash
npx -p @weave_protocol/adapter-opencode weave-ward-opencode init
```

Restart OpenCode; it installs the plugin on startup. Add a `WARD.md` to your project (`npx @weave_protocol/ward init`), or a global one at `~/.config/opencode/WARD.md`.

The command is `weave-ward-opencode`, not `weave-opencode`. The `weave-opencode` npm name belongs to W&B Weave's opencode integration, which is a different product.

## What it checks

The plugin runs in OpenCode's `tool.execute.before` hook and uses Ward's shared evaluator (`evaluateToolCall`), so the rules match the other adapters exactly:

| Tool | Checked |
|---|---|
| `bash` | `shell_exec`, plus every URL and every absolute or `~` path in the command (relative paths resolve against `workdir`) |
| `read`, `write`, `edit` | `filePath` (read or write) |
| `glob`, `grep` | `path` (list or read) |
| `webfetch` | `url` |
| `apply_patch` | the files in its `patchText` (`*** Add/Update File` and `*** Move to` are writes, `*** Delete File` is a delete); patch content is never treated as a target |
| `todowrite`, `question` | the `task_planning` capability |
| MCP tools (`<server>_<tool>`) and custom tools | by name, plus every path- and URL-named argument |

A blocked call throws, and the agent sees `WARD: <reason>` as the tool error. A call that needs approval is blocked with a reason saying so.

**Policy loading:**
- **WARD.md is re-read on every call**, so edits take effect without restarting OpenCode.
- **An invalid WARD.md blocks every call**, so a typo can't silently switch enforcement off.
- **No WARD.md anywhere means no enforcement.**

WARD.md is looked up in this order:
1. `$WEAVE_WARD_PATH`
2. `<project>/WARD.md`
3. `<project>/.opencode/WARD.md`
4. `<project>/.weave/WARD.md`
5. `~/.config/opencode/WARD.md`

## Commands

```bash
weave-ward-opencode init       # add the plugin to ~/.config/opencode/opencode.json
weave-ward-opencode disable    # remove it
weave-ward-opencode status
weave-ward-opencode test read --input='{"filePath":"secrets/key"}'   # dry run
```

`init` backs up `opencode.json` and edits it atomically, leaving your other plugins and settings alone. It won't rewrite an `opencode.jsonc` file (it has comments); it tells you what to add instead.

## For plugin authors

The package's main entry default-exports only the plugin, `{ id: "weave-ward", server }`, as OpenCode's loader requires. The helpers are at `@weave_protocol/adapter-opencode/lib`.

## Dashboard

Set `WEAVE_DASHBOARD_URL` (and `WEAVE_API_KEY`) where you run the agent, and each decision is reported to a local [Weave API](https://github.com/Tyox-all/Weave_Protocol/tree/main/api) dashboard (0.2.0+). Only the decision and the tool name are sent, never command or argument contents. Reporting never changes a decision and gives up after 250 ms.

## Verified

Built against OpenCode's [plugin docs](https://opencode.ai/docs/plugins/), plus the plugin loader and tool schemas in OpenCode v1.19.5. 12 fixture tests.

Live-checked in OpenCode 1.19.5 (on Gemini 3.5 Flash-Lite), loaded as a local plugin:
- a `read` of `secrets/key` was blocked, and the model received `WARD: Denied by filesystem rule …`;
- a `write` of `TODO.md` outside the allowed folder was blocked, and no file was created;
- allowed `glob` and `read` calls went through.

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
