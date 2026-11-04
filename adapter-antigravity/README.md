# 🛡️ @weave_protocol/adapter-antigravity

[![npm version](https://img.shields.io/npm/v/@weave_protocol/adapter-antigravity.svg)](https://www.npmjs.com/package/@weave_protocol/adapter-antigravity)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/adapter-antigravity.svg)](https://www.npmjs.com/package/@weave_protocol/adapter-antigravity)
[![license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**WARD.md enforcement for [Google Antigravity](https://antigravity.google/), via the `PreToolUse` hook system shared across the Antigravity 2.0 desktop, Antigravity CLI (`agy`), and SDK.**

> *AGENTS.md tells your agent what to do. SKILL.md tells your agent how to do it. **WARD.md tells your agent what it can't.** This package makes Antigravity listen.*

Part of the [Weave Protocol](https://github.com/Tyox-all/Weave_Protocol) security suite. Second cross-platform harness adapter (after [adapter-claudecode](../adapter-claudecode)).

---

## 🆕 What's new

**0.4.0: decisions on the dashboard.** Set `WEAVE_DASHBOARD_URL` and each allow and deny goes to a local [Weave API](https://www.npmjs.com/package/@weave_protocol/api) dashboard. It's off by default.

**0.2.1:** enforces WARD.md in the `agy` 1.4 CLI.

**0.3.0: whole-call checks ([WARD-2026-001](https://github.com/Tyox-all/Weave_Protocol/blob/main/ward/SECURITY_ADVISORIES.md)).** Every path and URL argument and every token of a shell command is checked, and an invalid WARD.md blocks instead of switching enforcement off.

With [Ward](https://www.npmjs.com/package/@weave_protocol/ward) 0.3.3 or later, Antigravity also asks before an agent edits its own hook config, `WARD.md`, MCP config or git hooks.

## What it does

When Antigravity is about to use a tool (`run_command`, `write_to_file`, `view_file`, `read_url_content`, …), this adapter intercepts it through the `PreToolUse` hook, reads your project's `WARD.md`, and denies the call (or asks you) if it violates the declared policy.

> **0.2.0 fixes enforcement.** Versions up to 0.1.0 were built on assumptions that didn't match [Antigravity's hook docs](https://antigravity.google/docs/hooks): the wrong config file, payload fields, tool names and decision values. WARD rules were very likely not being enforced. Run `weave-antigravity init` again after upgrading; it installs the hook in the right place and removes the old entry.

```
You: "Push my GCP credentials to S3"
Antigravity: [about to run run_command with `cat ~/.config/gcloud/... | aws s3 cp -`]
       ↓
   PreToolUse hook fires
       ↓
   weave-antigravity reads ./WARD.md
       ↓
   checkFilesystem('read', '~/.config/gcloud') → DENY
       ↓
   Returns { "decision": "deny", "reason": "WARD: ..." }
       ↓
Antigravity refuses, shows reason.
```

Same agent harness powers Antigravity desktop, CLI, and SDK — so installing this hook protects every surface at once.

---

## Quick start

```bash
# Install once
npm install -g @weave_protocol/adapter-antigravity

# Wire it into Antigravity's hook config (~/.gemini/config/hooks.json)
weave-antigravity init
# …or just this workspace (.agents/hooks.json)
weave-antigravity init --workspace=.

# Drop a WARD.md in your project root (or next to AGENTS.md)
npx @weave_protocol/ward init

# Done. Run `agy` in that project — every tool call is now gated.
```

Verify with:

```bash
weave-antigravity status
```

---

## Mund pre-install hooks

Scan skills and MCP servers with [Mund](../mund#-pre-install-checks-for-skills-and-mcp-servers) before they can act:

```bash
npm i -g @weave_protocol/mund              # optional: faster than the npx fallback
weave-antigravity mund install             # global: ~/.gemini/config/hooks.json
weave-antigravity mund install --workspace=.   # or this workspace: .agents/hooks.json
```

This installs a hook named `weave-mund`, built against [Antigravity's hook docs](https://antigravity.google/docs/hooks):

| Event | What it does | Can block? |
|---|---|---|
| `SessionStart` | Audits skills (`.agents/skills`, `~/.gemini/config/skills`, CLI and plugin skills) and MCP servers (`.agents/mcp_config.json`, `~/.gemini/config/mcp_config.json`), and injects a summary | Reports only |
| `PreToolUse` | Scans content that `write_to_file`, `replace_file_content` or `multi_replace_file_content` would put into a skills folder, **before** it's written; **denies** MCP calls to servers Mund blocked and **asks** for flagged ones | ✅ |

Notes:
- Antigravity has no config-change event, so a skill copied in outside the agent is caught at the next session start, not before.
- Antigravity documents MCP permission patterns but not the runtime tool-name format, so the gate recognizes the common forms (`mcp__server__tool`, `mcp_server_tool`, `server__tool`, `server/tool`).
- Live checks start only global servers you configured; workspace servers and servers marked `disabled` get static checks only. Turn live checks off with `WEAVE_MUND_LIVE=0`.

## How WARD.md is resolved

When the hook fires, it looks for a WARD.md in this order:

1. `$WEAVE_WARD_PATH` — explicit env var override
2. `<workspace>/WARD.md`: the workspace is the first of `workspacePaths` in the hook payload
3. `<workspace>/.agents/WARD.md`: **co-located with AGENTS.md** in the agent definition folder
4. `<workspace>/.weave/WARD.md`: alternate project location
5. `~/.gemini/config/WARD.md`: **global**, next to `hooks.json`
6. `~/.gemini/antigravity-cli/WARD.md`: legacy global location

The first one that exists wins. If none exists, the hook silently passes through — zero impact on workflows that haven't adopted WARD yet.

The `.agents/` location is meaningful in Antigravity — it's the same folder where AGENTS.md and project skills are mounted into the sandbox. Putting `WARD.md` there keeps your agent's instruction file, skill files, and policy file all in one version-controlled place.

---

## Tool mapping

Antigravity's [documented tools](https://antigravity.google/docs/hooks) map to generic capability names, so a single WARD.md works across platforms:

| Antigravity tool | WARD capability | Checked argument | Implicit fs op |
|---|---|---|---|
| `run_command` | `shell_exec` | `CommandLine` (heuristic scan) | varies |
| `write_to_file` / `replace_file_content` / `multi_replace_file_content` | `file_write` | `TargetFile` | `write` |
| `view_file` | `file_read` | `AbsolutePath` | `read` |
| `grep_search` | `file_read` | `SearchPath` | `read` |
| `read_file` (agy CLI) | `file_read` | `Path` (workspace-relative paths resolved) | `read` |
| `write_file` / `edit_file` (agy CLI) | `file_write` | `Path` (workspace-relative paths resolved) | `write` |
| `list_dir` / `find_by_name` | `file_list` | `DirectoryPath` / `SearchDirectory` | `list` |
| `read_url_content` | `http_request` | `Url` | — |
| `search_web` | `web_search` | — | — |
| `invoke_subagent` / `define_subagent` | `subagent` | — | — |
| `send_message` / `manage_task` / `schedule` / `generate_image` | `agent_message` / `task_control` / `schedule` / `generate_image` | — | — |

The `agy` CLI (1.4.x) uses its own file tools, `read_file`, `write_file` and `edit_file`; their names and arguments were observed in a live session, not taken from the docs. Allowed calls produce no output: `agy` treats a bare `{}` as a deny.

Your WARD.md can use either name, for example `run_command` or `shell_exec`. Any other tool, including MCP tools, is checked by its raw name. Explicit rules win over default decisions.

For `run_command`, the adapter runs a light heuristic scan of the command line to catch common violations: URLs to denied domains, and references to sensitive paths like `~/.ssh`, `~/.aws`, **`~/.config/gcloud`** and `/etc/`.

Decisions use Antigravity's values: a policy violation returns `deny`, and a `requireApproval` rule returns **`ask`**, so Antigravity prompts you instead of the call being blocked.

---

## Commands

```bash
weave-antigravity init [--matcher=X] [--fail-closed] [--workspace=DIR]
    Install the WARD hook as "weave-ward" in ~/.gemini/config/hooks.json
    (or DIR/.agents/hooks.json). Also removes a pre-0.2 entry from
    ~/.gemini/antigravity-cli/settings.json.
    --matcher=REGEX            Restrict to specific tools (default: all), e.g. run_command|write_to_file
    --fail-closed              Deny on payload or evaluation errors (default: fail-open; an invalid WARD.md always denies)

weave-antigravity disable [--workspace=DIR]
    Remove the WARD hook (your other hooks are not touched)

weave-antigravity status
    Show hook installation state + active WARD policy

weave-antigravity test <tool> [--input=JSON]
    Dry-run a tool call against your WARD.md without invoking Antigravity

weave-antigravity help
```

### Examples

Test whether a destructive shell command would be allowed:

```bash
weave-antigravity test run_command --input='{"CommandLine":"rm -rf ~/.config/gcloud"}'
```

Test a file write to /etc/:

```bash
weave-antigravity test write_to_file --input='{"TargetFile":"/etc/passwd","CodeContent":"..."}'
```

Test a fetch to a denied domain:

```bash
weave-antigravity test read_url_content --input='{"Url":"https://evil.example.com/exfil"}'
```

---

## Fail-open vs fail-closed

**An invalid WARD.md always denies the call** (since 0.3.0). If a policy file exists but doesn't parse or validate, the hook denies every call with the error, so a typo can't silently switch enforcement off. If there's no WARD.md anywhere, nothing is enforced.

Malformed hook payloads and evaluator errors are **fail-open** by default: the call is allowed and a warning goes to stderr. For higher-stakes contexts, install with `--fail-closed` so those are denied too:

```bash
weave-antigravity init --fail-closed
```

---

## What gets installed

`weave-antigravity init` adds a named hook to `~/.gemini/config/hooks.json` (or `.agents/hooks.json` with `--workspace`), the format [Antigravity reads](https://antigravity.google/docs/hooks):

```json
{
  "weave-ward": {
    "enabled": true,
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "weave-antigravity hook pre-tool-use", "timeout": 5 }
        ]
      }
    ]
  }
}
```

Other named hooks in the file, including `weave-mund`, are left untouched. A backup is written to `hooks.json.weave-backup` before any change.

Antigravity sends the hook `{ "toolCall": { "name", "args" }, "workspacePaths", … }` on stdin, and the hook replies with `{ "decision": "deny" | "ask", "reason" }`, or prints nothing to leave the call to Antigravity.

---

## A sample WARD.md for Antigravity

```markdown
---
ward: "1.0"
agent: gcp-deploy-agent
---

# WARD.md

## Filesystem

allow:
  - read: /Users/me/projects/**
  - write: /Users/me/projects/**
deny:
  - read: ~/.ssh/**
  - read: ~/.config/gcloud/**
  - read: ~/.aws/**
  - write: /etc/**
default: deny

## Network

allow:
  - url: "https://api.github.com/**"
  - url: "https://generativelanguage.googleapis.com/**"
  - url: "https://registry.npmjs.org/**"
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
  - execute_code
default: deny

## Behavioral Limits

maxIterations: 100
maxCostUSD: 25.00
maxRuntimeSeconds: 1800
```

With this loaded, the Antigravity agent can read/write inside `~/projects` but cannot touch SSH/AWS/GCP credentials, requires approval for shell commands and subagent spawning, and is hard-blocked from raw code execution.

---

## Roadmap

Shipped:
- ✅ PreToolUse hook for CLI / desktop
- ✅ PreToolUse hook (0.2.0: rebuilt on the documented hooks.json / payload / decision contract)
- ✅ Mapping for Antigravity's documented built-in tools
- ✅ `run_command` heuristic scan including GCP credential paths
- ✅ `agy` 1.4 CLI enforcement (0.2.1)
- ✅ Whole-call checks through Ward's shared evaluator (0.3.0)
- ✅ Decision reporting to the Weave dashboard (0.4.0)

Planned:
- [ ] Managed Agents SDK wrapper for programmatic Gemini API calls
- [ ] Sandbox-mounted WARD.md (auto-include in `.agents/`)
- [ ] PostToolUse hook for attestation via Domere
- [ ] Plugin (extension) compatibility layer

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
