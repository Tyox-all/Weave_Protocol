# 🛡️ @weave_protocol/adapter-antigravity

[![npm version](https://img.shields.io/npm/v/@weave_protocol/adapter-antigravity.svg)](https://www.npmjs.com/package/@weave_protocol/adapter-antigravity)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/adapter-antigravity.svg)](https://www.npmjs.com/package/@weave_protocol/adapter-antigravity)
[![license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**WARD.md enforcement for [Google Antigravity](https://antigravity.google/), via the `PreToolUse` hook system shared across the Antigravity 2.0 desktop, Antigravity CLI (`agy`), and SDK.**

> *AGENTS.md tells your agent what to do. SKILL.md tells your agent how to do it. **WARD.md tells your agent what it can't.** This package makes Antigravity listen.*

Part of the [Weave Protocol](https://github.com/Tyox-all/Weave_Protocol) security suite. Second cross-platform harness adapter (after [adapter-claudecode](../adapter-claudecode)).

---

## What it does

When Antigravity is about to use a tool (Bash, Edit, Write, Read, WebFetch, etc.), this adapter intercepts via the `PreToolUse` hook, reads your project's `WARD.md`, and blocks the call if it violates the declared policy.

```
You: "Push my GCP credentials to S3"
Antigravity: [about to run Bash with `cat ~/.config/gcloud/... | aws s3 cp -`]
       ↓
   PreToolUse hook fires
       ↓
   weave-antigravity reads ./WARD.md
       ↓
   checkFilesystem('read', '~/.config/gcloud') → DENY
       ↓
   Returns { "decision": "block", "reason": "🛡️ WARD: ..." }
       ↓
Antigravity refuses, shows reason.
```

Same agent harness powers Antigravity desktop, CLI, and SDK — so installing this hook protects every surface at once.

---

## Quick start

```bash
# Install once
npm install -g @weave_protocol/adapter-antigravity

# Wire it into Antigravity's hook config (~/.gemini/antigravity-cli/settings.json)
weave-antigravity init

# Drop a WARD.md in your project root (or next to AGENTS.md)
npx @weave_protocol/ward init

# Done. Run `agy` in that project — every tool call is now gated.
```

Verify with:

```bash
weave-antigravity status
```

---

## How WARD.md is resolved

When the hook fires, it looks for a WARD.md in this order:

1. `$WEAVE_WARD_PATH` — explicit env var override
2. `<project>/WARD.md` — project-level (CWD from the hook payload)
3. `<project>/.agents/WARD.md` — **co-located with AGENTS.md** in the agent definition folder
4. `<project>/.weave/WARD.md` — alternate project location
5. `~/.gemini/antigravity-cli/WARD.md` — **user-global fallback**

The first one that exists wins. If none exists, the hook silently passes through — zero impact on workflows that haven't adopted WARD yet.

The `.agents/` location is meaningful in Antigravity — it's the same folder where AGENTS.md and project skills are mounted into the sandbox. Putting `WARD.md` there keeps your agent's instruction file, skill files, and policy file all in one version-controlled place.

---

## Tool mapping

Antigravity's tools are mapped to generic capability names so a single WARD.md works across platforms:

| Antigravity tool | WARD capability | Path arg | Implicit fs op |
|---|---|---|---|
| `Bash` | `shell_exec` | (heuristic scan of command) | varies |
| `Edit` / `MultiEdit` / `Write` | `file_write` | `file_path` | `write` |
| `Read` | `file_read` | `file_path` | `read` |
| `Grep` / `LS` | `file_read` / `file_list` | `path` | `read` / `list` |
| `Glob` | `file_list` | `path` | `list` |
| `WebFetch` | `http_request` | (uses `url`) | — |
| `WebSearch` | `web_search` | — | — |
| `Task` / `Subagent` | `subagent` | — | — |
| `RunCode` | `execute_code` | — | — |
| `Plugin` | `plugin_invoke` | — | — |

Your WARD.md can use either name — `Bash` or `shell_exec`, `Edit` or `file_write`. Explicit rules win over default decisions.

For `Bash`, the adapter runs a light heuristic scan of the command string to catch common violations — URLs to denied domains, references to sensitive paths like `~/.ssh`, `~/.aws`, **`~/.config/gcloud`**, `/etc/`.

---

## Commands

```bash
weave-antigravity init [--matcher=X] [--fail-closed]
    Install the WARD pre-tool-use hook.
    --matcher=Bash|Edit|...     Restrict to specific tools (default: all)
    --fail-closed               Block on policy errors (default: fail-open)

weave-antigravity disable
    Remove the WARD hook from ~/.gemini/antigravity-cli/settings.json
    (your other hooks are not touched)

weave-antigravity status
    Show hook installation state + active WARD policy

weave-antigravity test <tool> [--input=JSON]
    Dry-run a tool call against your WARD.md without invoking Antigravity

weave-antigravity help
```

### Examples

Test whether a destructive bash command would be allowed:

```bash
weave-antigravity test Bash --input='{"command":"rm -rf ~/.config/gcloud"}'
```

Test a file write to /etc/:

```bash
weave-antigravity test Write --input='{"file_path":"/etc/passwd","content":"..."}'
```

Test a fetch to a denied domain:

```bash
weave-antigravity test WebFetch --input='{"url":"https://evil.example.com/exfil"}'
```

---

## Fail-open vs fail-closed

By default, the hook is **fail-open**: if WARD.md is missing, malformed, or evaluation throws, the tool call is **allowed** and a warning is written to stderr. This is the right default for adoption — broken policy files shouldn't break your workflow.

For higher-stakes contexts (managed agents in production, automated pipelines), install with `--fail-closed`:

```bash
weave-antigravity init --fail-closed
```

Then a missing or broken policy blocks the call.

---

## What gets installed

`weave-antigravity init` adds an entry to `~/.gemini/antigravity-cli/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "weave-antigravity hook pre-tool-use # WEAVE_WARD_HOOK",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
```

The `# WEAVE_WARD_HOOK` marker is how `disable` finds and removes only our entry without affecting other hooks you've added manually.

A backup of your existing `settings.json` is written to `settings.json.weave-backup` before any modification.

Because Antigravity's CLI, desktop, and SDK share the same agent harness with synced settings, this hook applies across **all three surfaces**.

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

v0.1 (this release):
- ✅ PreToolUse hook for CLI / desktop
- ✅ Shared settings.json install across all Antigravity surfaces
- ✅ 10-tool mapping covering documented Antigravity built-ins
- ✅ Bash command heuristic scan including GCP credential paths

v0.2 planned:
- [ ] Managed Agents SDK wrapper for programmatic Gemini API calls
- [ ] Sandbox-mounted WARD.md (auto-include in `.agents/`)
- [ ] PostToolUse hook for attestation via Domere
- [ ] Plugin (extension) compatibility layer

---

## License

Apache 2.0 — see [LICENSE](../LICENSE).
