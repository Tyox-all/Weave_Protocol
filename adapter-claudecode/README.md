# 🛡️ @weave_protocol/adapter-claudecode

[![npm version](https://img.shields.io/npm/v/@weave_protocol/adapter-claudecode.svg)](https://www.npmjs.com/package/@weave_protocol/adapter-claudecode)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/adapter-claudecode.svg)](https://www.npmjs.com/package/@weave_protocol/adapter-claudecode)
[![license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**WARD.md enforcement for Claude Code, via Claude Code's native hook system.**

> *AGENTS.md tells your agent what to do. SKILL.md tells your agent how to do it. **WARD.md tells your agent what it can't.** This package makes Claude Code listen.*

Part of the [Weave Protocol](https://github.com/Tyox-all/Weave_Protocol) security suite. First in a planned series of cross-platform harness adapters (Claude Code → Antigravity → MDASH).

---

## What it does

When Claude Code is about to use a tool (Bash, Edit, Write, Read, WebFetch, etc.), this adapter intercepts via Claude Code's `PreToolUse` hook, reads your project's `WARD.md`, and blocks the call if it violates the declared policy.

```
You: "Delete all the SSH keys"
Claude Code: [about to run Bash with `rm -rf ~/.ssh`]
       ↓
   PreToolUse hook fires
       ↓
   weave-claude-code reads ./WARD.md
       ↓
   checkFilesystem('delete', '~/.ssh/**') → DENY
       ↓
   Returns { "decision": "block", "reason": "🛡️ WARD: ..." }
       ↓
Claude Code refuses, shows reason
```

No code changes needed in your project. Just a `WARD.md` file and a one-time hook install.

---

## Quick start

```bash
# Install once
npm install -g @weave_protocol/adapter-claudecode

# Wire it into Claude Code's hook config
weave-claude-code init

# Drop a WARD.md in your project root
npx @weave_protocol/ward init

# Done. Open Claude Code in that project — every tool call is now gated by WARD.
```

Verify with:

```bash
weave-claude-code status
```

---

## How WARD.md is resolved

When the hook fires, it looks for a WARD.md in this order:

1. `$WEAVE_WARD_PATH` — explicit env var override
2. `<project>/WARD.md` — project-level (CWD from the hook payload)
3. `<project>/.weave/WARD.md` — alternate project location
4. `~/.claude/WARD.md` — **user-global fallback** (applies to every Claude Code session)

The first one that exists wins. If none exists, the hook silently passes through — zero impact on workflows that haven't adopted WARD yet.

---

## Tool mapping

Claude Code's tools are mapped to generic capability names so a single WARD.md works across platforms:

| Claude Code tool | WARD capability | Path arg | Implicit fs op |
|---|---|---|---|
| `Bash` | `shell_exec` | (heuristic scan of command) | varies |
| `Edit` / `MultiEdit` / `Write` | `file_write` | `file_path` | `write` |
| `Read` | `file_read` | `file_path` | `read` |
| `Grep` / `LS` | `file_read` / `file_list` | `path` | `read` / `list` |
| `Glob` | `file_list` | `path` | `list` |
| `WebFetch` | `http_request` | (uses `url`) | — |
| `WebSearch` | `web_search` | — | — |
| `Task` | `subagent` | — | — |
| `TodoWrite` | `todo_write` | — | — |
| `NotebookEdit` | `notebook_edit` | `notebook_path` | `write` |

Your WARD.md can use either name — `Bash` or `shell_exec`, `Edit` or `file_write`. The stricter rule wins.

For `Bash`, the adapter also runs a light heuristic scan of the command string to catch obvious violations (URLs to denied domains, references to sensitive paths like `~/.ssh`, `~/.aws`, `/etc/`).

---

## Commands

```bash
weave-claude-code init [--matcher=X] [--fail-closed]
    Install the WARD pre-tool-use hook.
    --matcher=Bash|Edit|...     Restrict to specific tools (default: all)
    --fail-closed               Block on policy errors (default: fail-open)

weave-claude-code disable
    Remove the WARD hook from ~/.claude/settings.json
    (your other hooks are not touched)

weave-claude-code status
    Show hook installation state + active WARD policy for current dir

weave-claude-code test <tool> [--input=JSON]
    Dry-run a tool call against your WARD.md without invoking Claude Code

weave-claude-code help
```

### Examples

Test whether `rm -rf ~/.ssh` would be allowed:

```bash
weave-claude-code test Bash --input='{"command":"rm -rf ~/.ssh"}'
```

Test a file write to /etc/:

```bash
weave-claude-code test Write --input='{"file_path":"/etc/passwd","content":"..."}'
```

Test a fetch to a disallowed domain:

```bash
weave-claude-code test WebFetch --input='{"url":"https://evil.example.com/exfil"}'
```

---

## Fail-open vs fail-closed

By default, the hook is **fail-open**: if WARD.md is missing, malformed, or evaluation throws, the tool call is **allowed** and a warning is written to stderr. This is the right default for adoption — broken policy files shouldn't break your workflow.

For higher-stakes contexts, install with `--fail-closed`:

```bash
weave-claude-code init --fail-closed
```

Then a missing or broken policy blocks the call.

---

## What gets installed

`weave-claude-code init` adds an entry to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "weave-claude-code hook pre-tool-use # WEAVE_WARD_HOOK",
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

---

## A sample WARD.md for Claude Code

```markdown
---
ward: "1.0"
agent: my-coding-agent
---

# WARD.md

## Filesystem

allow:
  - read: /Users/me/projects/**
  - write: /Users/me/projects/**
deny:
  - read: ~/.ssh/**
  - read: ~/.aws/**
  - write: /etc/**
default: deny

## Network

allow:
  - url: "https://api.github.com/**"
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
deny:
  - subagent
default: deny

## Behavioral Limits

maxIterations: 50
maxCostUSD: 10.00
```

With this loaded, Claude Code is allowed to read/write inside `~/projects` but cannot touch SSH/AWS keys, will require approval before running shell commands, and is hard-blocked from spawning subagents.

---

## Programmatic use

```typescript
import {
  resolveWardForCwd,
  evaluateCall,
  installHook,
} from '@weave_protocol/adapter-claudecode';

const resolved = resolveWardForCwd(process.cwd());
if (resolved) {
  const decision = evaluateCall(resolved.policy, 'Bash', { command: 'rm -rf /' });
  console.log(decision.decision); // "deny"
}
```

---

## License

Apache 2.0 — see [LICENSE](../LICENSE).
