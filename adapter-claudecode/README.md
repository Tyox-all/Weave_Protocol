# 🛡️ @weave_protocol/adapter-claudecode

[![npm version](https://img.shields.io/npm/v/@weave_protocol/adapter-claudecode.svg)](https://www.npmjs.com/package/@weave_protocol/adapter-claudecode)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/adapter-claudecode.svg)](https://www.npmjs.com/package/@weave_protocol/adapter-claudecode)
[![license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**WARD.md enforcement for Claude Code, via Claude Code's native hook system.**

> *AGENTS.md tells your agent what to do. SKILL.md tells your agent how to do it. **WARD.md tells your agent what it can't.** This package makes Claude Code listen.*

Part of the [Weave Protocol](https://github.com/Tyox-all/Weave_Protocol) security suite. First in a planned series of cross-platform harness adapters (Claude Code → Antigravity → MDASH).

---

## 🆕 What's new

**0.5.0: session and spend limits.** WARD.md's limits are now enforced per session, keyed on the Claude Code `session_id`:
- Behavioral Limits: `maxToolCalls`, `maxRuntimeSeconds` and `maxExternalServices`;
- `spending_limits:` caps: tool calls, and per-tool call counts and USD amounts over a run, hour, day, week or month.

The counts live in a small local ledger (`~/.weave/ledger`, or `$WEAVE_LEDGER_DIR`) because every hook call is a new process. [Ward](https://www.npmjs.com/package/@weave_protocol/ward) 0.3.6's **payment guard** also asks before any call that moves money: payment tools, and wallet or Stripe CLIs in shell commands.

**0.4.0: decisions on the dashboard.** Set `WEAVE_DASHBOARD_URL` and each allow and deny goes to a local [Weave API](https://www.npmjs.com/package/@weave_protocol/api) dashboard. It's off by default.

**0.3.0: whole-call checks ([WARD-2026-001](https://github.com/Tyox-all/Weave_Protocol/blob/main/ward/SECURITY_ADVISORIES.md)).** Every path and URL argument and every token of a shell command is checked, and an invalid WARD.md blocks instead of switching enforcement off.

With [Ward](https://www.npmjs.com/package/@weave_protocol/ward) 0.3.3 or later, Claude Code also asks before an agent edits its own `.claude/settings.json`, `WARD.md`, MCP config or git hooks.

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

## Mund pre-install hooks

Scan skills and MCP servers with [Mund](../mund#-pre-install-checks-for-skills-and-mcp-servers) before they can act:

```bash
npm i -g @weave_protocol/mund          # optional: faster than the npx fallback
weave-claude-code mund install         # adds 4 hooks to ~/.claude/settings.json
```

| Hook | What it does | Can block? |
|---|---|---|
| `SessionStart` | Audits installed skills and MCP servers (`mund agent-audit --live`), caches the verdicts, and tells you and Claude what's flagged | Reports only |
| `PreToolUse` `^mcp__` | **Denies** tool calls to MCP servers Mund blocked; **asks** you for flagged ones | ✅ |
| `PreToolUse` `Write`/`Edit`/`MultiEdit` | Scans content an agent writes into `.claude/skills/` **before** it's written | ✅ |
| `ConfigChange` `skills` | Scans a changed skill file and stops a blocked change from taking effect | ✅ |

Notes:
- Claude Code has no hook that runs before it *connects* to an MCP server, so a flagged server may still start. The gate makes sure no tool call reaches it.
- Live checks only start servers you configured yourself or approved. Turn them off with `WEAVE_MUND_LIVE=0`.
- Every hook fails open (allows, with a note on stderr) if Mund can't run. `weave-claude-code mund status` shows how Mund is resolved: `$WEAVE_MUND_BIN`, then a local install, then `npx`.
- Remove the hooks with `weave-claude-code mund uninstall`; your other hooks are left alone.

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
    --fail-closed               Block on payload or evaluation errors (default: fail-open; an invalid WARD.md always blocks)

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

**An invalid WARD.md always blocks the call** (since 0.3.0). If a policy file exists but doesn't parse or validate, the hook blocks every call with the error, so a typo can't silently switch enforcement off. If there's no WARD.md anywhere, nothing is enforced.

Malformed hook payloads and evaluator errors are **fail-open** by default: the call is allowed and a warning goes to stderr. For higher-stakes contexts, install with `--fail-closed` so those block too:

```bash
weave-claude-code init --fail-closed
```

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
