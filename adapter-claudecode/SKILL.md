---
name: adapter-claudecode
description: Use this skill when the user wants to enforce a WARD.md security policy inside Claude Code via its native hook system. Triggers on requests to "secure my Claude Code session", "block Claude Code from doing X", "install WARD hooks in Claude Code", "make Claude Code respect my policy file", or any work involving the `weave-claude-code` command. Also useful when reviewing a user's `~/.claude/settings.json` for hook configuration, or when a user reports that Claude Code is doing things they want stopped.
---

# Claude Code adapter for Weave Protocol

The `@weave_protocol/adapter-claudecode` package enforces [WARD.md](https://www.npmjs.com/package/@weave_protocol/ward) policies inside Claude Code via the `PreToolUse` hook system. When Claude Code is about to use a tool, the adapter reads the active WARD.md and blocks the call if it violates the policy.

## When to use

- User runs Claude Code and wants visibility/control over what it does
- User has a WARD.md and wants it enforced inside Claude Code (not just on MCP servers)
- User wants to lock down a sensitive project so Claude Code can't escape its bounds
- User has a global `~/.claude/WARD.md` they want applied to every session
- User wants to test what their WARD policy would do before deploying it

## Commands

```bash
weave-claude-code init [--matcher=X] [--fail-closed]    # Install hook
weave-claude-code disable                                # Remove hook
weave-claude-code status                                 # Show config + active policy
weave-claude-code test <tool> [--input=JSON]             # Dry-run a tool call
weave-claude-code help
```

## WARD resolution order

When the hook fires:

1. `$WEAVE_WARD_PATH` — explicit override
2. `<cwd>/WARD.md` — project root
3. `<cwd>/.weave/WARD.md` — alternate location
4. `~/.claude/WARD.md` — user-global fallback

First match wins. If none exists, the hook passes through silently.

## Tool mapping

Claude Code → WARD capability:

- `Bash` → `shell_exec` (also scans command string heuristically)
- `Edit`, `MultiEdit`, `Write` → `file_write`
- `Read` → `file_read`
- `Grep`, `LS`, `Glob` → `file_read` / `file_list`
- `WebFetch` → `http_request` (checks `url`)
- `WebSearch` → `web_search`
- `Task` → `subagent`
- `NotebookEdit` → `notebook_edit`

WARD.md can use either the literal Claude tool name (e.g., `Bash`) or the generic capability (`shell_exec`). The stricter rule wins.

## Decision rules

| Situation | Action |
|---|---|
| User wants to enforce WARD in Claude Code | `weave-claude-code init` |
| User wants to test their policy | `weave-claude-code test <tool>` |
| User wants global policy across all projects | Write `~/.claude/WARD.md` |
| User wants project-specific policy | Write `<project>/WARD.md` |
| User wants stricter failure mode | `init --fail-closed` |
| User wants to uninstall | `weave-claude-code disable` |
| User reports Claude Code blocked unexpectedly | `weave-claude-code status` (shows active policy and source) |

## Fail modes

- **fail-open** (default): broken or missing WARD.md → allow the call, warn to stderr
- **fail-closed** (`--fail-closed`): broken or missing WARD.md → block the call

Default is fail-open because broken policy files shouldn't break the user's workflow. Recommend fail-closed only for high-stakes environments (production deployment agents, etc.).

## Pairs with

- `@weave_protocol/ward` — the policy format being enforced
- `@weave_protocol/hundredmen` — enforces the same WARD.md on MCP servers (complementary)
- `@weave_protocol/cli` — `weave init` scaffolds projects with a WARD.md

## Anti-patterns

- **Don't hand-edit `~/.claude/settings.json` to add the hook.** Use `weave-claude-code init` so it backs up your config and stays idempotent.
- **Don't ship a project with `--fail-closed` and no WARD.md.** That blocks every tool call. Either ship a WARD.md or stay fail-open.
- **Don't expect WARD to catch semantic intent drift.** WARD is policy-as-code. For drift between declared intent and actual behavior, pair this with `hundredmen_declare_intent`.
