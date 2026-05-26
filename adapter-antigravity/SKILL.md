---
name: adapter-antigravity
description: Use this skill when the user wants to enforce a WARD.md security policy inside Google Antigravity via its hook system. Triggers on requests to "secure my Antigravity agent", "block agy from doing X", "install WARD hooks in Antigravity", "make Antigravity respect my policy file", or any work involving the `weave-antigravity` command or the `agy` CLI. Also useful when reviewing a user's `~/.gemini/antigravity-cli/settings.json` for hook configuration, or when a user reports that an Antigravity agent is doing things they want stopped.
---

# Google Antigravity adapter for Weave Protocol

The `@weave_protocol/adapter-antigravity` package enforces [WARD.md](https://www.npmjs.com/package/@weave_protocol/ward) policies inside Google Antigravity via the `PreToolUse` hook system. The same hook installation protects Antigravity 2.0 desktop, the `agy` CLI, and the Antigravity SDK because they share one agent harness with synced settings.

## When to use

- User runs Antigravity (desktop or `agy`) and wants visibility/control over what it does
- User has a WARD.md and wants it enforced inside Antigravity (not just on MCP servers or Claude Code)
- User wants to lock down GCP credentials, SSH keys, or specific paths from being read by the agent
- User wants the same policy to work across desktop, CLI, and SDK surfaces
- User has a global `~/.gemini/antigravity-cli/WARD.md` they want applied to every session

## Commands

```bash
weave-antigravity init [--matcher=X] [--fail-closed]    # Install hook
weave-antigravity disable                                # Remove hook
weave-antigravity status                                 # Show config + active policy
weave-antigravity test <tool> [--input=JSON]             # Dry-run a tool call
weave-antigravity help
```

## WARD resolution order

When the hook fires:

1. `$WEAVE_WARD_PATH` — explicit override
2. `<cwd>/WARD.md` — project root
3. `<cwd>/.agents/WARD.md` — **co-located with AGENTS.md** in the agent definition folder
4. `<cwd>/.weave/WARD.md` — alternate location
5. `~/.gemini/antigravity-cli/WARD.md` — user-global fallback

First match wins. If none exists, the hook passes through silently.

The `.agents/` location is significant — that's where AGENTS.md and project skills already live for Antigravity. Co-locating WARD.md there keeps all three policy files (`AGENTS.md`, `SKILL.md`, `WARD.md`) in one version-controlled directory.

## Tool mapping

Antigravity tool → WARD capability:

- `Bash` → `shell_exec` (also scans command string heuristically, including for `~/.config/gcloud`)
- `Edit`, `MultiEdit`, `Write` → `file_write`
- `Read` → `file_read`
- `Grep`, `LS`, `Glob` → `file_read` / `file_list`
- `WebFetch` → `http_request` (checks `url`)
- `WebSearch` → `web_search`
- `Task`, `Subagent` → `subagent`
- `RunCode` → `execute_code`
- `Plugin` → `plugin_invoke`

WARD.md can use either the literal Antigravity tool name (e.g., `Bash`) or the generic capability (`shell_exec`). The stricter rule wins.

## Decision rules

| Situation | Action |
|---|---|
| User wants to enforce WARD in Antigravity | `weave-antigravity init` |
| User wants to test their policy | `weave-antigravity test <tool>` |
| User wants global policy across all projects | Write `~/.gemini/antigravity-cli/WARD.md` |
| User wants project-specific policy | Write `<project>/WARD.md` or `<project>/.agents/WARD.md` |
| User wants stricter failure mode | `init --fail-closed` |
| User wants to uninstall | `weave-antigravity disable` |
| User reports Antigravity blocked unexpectedly | `weave-antigravity status` (shows active policy and source) |

## Fail modes

- **fail-open** (default): broken or missing WARD.md → allow the call, warn to stderr
- **fail-closed** (`--fail-closed`): broken or missing WARD.md → block the call

Default is fail-open because broken policy files shouldn't break the user's workflow. Recommend fail-closed only for high-stakes environments (production Managed Agents, automated pipelines).

## Pairs with

- `@weave_protocol/ward` — the policy format being enforced
- `@weave_protocol/adapter-claudecode` — same WARD.md, enforced inside Claude Code
- `@weave_protocol/hundredmen` — enforces the same WARD.md on MCP servers (complementary)
- `@weave_protocol/cli` — `weave init` scaffolds projects with a WARD.md

## Anti-patterns

- **Don't hand-edit `~/.gemini/antigravity-cli/settings.json` to add the hook.** Use `weave-antigravity init` so it backs up your config and stays idempotent.
- **Don't ship a project with `--fail-closed` and no WARD.md.** That blocks every tool call. Either ship a WARD.md or stay fail-open.
- **Don't use this for Managed Agents in the Gemini API yet** — that uses a different integration surface (programmatic via SDK). v0.2 will add SDK wrapper support.
