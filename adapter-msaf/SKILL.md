---
name: adapter-msaf
description: Use this skill when the user wants to enforce a WARD.md security policy inside Microsoft Agent Framework (MSAF) via its middleware pipeline. Triggers on requests to "secure my Agent Framework agent", "block MSAF from doing X", "add WARD middleware to my agent", "lock down my Copilot SDK agent", or any work involving the `weave-msaf` command or programmatic WARD enforcement in a Microsoft agent setup. Also useful when reviewing a user's MSAF agent code for missing security middleware, or when a user wants to know how to express their WARD.md as runtime enforcement in C#/TypeScript/Python.
---

# Microsoft Agent Framework adapter for Weave Protocol

The `@weave_protocol/adapter-msaf` package enforces [WARD.md](https://www.npmjs.com/package/@weave_protocol/ward) policies inside Microsoft Agent Framework (MSAF) via its middleware pipeline. Unlike the Claude Code and Antigravity adapters which use config-file hooks, this adapter is a **library** that the user registers programmatically in their agent setup.

## When to use

- User is building an MSAF agent and wants policy enforcement at the tool-call layer
- User wants the same WARD.md they use elsewhere (Claude Code, Antigravity, MCP) to apply to their MSAF agent
- User wants typed exceptions (`WardDeniedError`) to catch and handle WARD denials in their code
- User wants per-agent enforcement (not global, since one process may run multiple agents with different policies)

## Architecture difference from claudecode / antigravity adapters

MSAF middleware is **registered programmatically**, not via a config file. So:
- No `init` writes to disk; instead it prints the integration snippet
- Middleware is per-agent, not global
- Runs in-process (no subprocess invocation overhead)

The user must paste a small code snippet into their MSAF agent setup. The CLI helps with `init` (snippet generator), `status` (verify policy resolution), and `test` (dry-run a call).

## Primary API

```typescript
import { WardMiddleware } from '@weave_protocol/adapter-msaf';

const ward = new WardMiddleware({
  // wardPath: './WARD.md'  // or auto-resolve from cwd
  // failMode: 'closed'      // or 'open' (default)
  // toolMappings: { ... }   // custom tool name → capability
  // onAllow: (call, result) => { ... }
  // onDeny:  (call, result) => { ... }
});

agent.useFunctionMiddleware(ward.functionMiddleware());
```

## WARD resolution order

1. `wardPath` option (explicit)
2. `wardSource` option (raw markdown)
3. `$WEAVE_WARD_PATH`
4. `<cwd>/WARD.md`
5. `<cwd>/.weave/WARD.md`
6. `<cwd>/.msaf/WARD.md`

## CLI

```bash
weave-msaf init [--language=ts|csharp|python]    # print integration snippet
weave-msaf status                                 # show active WARD + mappings
weave-msaf test <tool> [--input=JSON]             # dry-run a tool call
```

## Tool mapping

Covers MSAF's local agent runtime tools, Copilot SDK patterns, and Claude Code SDK integration (since MSAF can use them as a sub-harness):

- `ShellExec`/`Bash`/`RunCommand` → `shell_exec` (with command heuristic)
- `FileWrite`/`FileEdit`/`Edit`/`Write` → `file_write`
- `FileRead`/`Read` → `file_read`
- `FileDelete` → `file_delete`
- `ListDirectory` → `file_list`
- `HttpRequest`/`WebFetch` → `http_request`
- `SendEmail` → `send_email`
- `PostMessage` → `send_message`
- `CreateIssue` → `create_issue`
- `Subagent` → `subagent`

WARD.md can use either MSAF tool names or generic capabilities. Custom mappings via `toolMappings` option.

Bash command heuristic includes **Azure credential paths** (`~/.azure/`) — the realistic threat vector for MSAF users.

## Decision rules

| Situation | Action |
|---|---|
| User asks how to enforce WARD in their MSAF agent | Show `init` snippet + `WardMiddleware` construction |
| User wants to test policy without running the agent | `weave-msaf test <tool>` |
| User reports a tool call was blocked | Suggest catching `WardDeniedError` |
| User wants emergency override capability | Use `onDeny` callback returning `true` |
| User wants stricter failure mode | `failMode: 'closed'` |
| User uses non-standard tool names | `toolMappings: { MyTool: { capability: '...' } }` |

## Pairs with

- `@weave_protocol/ward` — the policy format being enforced
- `@weave_protocol/adapter-claudecode` — same WARD.md, enforced in Claude Code
- `@weave_protocol/adapter-antigravity` — same WARD.md, enforced in Antigravity
- `@weave_protocol/hundredmen` — enforces the same WARD.md on MCP servers
- `@weave_protocol/cli` — `weave init` scaffolds projects with a WARD.md

## Anti-patterns

- **Don't try to globally install this adapter via a config file.** MSAF doesn't work that way. Each agent registration is explicit.
- **Don't catch `WardDeniedError` and silently swallow it** — if a WARD says no, that's the policy. If you need to override, use the `onDeny` callback explicitly so the decision is logged.
- **Don't ship to production with `failMode: 'open'` and no WARD.md.** That's silent no-enforcement. Either ship a WARD.md or use `failMode: 'closed'` so a missing policy is loud.
- **Don't use this for MDASH** — MDASH is Microsoft's internal vulnerability-scanning research platform, not the Microsoft Agent Framework. This adapter targets MSAF (the public developer-facing framework).
