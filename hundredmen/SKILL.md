---
name: security-inspection
description: Use this skill when the user wants to inspect, intercept, or gate AI agent tool calls in real time. Triggers include monitoring agent activity, detecting drift between declared intent and actual actions, checking MCP server reputation, manually approving or blocking suspicious calls, viewing a live feed of agent operations, or enforcing a WARD.md security policy at the MCP layer. Also triggers when the user asks "is this tool call safe?", "block this call", "show what my agent is doing", or wants to test how their WARD policy would gate a specific operation.
---

# Hundredmen — Real-Time MCP Security Proxy

`@weave_protocol/hundredmen` intercepts MCP tool calls, analyzes them, and decides whether to allow, block, or require approval. v1.1.0 adds enforcement of [WARD.md](https://www.npmjs.com/package/@weave_protocol/ward) policies at the interception layer.

## When to use

- User has an agent and wants visibility into what tools it's calling
- User wants to gate sensitive operations behind manual approval
- User has a WARD.md and wants it enforced at runtime, not just declared
- User suspects drift: "the agent said X but is doing Y"
- User wants reputation tracking for the MCP servers they use

## Gating order

When a tool call hits Hundredmen, the checks run in this order:

1. **WARD policy** (if loaded) — capability/filesystem/network rules from `WARD.md`
2. **Reputation** — server trust score
3. **Intent / drift** — declared vs actual comparison
4. **Manual approval** — if any earlier gate produced `require_approval`

WARD is the first gate. A WARD deny short-circuits everything else.

## WARD-related tools

- `hundredmen_load_ward({ path? })` — load a WARD.md (auto-loads `./WARD.md` on startup)
- `hundredmen_show_ward()` — show currently active policy
- `hundredmen_check_ward({ tool, args })` — dry-run a tool call against the policy
- `hundredmen_unload_ward()` — disable WARD enforcement

## Other key tools

- `hundredmen_create_session({ agent_id? })`
- `hundredmen_declare_intent({ session_id, intent })`
- `hundredmen_diff_intent({ session_id })`
- `hundredmen_get_live_feed({ since?, limit? })`
- `hundredmen_get_pending()` / `hundredmen_approve_call` / `hundredmen_block_call`
- `hundredmen_check_reputation({ server_id })`
- `hundredmen_get_stats()` / `hundredmen_get_server_stats({ server_id })`

## Decision rules

| User says | Action |
|---|---|
| "Set up monitoring for my agent" | `hundredmen_create_session` + `hundredmen_declare_intent` |
| "What is my agent doing right now" | `hundredmen_get_live_feed` |
| "Why was this call blocked" | `hundredmen_show_ward` + check live feed for the blocked call |
| "Will my WARD block X" | `hundredmen_check_ward({ tool: 'X', args: {...} })` |
| "I want WARD enforcement on" | `hundredmen_load_ward()` (loads from CWD or env) |
| "This server seems off" | `hundredmen_check_reputation` + `hundredmen_report_suspicious` |

## Pairs with

- `@weave_protocol/ward` — the policy format Hundredmen enforces
- `@weave_protocol/mund` — input-level threat scanning (complementary to interception)
- `@weave_protocol/domere` — attests to the policy decisions for compliance proofs
- `@weave_protocol/witan` — consensus on high-stakes blocks

## Anti-patterns

- **Don't manually approve every call.** That defeats the point. Set a reasonable WARD policy or reputation threshold, only escalate to manual on edge cases.
- **Don't expect WARD to catch semantic intent drift.** WARD is policy-as-code (allow/deny). For drift detection use `hundredmen_declare_intent` + `hundredmen_diff_intent`.
- **Don't skip session declaration.** Without `hundredmen_declare_intent`, drift detection can't work.
