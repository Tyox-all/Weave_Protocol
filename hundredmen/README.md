# 🔍 @weave_protocol/hundredmen

[![npm version](https://img.shields.io/npm/v/@weave_protocol/hundredmen.svg)](https://www.npmjs.com/package/@weave_protocol/hundredmen)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/hundredmen.svg)](https://www.npmjs.com/package/@weave_protocol/hundredmen)
[![license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Real-time MCP security proxy** that intercepts, scans, and gates AI agent tool calls. **v1.1.0 enforces [WARD.md](https://www.npmjs.com/package/@weave_protocol/ward) policies at the interception layer.**

> *Old English "hundredmen" — the watchers of a hundred. Local officials who knew everyone passing through and could stop trouble before it spread.*

Part of the [Weave Protocol](https://github.com/Tyox-all/Weave_Protocol) security suite.

---

## 🆕 v1.1.0 — WARD.md enforcement

Hundredmen now reads your project's [`WARD.md`](https://www.npmjs.com/package/@weave_protocol/ward) and **enforces it at the MCP interception layer**. Calls that violate the declared policy are blocked before they ever reach the underlying MCP server.

```
my-agent/
├── AGENTS.md          # what the agent does          (Google's format)
├── SKILL.md           # how the agent does it        (Anthropic's format)
├── WARD.md            # what the agent can't do      ← Hundredmen enforces
└── ...
```

Auto-detection on startup:

```
🔍 Weave Hundredmen MCP Server running
🛡️  WARD.md loaded from /Users/me/my-agent/WARD.md (My Agent Security Policy)
```

When a call violates the policy:

```json
{
  "decision": "auto_blocked",
  "decisionReason": "WARD: Tool 'shell_exec' is in the deny list."
}
```

When a call requires human approval per WARD:

```json
{
  "decision": "pending_review",
  "decisionReason": "WARD requires approval: Tool 'deploy' requires human approval before execution."
}
```

If no `WARD.md` is present, Hundredmen behaves exactly as v1.0 did — zero impact.

---

## Install

```bash
npm install @weave_protocol/hundredmen
```

## Use as a Claude Desktop MCP server

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "hundredmen": {
      "command": "npx",
      "args": ["-y", "@weave_protocol/hundredmen"]
    }
  }
}
```

Restart Claude Desktop. If you have a `WARD.md` in the CWD or set `$WEAVE_WARD_PATH`, Hundredmen will pick it up automatically.

---

## How WARD integration works

When a tool call arrives at Hundredmen, the gating order is:

1. **WARD policy** (new in v1.1.0) — capability/filesystem/network rules from your `WARD.md`
2. **Critical scan issues** — blocked content in args
3. **Reputation** — server trust score
4. **Intent / drift** — declared vs actual analysis
5. **Manual approval queue** — if any earlier gate said `require_approval`

WARD is the **first** gate. A WARD deny short-circuits everything else.

WARD's filesystem and network checks fire automatically when tool arguments look like file paths (`path`, `file`, `filepath`, `target`, ...) or URLs (`url`, `endpoint`, `uri`, ...). You don't have to teach Hundredmen which tools touch what — it inspects the call shape.

---

## MCP tools

### 🆕 WARD policy (v1.1.0)
- `hundredmen_load_ward({ path? })` — load a WARD.md file
- `hundredmen_show_ward()` — show the active policy
- `hundredmen_check_ward({ tool, args })` — dry-run a tool call against the policy
- `hundredmen_unload_ward()` — disable WARD enforcement for the session

### Session & intent
- `hundredmen_create_session({ agent_id? })`
- `hundredmen_declare_intent({ session_id, intent })`
- `hundredmen_diff_intent({ session_id })`
- `hundredmen_end_session({ session_id, reason? })`

### Call inspection
- `hundredmen_get_live_feed({ session_id?, server?, status?, limit? })`
- `hundredmen_get_pending()`
- `hundredmen_approve_call({ call_id, approved_by? })`
- `hundredmen_block_call({ call_id, blocked_by?, reason? })`
- `hundredmen_get_call_history({ ... })`

### Reputation
- `hundredmen_check_reputation({ server_id })`
- `hundredmen_list_servers({ filter?, min_score? })`
- `hundredmen_report_suspicious({ server_id, report_type, description, evidence? })`
- `hundredmen_get_server_stats({ server_id })`

### Config & stats
- `hundredmen_get_config()` / `hundredmen_set_policy({ ... })`
- `hundredmen_get_stats()`

---

## Programmatic use

```typescript
import { Interceptor, WardPolicyManager } from '@weave_protocol/hundredmen';

const interceptor = new Interceptor();
const wardManager = new WardPolicyManager();

// Auto-detect from CWD or $WEAVE_WARD_PATH
wardManager.autoLoad();

// Or explicit path
wardManager.loadFromPath('./policies/strict.WARD.md');

interceptor.setWardManager(wardManager);

// Now every call routed through interceptor.intercept() is checked against WARD
const call = await interceptor.intercept(sessionId, server, tool, args);
console.log(call.decision); // 'auto_approved' | 'auto_blocked' | 'pending_review'
```

---

## Example WARD.md

```markdown
---
ward: "1.0"
agent: my-agent
---

# WARD.md

## Capabilities
allow:
  - file_read
  - file_write
requireApproval:
  - deploy
  - secrets_read
deny:
  - shell_exec
  - eval
default: deny

## Filesystem
allow:
  - read: /workspace/**
  - write: /workspace/output/**
deny:
  - read: ~/.ssh/**
  - read: ~/.aws/**
default: deny

## Network
allow:
  - url: "https://api.openai.com/**"
  - url: "https://api.anthropic.com/**"
default: deny

## Behavioral Limits
maxCostUSD: 5.00
maxRuntimeSeconds: 300
```

See [@weave_protocol/ward](https://www.npmjs.com/package/@weave_protocol/ward) for the full WARD.md specification.

---

## License

Apache 2.0 — see [LICENSE](../LICENSE).
