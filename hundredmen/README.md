# 🔍 @weave_protocol/hundredmen

[![npm version](https://img.shields.io/npm/v/@weave_protocol/hundredmen.svg)](https://www.npmjs.com/package/@weave_protocol/hundredmen)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/hundredmen.svg)](https://www.npmjs.com/package/@weave_protocol/hundredmen)
[![license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Real-time MCP security proxy** that intercepts, scans, and gates AI agent tool calls. Now with [WARD.md](https://www.npmjs.com/package/@weave_protocol/ward) policy enforcement.

> *Old English "hundredmen" — the watchers of a hundred. Local officials who knew everyone passing through and could stop trouble before it spread.*

Part of the [Weave Protocol](https://github.com/Tyox-all/Weave_Protocol) security suite.

---

## 🆕 v1.1.0 — WARD.md enforcement

Hundredmen now reads your [WARD.md](https://www.npmjs.com/package/@weave_protocol/ward) file and **enforces it at the MCP interception layer**. Tool calls that violate the policy are blocked before they ever reach the underlying MCP server.

```
my-agent/
├── AGENTS.md          # what the agent does
├── SKILL.md           # how the agent does it
├── WARD.md            # what the agent can't do  ← Hundredmen enforces this
└── ...
```

Auto-detection: on startup, Hundredmen looks for `WARD.md` in the current working directory (or at `$WEAVE_WARD_PATH`). If found, it's loaded and every tool call is checked against the policy before being allowed through.

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

Restart Claude Desktop. If you have a `WARD.md` in your home directory or set `WEAVE_WARD_PATH`, Hundredmen will pick it up automatically.

---

## MCP tools

### Session & intent
- `hundredmen_create_session` — start an inspection session
- `hundredmen_declare_intent` — declare intended actions for drift detection
- `hundredmen_diff_intent` — compare declared vs actual
- `hundredmen_end_session` — wrap up a session

### Call inspection
- `hundredmen_get_live_feed` — real-time stream of intercepted calls
- `hundredmen_get_pending` — calls awaiting human approval
- `hundredmen_approve_call` / `hundredmen_block_call` — manual gating
- `hundredmen_get_call_history` — query past calls

### Reputation
- `hundredmen_check_reputation` — server trust score
- `hundredmen_list_servers` — all servers seen
- `hundredmen_report_suspicious` — flag bad behavior

### 🆕 WARD policy (v1.1.0)
- `hundredmen_load_ward` — load a WARD.md file
- `hundredmen_show_ward` — show the active policy
- `hundredmen_check_ward` — dry-run a tool call against the policy
- `hundredmen_unload_ward` — disable WARD enforcement for the session

### Config
- `hundredmen_get_config` / `hundredmen_set_policy` — runtime configuration
- `hundredmen_get_stats` / `hundredmen_get_server_stats` — metrics

---

## How WARD integration works

When a tool call arrives at Hundredmen, the gating order is:

1. **WARD policy check** (new) — capability/filesystem/network rules from your `WARD.md`
2. **Reputation check** — server trust score
3. **Intent analysis** — drift detection vs declared intent
4. **Manual approval** — if any gate requires it

WARD is the **first** gate. If a call is denied by WARD, the existing reputation/drift machinery never runs — the call is short-circuited and never reaches the underlying MCP server.

WARD's filesystem and network checks fire automatically when tool arguments look like file paths (`path`, `file`, `filepath`, etc.) or URLs (`url`, `endpoint`, etc.). You don't have to teach Hundredmen which tools touch what — it inspects the call shape.

---

## Programmatic use

```typescript
import { Interceptor, WardPolicyManager } from '@weave_protocol/hundredmen';

const interceptor = new Interceptor();
const wardManager = new WardPolicyManager();

wardManager.loadFromPath('./WARD.md');
interceptor.setWardManager(wardManager);

// ... your normal interceptor wiring
```

---

## License

Apache 2.0 — see [LICENSE](../LICENSE).
