# 🔍 @weave_protocol/hundredmen

[![npm version](https://img.shields.io/npm/v/@weave_protocol/hundredmen.svg)](https://www.npmjs.com/package/@weave_protocol/hundredmen)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/hundredmen.svg)](https://www.npmjs.com/package/@weave_protocol/hundredmen)
[![license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Real-time MCP security proxy** that intercepts, scans, and gates AI agent tool calls, and enforces [WARD.md](https://www.npmjs.com/package/@weave_protocol/ward) policies at the interception layer.

> *Old English "hundredmen" — the watchers of a hundred. Local officials who knew everyone passing through and could stop trouble before it spread.*

Part of the [Weave Protocol](https://github.com/Tyox-all/Weave_Protocol) security suite.

---

## 🆕 What's new

**1.4.0: the same enforcement as the harness adapters.** Hundredmen now decides MCP calls with [Ward](https://www.npmjs.com/package/@weave_protocol/ward)'s shared evaluator, keyed on the MCP session. Every call gets:
- checks on every path, URL and command token;
- self-protection;
- checks on what the call sends;
- the payment guard, which holds money-moving tools for review;
- WARD.md's session and spend limits.

When WARD.md's Verification section says `required: true`, each decision is recorded as a signed, hash-chained receipt with `surface: "mcp"`. A signed WARD.md that was edited, or isn't signed by a key in `~/.weave/trusted-policy-keys`, blocks every call.

**1.3.2: checks what MCP calls send.** Using [Ward](https://www.npmjs.com/package/@weave_protocol/ward) 0.3.5, Hundredmen checks the URLs, message bodies and arguments of a call for credentials and personal data:
- it enforces WARD.md's `egressDeny`, even to allowed hosts;
- a credential sent anywhere but its issuer is held for review;
- so is sensitive data sent to a model API that WARD.md doesn't name.

**1.3.0: decisions on the dashboard.** Set `WEAVE_DASHBOARD_URL` and Hundredmen sends each allow and deny decision to a local [Weave API](https://www.npmjs.com/package/@weave_protocol/api) dashboard. It's off by default.

**1.2.0: whole-call checks.**
- Every path and URL argument of a call is checked against WARD.md, not just one field, using Ward's shared evaluator.
- Calls in a terminated session are blocked.

**1.1.0: WARD.md enforcement**, described below.

## WARD.md enforcement

Hundredmen reads your project's [`WARD.md`](https://www.npmjs.com/package/@weave_protocol/ward) and **enforces it at the MCP interception layer**. Calls that violate the declared policy are blocked before they ever reach the underlying MCP server.

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

If no `WARD.md` is present, Hundredmen runs its own interception rules only.

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
