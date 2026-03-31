---
name: security-inspection
description: "Real-time MCP security proxy with drift detection and reputation scoring. Use when: inspect tool calls, detect drift, check server reputation, approve/block operations, monitor agent activity, live feed."
---

# 🔍 Inspector - Real-Time Security Proxy

Intercept, scan, and gate AI agent tool calls in real-time.

## Installation

```bash
npm install @weave_protocol/inspector
```

## MCP Tools

### Session Management

| Tool | Purpose |
|------|---------|
| `inspector_create_session` | Start inspection session |
| `inspector_declare_intent` | Declare intended actions |
| `inspector_end_session` | End session with summary |

### Live Feed

| Tool | Purpose |
|------|---------|
| `inspector_get_live_feed` | Stream of intercepted calls |
| `inspector_get_call_history` | Query past calls |
| `inspector_diff_intent` | "Said X, doing Y" analysis |

### Approval Gate

| Tool | Purpose |
|------|---------|
| `inspector_get_pending` | List calls awaiting approval |
| `inspector_approve_call` | Approve a pending call |
| `inspector_block_call` | Block a pending call |

### Reputation

| Tool | Purpose |
|------|---------|
| `inspector_check_reputation` | Get server trust score |
| `inspector_report_suspicious` | Report bad behavior |
| `inspector_get_server_stats` | Server analytics |
| `inspector_list_servers` | List known servers |

### Configuration

| Tool | Purpose |
|------|---------|
| `inspector_set_policy` | Configure rules |
| `inspector_get_config` | View settings |
| `inspector_get_stats` | Overall statistics |

## Usage Examples

### Start Session with Intent

```typescript
// Create session
const session = await inspector_create_session({ agent_id: 'my-agent' });

// Declare what you plan to do
await inspector_declare_intent({
  session_id: session.session_id,
  intent: 'Read and summarize the README file'
});
```

### Monitor Live Activity

```typescript
// Get recent calls
const feed = await inspector_get_live_feed({ limit: 20 });

// Check for drift
const drift = await inspector_diff_intent({ session_id: 'abc123' });
if (drift.drift_detected_count > 0) {
  console.log('⚠️ Drift detected:', drift.drift_calls);
}
```

### Handle Pending Approvals

```typescript
// Get pending calls
const pending = await inspector_get_pending();

// Review and approve/block
for (const call of pending.pending) {
  if (call.risk_level === 'critical') {
    await inspector_block_call({
      call_id: call.id,
      reason: 'Critical risk level'
    });
  } else {
    await inspector_approve_call({ call_id: call.id });
  }
}
```

### Check Server Reputation

```typescript
// Before using a new server
const rep = await inspector_check_reputation({
  server_id: 'unknown-server'
});

if (rep.overall_score < 30) {
  console.log('⚠️ Low reputation server');
}

if (rep.known_malicious) {
  console.log('🚫 MALICIOUS SERVER - DO NOT USE');
}
```

### Report Suspicious Behavior

```typescript
await inspector_report_suspicious({
  server_id: 'bad-server',
  report_type: 'unexpected_actions',
  description: 'Server accessed files outside declared scope',
  evidence: 'Call log showing /etc/passwd access'
});
```

## Inspection Modes

| Mode | Behavior |
|------|----------|
| `passive` | Log only, never block |
| `active` | Block critical, review high-risk |
| `strict` | Block all high-risk automatically |

```typescript
await inspector_set_policy({ mode: 'strict' });
```

## Drift Detection

Detects when actual actions deviate from declared intent:

- **Tool mismatch**: Using unexpected tools
- **Scope expansion**: Accessing more than declared
- **Capability escalation**: Gaining new permissions
- **Data access**: Touching sensitive data unexpectedly

## Reputation Scores

- **90-100**: Verified, trusted
- **70-89**: Generally safe
- **50-69**: Neutral, unverified
- **30-49**: Caution advised
- **0-29**: High risk, likely malicious
