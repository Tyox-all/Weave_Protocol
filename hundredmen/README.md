# 🔍 @weave_protocol/hundredmen

**Real-Time MCP Security Proxy for AI Agents**

[![npm](https://img.shields.io/npm/v/@weave_protocol/hundredmen.svg)](https://www.npmjs.com/package/@weave_protocol/hundredmen)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/hundredmen.svg)](https://www.npmjs.com/package/@weave_protocol/hundredmen)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Part of the [Weave Protocol](https://github.com/Tyox-all/Weave_Protocol) security suite.

---

## ✨ What It Does

Hundredmen sits between AI agents and MCP servers, providing:

```
┌─────────────────────────────────────────────────────────────┐
│  AI Agent (Claude Code, Cursor, etc.)                       │
└─────────────────┬───────────────────────────────────────────┘
                  │ Tool calls
                  ▼
┌─────────────────────────────────────────────────────────────┐
│  🔍 Weave Hundredmen                                         │
│                                                             │
│  • Intercept every tool call                                │
│  • Scan arguments for secrets, PII, injection               │
│  • Detect drift from declared intent                        │
│  • Check server reputation                                  │
│  • Gate risky operations for approval                       │
│  • Log everything with blockchain anchoring                 │
│                                                             │
└─────────────────┬───────────────────────────────────────────┘
                  │ Approved calls only
                  ▼
┌─────────────────────────────────────────────────────────────┐
│  Target MCP Servers (filesystem, github, slack, etc.)       │
└─────────────────────────────────────────────────────────────┘
```

**"Said X, Doing Y" Detection:** Catches when an AI agent says it will "read a file" but actually tries to "delete the database."

---

## 📦 Installation

```bash
npm install @weave_protocol/hundredmen
```

---

## 🚀 Quick Start

### Claude Desktop Integration

Add to `claude_desktop_config.json`:

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

### Basic Usage

```typescript
import { Interceptor, ReputationManager } from '@weave_protocol/hundredmen';

// Create components
const interceptor = new Interceptor({
  mode: 'active',           // 'passive' | 'active' | 'strict'
  scanEnabled: true,
  driftDetectionEnabled: true,
  reputationEnabled: true,
  minReputationScore: 30,
});

const reputationManager = new ReputationManager();

// Wire them together
interceptor.setReputationChecker(async (serverId) => {
  return reputationManager.getScore(serverId);
});

// Create a session
const session = interceptor.createSession('my-agent');

// Declare intent (enables drift detection)
interceptor.declareIntent(session.id, 'Read and summarize the README file');

// Intercept a tool call
const call = await interceptor.intercept(
  session.id,
  'filesystem',
  'read_file',
  { path: '/README.md' }
);

if (call.status === 'approved') {
  // Execute the actual call
  // ...
  interceptor.recordResult(call.id, result);
} else if (call.status === 'pending') {
  console.log('Manual approval required:', call.decisionReason);
} else {
  console.log('Blocked:', call.decisionReason);
}
```

---

## 🛠️ MCP Tools

### Session Management

| Tool | Purpose |
|------|---------|
| `hundredmen_create_session` | Start inspection session |
| `hundredmen_declare_intent` | Declare what you plan to do |
| `hundredmen_end_session` | End session and get summary |

### Live Feed & History

| Tool | Purpose |
|------|---------|
| `hundredmen_get_live_feed` | Real-time stream of intercepted calls |
| `hundredmen_get_call_history` | Query historical call data |
| `hundredmen_diff_intent` | "Said X, doing Y" analysis |

### Manual Approval

| Tool | Purpose |
|------|---------|
| `hundredmen_get_pending` | List calls waiting for approval |
| `hundredmen_approve_call` | Manually approve a pending call |
| `hundredmen_block_call` | Manually block a pending call |

### Reputation

| Tool | Purpose |
|------|---------|
| `hundredmen_check_reputation` | Get server trust score |
| `hundredmen_report_suspicious` | Report bad behavior |
| `hundredmen_get_server_stats` | Detailed server analytics |
| `hundredmen_list_servers` | List all known servers |

### Configuration

| Tool | Purpose |
|------|---------|
| `hundredmen_set_policy` | Configure inspection rules |
| `hundredmen_get_config` | View current settings |
| `hundredmen_get_stats` | Overall statistics |

---

## 🔒 Inspection Modes

| Mode | Behavior |
|------|----------|
| **passive** | Log everything, block nothing |
| **active** | Block critical issues, require approval for high-risk |
| **strict** | Block all high-risk operations automatically |

```typescript
// Set mode via tool
hundredmen_set_policy({ mode: 'strict' })

// Or programmatically
interceptor.setConfig({ mode: 'strict' });
```

---

## 📊 Reputation Scoring

Servers are scored 0-100 based on:

| Factor | Weight | Description |
|--------|--------|-------------|
| **Trust** | 30% | Verification status, age, known good |
| **Security** | 40% | Blocked calls, scan results |
| **Community** | 15% | User reports, confirmed issues |
| **Reliability** | 15% | Success rate, response time |

### Pre-loaded Trusted Servers

```
anthropic/filesystem     - 95
anthropic/github         - 95
anthropic/slack          - 90
modelcontextprotocol/*   - 85-90
```

### Automatic Detection

- Malicious name patterns (hack, exploit, etc.) → Start at 10
- Typosquatting detection → Flag for review
- Unknown servers → Start at 50

---

## 🎯 Drift Detection

Compares declared intent against actual tool calls:

```typescript
// Declare intent
hundredmen_declare_intent({
  session_id: 'abc123',
  intent: 'Read and summarize the README file'
});

// Later, if the agent tries to:
// - Delete files → DRIFT DETECTED (scope expansion)
// - Access payment data → DRIFT DETECTED (data access)
// - Execute code → DRIFT DETECTED (capability escalation)
```

Drift severity:
- **Low**: Minor deviation, auto-approved
- **Medium**: Requires review in active mode
- **High**: Blocked in strict mode, requires approval in active
- **Critical**: Always blocked

---

## 🔌 Integration with Mund & Domere

Hundredmen integrates with other Weave Protocol packages:

```typescript
import { Interceptor } from '@weave_protocol/hundredmen';
import { scan } from '@weave_protocol/mund';
import { ComplianceManager } from '@weave_protocol/domere';

const interceptor = new Interceptor();
const compliance = new ComplianceManager(['soc2']);

// Use Mund for scanning
interceptor.setScanner(async (content) => {
  const result = await scan(content);
  return {
    safe: result.safe,
    issues: result.issues,
    scannedAt: new Date(),
    scanDurationMs: 0,
  };
});

// Use Domere for blockchain anchoring
interceptor.setBlockchainAnchor(async (data) => {
  const checkpoint = await compliance.createCheckpoint({
    action: 'tool_call',
    resource: 'mcp',
    actor: 'hundredmen',
    metadata: data,
  });
  return checkpoint.id;
});
```

---

## 📈 Example: Security Dashboard

```typescript
// Get live feed for dashboard
const feed = await hundredmen_get_live_feed({ limit: 50 });

// Show pending approvals
const pending = await hundredmen_get_pending();

// Check overall health
const stats = await hundredmen_get_stats();

console.log(`
📊 Hundredmen Dashboard
─────────────────────
Total Calls:    ${stats.interceptor.totalCalls}
Approved:       ${stats.interceptor.approvedCalls}
Blocked:        ${stats.interceptor.blockedCalls}
Pending:        ${stats.interceptor.pendingCalls}
Active Sessions: ${stats.interceptor.activeSessions}

🏢 Server Health
─────────────────────
Total Servers:  ${stats.reputation.total_servers}
Verified:       ${stats.reputation.verified_servers}
Malicious:      ${stats.reputation.malicious_servers}
Low Rep:        ${stats.reputation.low_reputation_servers}
`);
```

---

## 🤖 AI Agent Skill

This package includes a `SKILL.md` for Claude AI integration.

**Skill name:** `security-inspection`

**Triggers:** inspect, intercept, drift, reputation, approve, block, live feed

---

## 📄 License

Apache 2.0 - See [LICENSE](../LICENSE)

---

## 🔗 Links

- **GitHub:** https://github.com/Tyox-all/Weave_Protocol
- **npm:** https://www.npmjs.com/package/@weave_protocol/hundredmen
- **Main README:** [Weave Protocol](../README.md)
