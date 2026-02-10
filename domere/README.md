# ⚖️ Dōmere - Judge Protocol

[![npm version](https://img.shields.io/npm/v/@weave_protocol/domere.svg)](https://www.npmjs.com/package/@weave_protocol/domere)
[![license](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![downloads](https://img.shields.io/npm/dm/@weave_protocol/domere.svg)](https://www.npmjs.com/package/@weave_protocol/domere)

**Enterprise-grade verification, compliance, and audit infrastructure for AI agents.**

Part of the [Weave Protocol Security Suite](https://github.com/Tyox-all/Weave_Protocol).

## ✨ Features

- 🎯 **Intent Tracking** - Track and verify agent intent throughout execution
- 🔄 **Execution Replay** - Complete audit trails with cryptographic verification
- 🤝 **Multi-Agent Handoff** - Secure delegation between AI agents
- 📋 **Compliance Checkpoints** - SOC2, HIPAA, GDPR automated tracking
- ⛓️ **Blockchain Anchoring** - Immutable proof on Solana & Ethereum
- 🔍 **Drift Detection** - Detect when agents deviate from original intent

## 📦 Installation

```bash
npm install @weave_protocol/domere
```

## 🚀 Quick Start

### Thread Management

```typescript
import { ThreadManager } from '@weave_protocol/domere';

const manager = new ThreadManager();

// Create verified thread
const thread = await manager.createThread({
  origin_type: 'human',
  origin_identity: 'user@company.com',
  intent: 'Generate quarterly report',
  constraints: ['read-only', 'no-external-api']
});

// Check for intent drift
const drift = await manager.checkDrift(thread.id, 'Sending data to external API');
// → { drifted: true, reason: 'Violates no-external-api constraint' }
```

### 🔄 Execution Replay

Complete audit trail with cryptographic verification for forensic analysis.

```typescript
import { ExecutionReplayManager } from '@weave_protocol/domere';

const replay = new ExecutionReplayManager('encryption-key');

// Record every agent action
await replay.recordAction({
  thread_id: 'thr_xxx',
  agent_id: 'gpt-4-agent',
  agent_type: 'llm',
  action_type: 'inference',
  action_name: 'generate_report',
  input: { prompt: '...' },
  output: { response: '...' },
  latency_ms: 1250,
  cost_usd: 0.03,
  tokens_in: 500,
  tokens_out: 1000,
  model: 'gpt-4',
  provider: 'openai'
});

// Get complete execution trail
const trail = await replay.getExecutionTrail('thr_xxx');
console.log(trail.integrity_valid);  // true - chain is tamper-proof
console.log(trail.merkle_root);      // For blockchain anchoring

// Generate audit report
const report = await replay.generateAuditReport({
  thread_id: 'thr_xxx',
  start_time: new Date('2026-01-01'),
  end_time: new Date('2026-01-31')
});
// → { total_actions: 150, total_cost_usd: 4.50, anomalies: [...] }
```

### 🤝 Multi-Agent Handoff Verification

Secure delegation between AI agents with permission inheritance.

```typescript
import { HandoffManager } from '@weave_protocol/domere';

const handoff = new HandoffManager('signing-key', {
  max_delegation_depth: 5,
  max_handoff_duration_ms: 3600000 // 1 hour
});

// Agent A delegates to Agent B
const token = await handoff.createHandoff({
  thread_id: 'thr_xxx',
  from_agent: 'orchestrator',
  to_agent: 'researcher',
  delegated_intent: 'Find Q3 revenue data',
  constraints: ['read-only', 'internal-data-only'],
  permissions: [
    { resource: 'database', actions: ['read'] },
    { resource: 'files', actions: ['read'] }
  ],
  max_actions: 10,
  expires_in_ms: 300000 // 5 minutes
});

// Agent B verifies before acting
const verification = await handoff.verifyHandoff(token.token, 'researcher');
if (verification.valid) {
  console.log('Remaining actions:', verification.remaining_actions);
  console.log('Constraints:', verification.constraints);
}

// Track delegation chain
const chain = await handoff.getDelegationChain('thr_xxx');
console.log('Delegation depth:', chain.depth);
console.log('Chain integrity:', chain.integrity_valid);
```

### 📋 Compliance Checkpoints - SOC2/HIPAA

Automated compliance tracking and reporting.

```typescript
import { ComplianceManager } from '@weave_protocol/domere';

const compliance = new ComplianceManager('signing-key');

// HIPAA: Log PHI access
await compliance.logPHIAccess({
  thread_id: 'thr_xxx',
  agent_id: 'medical-assistant',
  patient_id: 'patient_123',
  access_reason: 'Treatment recommendation',
  data_accessed: ['diagnosis', 'medications'],
  legal_basis: 'treatment'
});

// SOC2: Log access control event
await compliance.logAccessControl({
  thread_id: 'thr_xxx',
  agent_id: 'admin-bot',
  user_id: 'user_456',
  resource: 'financial-reports',
  action: 'grant',
  success: true
});

// Generic compliance checkpoint
await compliance.checkpoint({
  thread_id: 'thr_xxx',
  framework: 'SOC2',
  control: 'CC6.1', // Logical Access Security
  event_type: 'access',
  event_description: 'User accessed sensitive data',
  data_classification: 'confidential',
  agent_id: 'data-agent',
  sign: true
});

// Generate compliance report
const report = await compliance.generateReport({
  framework: 'HIPAA',
  period_start: new Date('2026-01-01'),
  period_end: new Date('2026-03-31'),
  attester: 'Compliance Officer'
});

console.log('Compliance Score:', report.compliance_score);
console.log('Open Violations:', report.open_violations);
console.log('Control Coverage:', report.control_coverage);
```

### ⛓️ Blockchain Anchoring

Immutable proof of AI agent actions on Solana and Ethereum.

```typescript
import { SolanaAnchor, EthereumAnchor } from '@weave_protocol/domere';

// Solana (Devnet)
const solana = new SolanaAnchor({
  rpc_url: 'https://api.devnet.solana.com',
  program_id: 'BeCYVJYfbUu3k2TPGmh9VoGWeJwzm2hg2NdtnvbdBNCj'
});

await solana.anchorThread({
  thread_id: 'thr_xxx',
  merkle_root: trail.merkle_root,
  hop_count: 5,
  intent_hash: thread.intent_hash,
  compliant: true
});

// Ethereum (Mainnet)
const ethereum = new EthereumAnchor({
  rpc_url: 'https://mainnet.infura.io/v3/YOUR_KEY',
  contract_address: '0xAA8b52adD3CEce6269d14C6335a79df451543820'
});

await ethereum.anchorThread({
  thread_id: 'thr_xxx',
  merkle_root: trail.merkle_root,
  hop_count: 5,
  intent_hash: thread.intent_hash,
  compliant: true
});
```

## ⛓️ Blockchain Deployments

| Chain | Network | Contract/Program | Explorer |
|-------|---------|------------------|----------|
| **Solana** | Devnet | `BeCYVJYfbUu3k2TPGmh9VoGWeJwzm2hg2NdtnvbdBNCj` | [View](https://solscan.io/account/BeCYVJYfbUu3k2TPGmh9VoGWeJwzm2hg2NdtnvbdBNCj?cluster=devnet) |
| **Ethereum** | Mainnet | `0xAA8b52adD3CEce6269d14C6335a79df451543820` | [View](https://etherscan.io/address/0xAA8b52adD3CEce6269d14C6335a79df451543820) |

## 📚 API Reference

### ExecutionReplayManager

| Method | Description |
|--------|-------------|
| `recordAction(params)` | Record an action in the audit trail |
| `getExecutionTrail(threadId)` | Get complete trail for a thread |
| `replayActions(threadId)` | Replay actions for analysis |
| `generateAuditReport(query)` | Generate audit report |
| `verifyTrailIntegrity(actions)` | Verify chain hasn't been tampered |
| `exportTrail(threadId)` | Export trail as JSON |
| `importTrail(data)` | Import trail from JSON |

### HandoffManager

| Method | Description |
|--------|-------------|
| `createHandoff(params)` | Create delegation token |
| `verifyHandoff(token, agentId)` | Verify token before acting |
| `recordAction(handoffId, action)` | Record action under handoff |
| `revokeHandoff(handoffId)` | Revoke handoff and children |
| `getDelegationChain(threadId)` | Get full delegation chain |
| `checkPermission(handoffId, resource, action)` | Check if action permitted |

### ComplianceManager

| Method | Description |
|--------|-------------|
| `checkpoint(params)` | Record compliance checkpoint |
| `logPHIAccess(params)` | HIPAA: Log PHI access |
| `logAccessControl(params)` | SOC2: Log access control |
| `recordViolation(params)` | Record compliance violation |
| `updateRemediation(id, status)` | Update remediation status |
| `generateReport(params)` | Generate compliance report |
| `getCheckpoints(threadId)` | Get checkpoints for thread |
| `getViolations(threadId)` | Get violations for thread |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Dōmere - Judge Protocol                  │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │  Execution  │  │   Handoff   │  │      Compliance         │  │
│  │   Replay    │  │   Manager   │  │       Manager           │  │
│  ├─────────────┤  ├─────────────┤  ├─────────────────────────┤  │
│  │ • Recording │  │ • Tokens    │  │ • SOC2 Controls         │  │
│  │ • Trails    │  │ • Verify    │  │ • HIPAA Controls        │  │
│  │ • Reports   │  │ • Revoke    │  │ • Checkpoints           │  │
│  │ • Anomalies │  │ • Chain     │  │ • Violations            │  │
│  └─────────────┘  └─────────────┘  │ • Reports               │  │
│                                    └─────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────┐  ┌─────────────────────────────┐   │
│  │    Thread Manager       │  │    Blockchain Anchoring     │   │
│  │  • Intent Tracking      │  │  • Solana (Devnet)          │   │
│  │  • Drift Detection      │  │  • Ethereum (Mainnet)       │   │
│  │  • Constraints          │  │  • Merkle Proofs            │   │
│  └─────────────────────────┘  └─────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## 🔗 Related Packages

| Package | Description |
|---------|-------------|
| [@weave_protocol/mund](https://www.npmjs.com/package/@weave_protocol/mund) | Guardian Protocol - Secret & threat scanning |
| [@weave_protocol/hord](https://www.npmjs.com/package/@weave_protocol/hord) | Vault Protocol - Secure containment |
| [@weave_protocol/api](https://www.npmjs.com/package/@weave_protocol/api) | Universal REST API |

## 📄 License

Apache 2.0 - See [LICENSE](LICENSE) for details.

---

Made with ❤️ for AI Safety
