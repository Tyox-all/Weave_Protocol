# 🛡️ Weave Protocol Security Suite

[![npm version](https://img.shields.io/npm/v/@weave_protocol/domere.svg)](https://www.npmjs.com/package/@weave_protocol/domere)
[![license](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![downloads](https://img.shields.io/npm/dm/@weave_protocol/domere.svg)](https://www.npmjs.com/package/@weave_protocol/domere)

**Enterprise-grade security infrastructure for AI agents.** Weave Protocol provides defense-in-depth for autonomous AI systems through secret scanning, secure containment, intent verification, execution replay, multi-agent handoff, and compliance tracking.

## 📦 Packages

| Package | Description | Install |
|---------|-------------|---------|
| **[@weave_protocol/mund](./mund)** | Guardian Protocol - Secret & threat scanning | `npm i @weave_protocol/mund` |
| **[@weave_protocol/hord](./hord)** | Vault Protocol - Secure containment & sandboxing | `npm i @weave_protocol/hord` |
| **[@weave_protocol/domere](./domere)** | Judge Protocol - Verification & blockchain anchoring | `npm i @weave_protocol/domere` |
| **[@weave_protocol/api](./api)** | Universal REST API for all protocols | `npm i @weave_protocol/api` |

## 🚀 Quick Start

### Option 1: REST API (Recommended for any AI agent)

```bash
npm install @weave_protocol/api
npx weave-api
# Server running on http://localhost:3000
```

Any AI agent can call these endpoints:

```bash
# Scan for secrets/threats
curl -X POST http://localhost:3000/api/v1/mund/scan \
  -H "Content-Type: application/json" \
  -d '{"content": "AWS key: AKIAIOSFODNN7EXAMPLE"}'

# Create secure vault
curl -X POST http://localhost:3000/api/v1/hord/vaults \
  -d '{"name": "secrets-vault"}'

# Create verified thread
curl -X POST http://localhost:3000/api/v1/domere/threads \
  -d '{"origin_type": "agent", "origin_identity": "gpt-4", "intent": "Process user data"}'

# OpenAI/Gemini compatible function call
curl -X POST http://localhost:3000/api/v1/functions/call \
  -d '{"name": "weave_scan_content", "arguments": {"content": "scan this"}}'
```

### Option 2: Direct Package Usage

```typescript
import { MundScanner } from '@weave_protocol/mund';
import { HordVault } from '@weave_protocol/hord';
import { DomereJudge } from '@weave_protocol/domere';

// Scan for secrets
const scanner = new MundScanner();
const threats = await scanner.scan('API key: sk-1234567890abcdef');
// → Detects OpenAI API key, severity: critical

// Secure storage
const vault = new HordVault();
await vault.store('api-key', 'sk-1234...', { encryption: true });

// Verify intent
const judge = new DomereJudge();
const thread = await judge.createThread({
  origin_type: 'human',
  origin_identity: 'user@example.com',
  intent: 'Analyze sales data'
});
```

---

## 🔐 Mund - Guardian Protocol

Real-time threat detection for AI inputs/outputs.

**Detects:**
- 🔑 **Secrets**: API keys (OpenAI, AWS, GitHub, etc.), passwords, tokens
- 👤 **PII**: SSN, emails, phone numbers, credit cards
- 💉 **Injection**: Prompt injection, jailbreak attempts
- 📤 **Exfiltration**: Data theft patterns

```typescript
import { MundScanner } from '@weave_protocol/mund';

const scanner = new MundScanner();
const result = await scanner.scan(`
  My AWS key is AKIAIOSFODNN7EXAMPLE
  and my SSN is 123-45-6789
`);

console.log(result.issues);
// [
//   { type: 'secret', name: 'AWS Access Key', severity: 'critical' },
//   { type: 'pii', name: 'SSN', severity: 'high' }
// ]
```

---

## 🏛️ Hord - Vault Protocol

Secure containment and sandboxed execution.

**Features:**
- 🔒 Encrypted secret storage
- 📝 Automatic redaction
- 🏖️ Sandboxed code execution
- 🔐 Access control policies

```typescript
import { HordVault } from '@weave_protocol/hord';

const vault = new HordVault({ encryption_key: process.env.VAULT_KEY });

// Store secrets securely
await vault.store('openai-key', 'sk-...', { ttl: 3600 });

// Redact sensitive data
const safe = await vault.redact('My SSN is 123-45-6789');
// → "My SSN is [REDACTED]"

// Sandboxed execution
const result = await vault.sandbox.execute('return 2 + 2', 'javascript');
// → { success: true, result: 4 }
```

---

## ⚖️ Dōmere - Judge Protocol

Intent verification, compliance, and blockchain anchoring.

**Features:**
- 🎯 Intent tracking & drift detection
- ⛓️ Blockchain anchoring (Solana & Ethereum)
- 📋 SOC2/HIPAA compliance checkpoints
- 🔄 Execution replay & audit trails
- 🤝 Multi-agent handoff verification

### Thread Management

```typescript
import { DomereJudge } from '@weave_protocol/domere';

const judge = new DomereJudge();

// Create verified thread
const thread = await judge.createThread({
  origin_type: 'human',
  origin_identity: 'user@company.com',
  intent: 'Generate quarterly report',
  constraints: ['read-only', 'no-external-api']
});

// Check for intent drift
const drift = await judge.checkDrift(thread.id, 'Sending data to external API');
// → { drifted: true, reason: 'Violates no-external-api constraint' }
```

### 🔄 Execution Replay (NEW)

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

### 🤝 Multi-Agent Handoff Verification (NEW)

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

### 📋 Compliance Checkpoints - SOC2/HIPAA (NEW)

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

await ethereum.anchorThread({ ... });
```

---

## 🌐 REST API Endpoints

Start the server:
```bash
npm install @weave_protocol/api
npm start
```

### Mund (Scanning)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/mund/scan` | Scan content for threats |
| POST | `/api/v1/mund/scan/secrets` | Scan for secrets only |
| POST | `/api/v1/mund/scan/pii` | Scan for PII only |
| POST | `/api/v1/mund/scan/injection` | Check for injection |

### Hord (Vault)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/hord/vaults` | Create vault |
| GET | `/api/v1/hord/vaults` | List vaults |
| POST | `/api/v1/hord/vaults/:id/secrets` | Store secret |
| POST | `/api/v1/hord/redact` | Redact content |

### Dōmere (Verification)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/domere/threads` | Create thread |
| GET | `/api/v1/domere/threads/:id` | Get thread |
| POST | `/api/v1/domere/threads/:id/verify` | Verify thread |
| POST | `/api/v1/domere/drift/check` | Check intent drift |

### OpenAI/Gemini Compatible
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/functions` | List available functions |
| POST | `/api/v1/functions/call` | Call a function |

---

## ⛓️ Blockchain Deployments

| Chain | Network | Contract/Program | Explorer |
|-------|---------|------------------|----------|
| **Solana** | Devnet | `BeCYVJYfbUu3k2TPGmh9VoGWeJwzm2hg2NdtnvbdBNCj` | [View](https://solscan.io/account/BeCYVJYfbUu3k2TPGmh9VoGWeJwzm2hg2NdtnvbdBNCj?cluster=devnet) |
| **Ethereum** | Mainnet | `0xAA8b52adD3CEce6269d14C6335a79df451543820` | [View](https://etherscan.io/address/0xAA8b52adD3CEce6269d14C6335a79df451543820) |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        AI Agent / LLM                           │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Weave Protocol API                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │    Mund     │  │    Hord     │  │        Dōmere           │  │
│  │  Guardian   │  │    Vault    │  │         Judge           │  │
│  │             │  │             │  │  ┌───────────────────┐  │  │
│  │ • Secrets   │  │ • Storage   │  │  │ Execution Replay  │  │  │
│  │ • PII       │  │ • Redaction │  │  │ Handoff Verify    │  │  │
│  │ • Injection │  │ • Sandbox   │  │  │ Compliance        │  │  │
│  │ • Exfil     │  │ • Policies  │  │  │ Intent Tracking   │  │  │
│  └─────────────┘  └─────────────┘  │  │ Blockchain Anchor │  │  │
│                                     │  └───────────────────┘  │  │
│                                     └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │   Blockchain Layer    │
                    │  Solana  │  Ethereum  │
                    └───────────────────────┘
```

---

## 📄 License

Apache 2.0 - See [LICENSE](LICENSE) for details.

Use individually or together with the full Weave Protocol suite.

---

## 🤝 Contributing

Contributions welcome! Please read our contributing guidelines before submitting PRs.

---

Made with ❤️ for AI Safety
