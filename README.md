# 🛡️ Weave Protocol Security Suite

[![npm version](https://img.shields.io/npm/v/@weave_protocol/domere.svg)](https://www.npmjs.com/package/@weave_protocol/domere)
[![license](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![downloads](https://img.shields.io/npm/dm/@weave_protocol/domere.svg)](https://www.npmjs.com/package/@weave_protocol/domere)

**Enterprise-grade security and orchestration infrastructure for AI agents.**

Weave Protocol provides defense-in-depth for autonomous AI systems: secret scanning, secure containment, intent verification, execution replay, multi-agent coordination, and compliance tracking—all with blockchain anchoring for immutable audit trails.

## 📦 Packages

| Package | Description | Install |
|---------|-------------|---------|
| **[@weave_protocol/mund](./mund)** | Guardian Protocol - Secret & threat scanning | `npm i @weave_protocol/mund` |
| **[@weave_protocol/hord](./hord)** | Vault Protocol - Secure containment & sandboxing | `npm i @weave_protocol/hord` |
| **[@weave_protocol/domere](./domere)** | Judge Protocol - Verification, orchestration & compliance | `npm i @weave_protocol/domere` |
| **[@weave_protocol/witan](./witan)** | Council Protocol - Consensus, communication & governance | `npm i @weave_protocol/witan` |
| **[@weave_protocol/api](./api)** | Universal REST API for all protocols | `npm i @weave_protocol/api` |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           WEAVE PROTOCOL SUITE                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐  ┌─────────────┐  │
│  │     MUND      │  │     HORD      │  │    DŌMERE     │  │    WITAN    │  │
│  │   Guardian    │  │     Vault     │  │     Judge     │  │   Council   │  │
│  ├───────────────┤  ├───────────────┤  ├───────────────┤  ├─────────────┤  │
│  │ • Secrets     │  │ • Storage     │  │ • Intent      │  │ • Consensus │  │
│  │ • PII         │  │ • Redaction   │  │ • Replay      │  │ • Comms Bus │  │
│  │ • Injection   │  │ • Sandbox     │  │ • Handoff     │  │ • Policy    │  │
│  │ • Exfil       │  │ • Encrypt     │  │ • Compliance  │  │ • Recovery  │  │
│  │               │  │               │  │ • Scheduler   │  │ • Voting    │  │
│  │               │  │               │  │ • Registry    │  │ • Channels  │  │
│  └───────────────┘  └───────────────┘  └───────────────┘  └─────────────┘  │
│         │                  │                   │                 │          │
│         └──────────────────┴───────────────────┴─────────────────┘          │
│                                   │                                         │
│                    ┌──────────────▼──────────────┐                          │
│                    │     WITAN COUNCIL           │                          │
│                    │  (Orchestrator + N Agents)  │                          │
│                    └──────────────┬──────────────┘                          │
│            ┌────┬────┬────┬────┬──┴──┬────┬────┬────┐                       │
│            ▼    ▼    ▼    ▼    ▼     ▼    ▼    ▼    ▼                       │
│          [A1] [A2] [A3] [A4] [A5]  [A6] [A7] [A8] [...]                     │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                           BLOCKCHAIN LAYER                                  │
│                    ┌─────────────┬─────────────┐                            │
│                    │   Solana    │  Ethereum   │                            │
│                    │   Devnet    │   Mainnet   │                            │
│                    └─────────────┴─────────────┘                            │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Option 1: Witan Council (Full Stack)

```typescript
import { WitanCouncil } from '@weave_protocol/witan';

const council = new WitanCouncil({
  signing_key: 'your-secret-key',
  max_agents: 10
});

await council.start();

// Register agents with voting weights
await council.registerAgent({
  name: 'researcher',
  capabilities: ['search', 'analysis'],
  voting_weight: 2
});

// Submit tasks, propose decisions, send messages
await council.submitTask({ intent: 'Analyze market data', priority: 'high' });

const proposal = await council.propose({
  title: 'Increase compute budget',
  type: 'resource',
  proposer_id: 'researcher'
});

await council.vote(proposal.id, 'researcher', 'approve');
```

### Option 2: Dōmere Orchestration (Core)

```typescript
import { Orchestrator } from '@weave_protocol/domere';

// Create orchestrator for 10 agents
const orch = new Orchestrator({ max_agents: 10 });
await orch.start();

// Register agents with capabilities
for (let i = 0; i < 10; i++) {
  await orch.registerAgent({
    name: `agent-${i}`,
    capabilities: ['research', 'analysis', 'coding'][i % 3],
    max_concurrent_tasks: 3
  });
}

// Submit tasks with dependencies
const fetchTask = await orch.submitTask({
  intent: 'Fetch Q3 financial data',
  priority: 'high',
  required_capabilities: ['research']
});

const analyzeTask = await orch.submitTask({
  intent: 'Analyze Q3 trends',
  dependencies: [fetchTask.id],  // Waits for fetch to complete
  required_capabilities: ['analysis']
});

// Agents receive tasks via heartbeat
const { tasks_to_run } = await orch.heartbeat('agent-0', []);
```

### Option 3: REST API (Any AI Agent)

```bash
npm install @weave_protocol/api
npx weave-api
# Server running on http://localhost:3000
```

```bash
# Scan for secrets/threats
curl -X POST http://localhost:3000/api/v1/mund/scan \
  -H "Content-Type: application/json" \
  -d '{"content": "AWS key: AKIAIOSFODNN7EXAMPLE"}'

# Create verified thread
curl -X POST http://localhost:3000/api/v1/domere/threads \
  -d '{"origin_type": "agent", "origin_identity": "gpt-4", "intent": "Process data"}'
```

### Option 4: Direct Package Usage

```typescript
import { MundScanner } from '@weave_protocol/mund';
import { HordVault } from '@weave_protocol/hord';
import { ExecutionReplayManager, ComplianceManager } from '@weave_protocol/domere';

// Scan for secrets
const scanner = new MundScanner();
const threats = await scanner.scan('API key: sk-1234567890abcdef');

// Secure storage
const vault = new HordVault();
await vault.store('api-key', 'sk-1234...', { encryption: true });

// Track execution
const replay = new ExecutionReplayManager('encryption-key');
await replay.recordAction({ thread_id: 'thr_1', agent_id: 'agent-1', ... });
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
```

---

## ⚖️ Dōmere - Judge Protocol

Intent verification, orchestration, compliance, and blockchain anchoring.

### 🎯 Intent Tracking & Drift Detection

```typescript
import { ThreadManager } from '@weave_protocol/domere';

const manager = new ThreadManager();

const thread = await manager.createThread({
  origin_type: 'human',
  origin_identity: 'user@company.com',
  intent: 'Generate quarterly report',
  constraints: ['read-only', 'no-external-api']
});

// Check for drift
const drift = await manager.checkDrift(thread.id, 'Sending data to external API');
// → { drifted: true, reason: 'Violates no-external-api constraint' }
```

### 🔄 Execution Replay & Audit Trail

Complete forensic trail with cryptographic verification.

```typescript
import { ExecutionReplayManager } from '@weave_protocol/domere';

const replay = new ExecutionReplayManager('encryption-key');

// Record every action
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
  tokens_out: 1000
});

// Get tamper-proof trail
const trail = await replay.getExecutionTrail('thr_xxx');
console.log(trail.integrity_valid);  // true
console.log(trail.merkle_root);      // For blockchain anchoring
```

### 🤝 Multi-Agent Handoff Verification

Secure delegation between AI agents with permission inheritance.

```typescript
import { HandoffManager } from '@weave_protocol/domere';

const handoff = new HandoffManager('signing-key', {
  max_delegation_depth: 5,
  max_handoff_duration_ms: 3600000
});

// Delegate from orchestrator to researcher
const token = await handoff.createHandoff({
  thread_id: 'thr_xxx',
  from_agent: 'orchestrator',
  to_agent: 'researcher',
  delegated_intent: 'Find Q3 revenue data',
  constraints: ['read-only', 'internal-data-only'],
  permissions: [{ resource: 'database', actions: ['read'] }],
  max_actions: 10,
  expires_in_ms: 300000
});

// Researcher verifies before acting
const verification = await handoff.verifyHandoff(token.token, 'researcher');
```

### 📋 Compliance Checkpoints (SOC2/HIPAA)

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

// Generate compliance report
const report = await compliance.generateReport({
  framework: 'HIPAA',
  period_start: new Date('2026-01-01'),
  period_end: new Date('2026-03-31')
});
console.log('Score:', report.compliance_score);
```

### 📊 Task Scheduler (Multi-Agent)

Priority queue with dependencies, retries, and load balancing.

```typescript
import { TaskScheduler } from '@weave_protocol/domere';

const scheduler = new TaskScheduler();

const task = await scheduler.createTask({
  intent: 'Analyze Q3 data',
  priority: 'high',
  dependencies: ['fetch-data-task'],
  constraints: {
    required_capabilities: ['data-analysis'],
    max_duration_ms: 300000
  },
  retry_policy: { max_retries: 3, backoff: 'exponential' }
});

const assignment = await scheduler.assignTask(task.id);
```

### 🤖 Agent Registry (Health & Capabilities)

Agent lifecycle, heartbeat monitoring, and failover.

```typescript
import { AgentRegistry } from '@weave_protocol/domere';

const registry = new AgentRegistry();

const agent = await registry.register({
  agent_id: 'agent-7',
  capabilities: ['code-generation', 'testing'],
  max_concurrent_tasks: 3
});

registry.onAgentDown((agent, activeTasks) => {
  console.log(`Agent ${agent.id} down, reassigning tasks`);
});
```

### 🗃️ State Manager (Shared State with Locks)

Distributed state with locking, branching, and conflict resolution.

```typescript
import { StateManager } from '@weave_protocol/domere';

const state = new StateManager({ conflict_resolution: 'last-write-wins' });

// Lock before writing
const lock = await state.acquireLock({ key: 'db', holder: 'agent-3' });
if (lock.acquired) {
  await state.set('db', { updated: true });
  await state.releaseLock('db', 'agent-3');
}

// Git-style branching
await state.createBranch('experiment');
await state.set('config', newConfig, { branch: 'experiment' });
await state.merge('experiment', 'main');
```

### 🎛️ Unified Orchestrator

Single interface for multi-agent coordination.

```typescript
import { Orchestrator } from '@weave_protocol/domere';

const orch = new Orchestrator({ max_agents: 10 });
await orch.start();

for (let i = 0; i < 10; i++) {
  await orch.registerAgent({ name: `worker-${i}`, capabilities: ['general'] });
}

await orch.submitTask({ intent: 'Process batch', priority: 'high' });

const stats = orch.getStats();
console.log(`${stats.agents.ready}/${stats.agents.total} agents ready`);
```

---

## 🏛️ Witan - Council Protocol

Multi-agent consensus, communication, governance, and recovery.

### 🗳️ Consensus Engine

```typescript
import { ConsensusEngine } from '@weave_protocol/witan';

const consensus = new ConsensusEngine('signing-key', {
  default_quorum: 0.5,
  default_threshold: 0.6
});

const proposal = await consensus.createProposal({
  title: 'Deploy new model',
  proposal_type: 'action',
  proposer_id: 'orchestrator',
  eligible_voters: ['agent-1', 'agent-2', 'agent-3']
});

await consensus.vote(proposal.id, 'agent-1', 'approve');
await consensus.vote(proposal.id, 'agent-2', 'approve');

const result = await consensus.finalizeProposal(proposal.id);
console.log(result.decision); // 'approved'
```

### 📨 Communication Bus

```typescript
import { CommunicationBus } from '@weave_protocol/witan';

const bus = new CommunicationBus('signing-key');

// Direct message
await bus.send({
  from: 'agent-1',
  to: 'agent-2',
  type: 'data-handoff',
  payload: { dataset_id: 'ds_123' }
});

// Broadcast to all
await bus.broadcast({
  from: 'orchestrator',
  type: 'priority-change',
  payload: { all_tasks: 'high' }
});
```

### 📜 Policy Engine

```typescript
import { PolicyEngine } from '@weave_protocol/witan';

const policy = new PolicyEngine();

// Rate limit: 100 requests per minute
await policy.createRateLimit({
  name: 'api-limit',
  targets: [{ type: 'all' }],
  max_requests: 100,
  window_ms: 60000
});

// Enforce
const decision = await policy.enforce({
  agent_id: 'agent-1',
  action: 'api_call',
  timestamp: new Date()
});
```

### 🔄 Recovery Manager

```typescript
import { RecoveryManager } from '@weave_protocol/witan';

const recovery = new RecoveryManager('signing-key');

// Checkpoint
const checkpoint = await recovery.checkpoint({
  name: 'Pre-deployment',
  created_by: 'admin'
});

// Transaction with auto-rollback
const txn = await recovery.beginTransaction({
  initiator: 'agent-1',
  auto_checkpoint: true
});

// ... operations ...
await recovery.commitTransaction(txn.id);
// or: await recovery.rollbackTransaction(txn.id);
```

---

## ⛓️ Blockchain Deployments

| Chain | Network | Contract/Program | Explorer |
|-------|---------|------------------|----------|
| **Solana** | Mainnet | `6g7raTAHU2h331VKtfVtkS5pmuvR8vMYwjGsZF1CUj2o` | [View](https://solscan.io/account/6g7raTAHU2h331VKtfVtkS5pmuvR8vMYwjGsZF1CUj2o) |
| **Solana** | Devnet | `BeCYVJYfbUu3k2TPGmh9VoGWeJwzm2hg2NdtnvbdBNCj` | [View](https://solscan.io/account/BeCYVJYfbUu3k2TPGmh9VoGWeJwzm2hg2NdtnvbdBNCj?cluster=devnet) |
| **Ethereum** | Mainnet | `0xAA8b52adD3CEce6269d14C6335a79df451543820` | [View](https://etherscan.io/address/0xAA8b52adD3CEce6269d14C6335a79df451543820) |

---

## 📊 Feature Matrix

| Feature | Mund | Hord | Dōmere | Witan |
|---------|:----:|:----:|:------:|:-----:|
| Secret Detection | ✅ | | | |
| PII Detection | ✅ | | | |
| Injection Detection | ✅ | | | |
| Encrypted Storage | | ✅ | | |
| Redaction | | ✅ | | |
| Sandboxing | | ✅ | | |
| Intent Tracking | | | ✅ | |
| Drift Detection | | | ✅ | |
| Execution Replay | | | ✅ | |
| Multi-Agent Handoff | | | ✅ | |
| SOC2 Compliance | | | ✅ | |
| HIPAA Compliance | | | ✅ | |
| Task Scheduling | | | ✅ | |
| Agent Registry | | | ✅ | |
| Shared State/Locks | | | ✅ | |
| Blockchain Anchoring | | | ✅ | |
| Consensus/Voting | | | | ✅ |
| Agent Messaging | | | | ✅ |
| Policy Engine | | | | ✅ |
| Checkpoints/Recovery | | | | ✅ |

---

## 🗺️ Roadmap

### Current (v1.x)
- ✅ Mund - Secret & threat scanning
- ✅ Hord - Secure vault & sandbox
- ✅ Dōmere - Verification & orchestration
- ✅ Witan - Consensus, communication & governance
- ✅ REST API
- ✅ Ethereum mainnet deployment
- ✅ Solana mainnet deployment

### Next (v2.x)
- 🔲 MCP server integration
- 🔲 Advanced agent coordination patterns
- 🔲 Real-time monitoring dashboard
- 🔲 Additional compliance frameworks (PCI-DSS, ISO27001)

---

## 📄 License

Apache 2.0 - See [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

Contributions welcome! Here's how:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure your code passes existing tests and follows the project's coding style.

---

**Made with ❤️ for AI Safety**
