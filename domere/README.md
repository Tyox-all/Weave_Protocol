# ⚖️ Dōmere - Judge Protocol

[![npm version](https://img.shields.io/npm/v/@weave_protocol/domere.svg)](https://www.npmjs.com/package/@weave_protocol/domere)
[![license](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![downloads](https://img.shields.io/npm/dm/@weave_protocol/domere.svg)](https://www.npmjs.com/package/@weave_protocol/domere)

**Enterprise-grade verification, orchestration, compliance, and audit infrastructure for AI agents.**

Part of the [Weave Protocol Security Suite](https://github.com/Tyox-all/Weave_Protocol).

## ✨ Features

| Category | Features |
|----------|----------|
| **Verification** | Intent tracking, drift detection, execution replay, multi-agent handoff |
| **Orchestration** | Task scheduler, agent registry, shared state with locks |
| **Compliance** | SOC2 controls, HIPAA checkpoints, automated reporting |
| **Blockchain** | Solana & Ethereum anchoring for immutable audit trails |

## 📦 Installation

```bash
npm install @weave_protocol/domere
```

## 🚀 Quick Start: Agent Orchestration - Default agent limit IS 10 (configure as needed).

```typescript
import { Orchestrator } from '@weave_protocol/domere';

const orch = new Orchestrator({ max_agents: 10 });
await orch.start();

// Register 10 agents
for (let i = 0; i < 10; i++) {
  await orch.registerAgent({
    name: `agent-${i}`,
    capabilities: ['research', 'analysis', 'coding'][i % 3],
    max_concurrent_tasks: 3
  });
}

// Submit tasks with dependencies
const task1 = await orch.submitTask({
  intent: 'Fetch Q3 data',
  priority: 'high'
});

const task2 = await orch.submitTask({
  intent: 'Analyze Q3 trends',
  dependencies: [task1.id]  // Waits for task1
});

// Get stats
const stats = orch.getStats();
console.log(`${stats.agents.ready} agents ready, ${stats.tasks.queued} tasks queued`);
```

---

## 📊 Task Scheduler

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
    max_duration_ms: 300000,
    exclusive_resources: ['gpu-1']
  },
  retry_policy: {
    max_retries: 3,
    backoff: 'exponential'
  }
});

// Auto-assign to best agent
const assignment = await scheduler.assignTask(task.id);

// Track progress
scheduler.onTaskProgress(task.id, (p) => console.log(`${p.percent}%`));

// Handle completion
scheduler.onTaskComplete(task.id, (result) => {
  console.log(`Completed in ${result.duration_ms}ms`);
});
```

---

## 🤖 Agent Registry

Agent lifecycle, heartbeat monitoring, and failover.

```typescript
import { AgentRegistry } from '@weave_protocol/domere';

const registry = new AgentRegistry({
  heartbeat_interval_ms: 5000,
  heartbeat_timeout_ms: 15000
});

// Register agent
const agent = await registry.register({
  agent_id: 'agent-7',
  capabilities: ['code-generation', 'testing'],
  max_concurrent_tasks: 3
});

await registry.setReady('agent-7');

// Process heartbeats
await registry.heartbeat({
  agent_id: 'agent-7',
  current_tasks: ['task_1', 'task_2']
});

// Handle failures
registry.onAgentDown((agent, tasks) => {
  console.log(`${agent.id} down with ${tasks.length} tasks`);
  // Reassign tasks...
});

// Find best agent
const best = registry.getBestAgent({
  capabilities: ['code-generation'],
  prefer_lowest_load: true
});
```

---

## 🗃️ State Manager

Shared state with locking, branching, and conflict resolution.

```typescript
import { StateManager } from '@weave_protocol/domere';

const state = new StateManager({
  conflict_resolution: 'last-write-wins'
});

// Lock before writing
const lock = await state.acquireLock({
  key: 'customer-db',
  holder: 'agent-3',
  duration_ms: 30000,
  type: 'exclusive'
});

if (lock.acquired) {
  await state.set('customer-db', { updated: true });
  await state.releaseLock('customer-db', 'agent-3');
}

// Git-style branching
await state.createBranch('experiment', { parent: 'main' });
await state.set('config', newConfig, { branch: 'experiment' });

// Merge with conflict detection
const result = await state.merge('experiment', 'main');
if (result.conflicts.length > 0) {
  // Resolve conflicts
}

// Snapshots for rollback
const snap = await state.createSnapshot();
// ... later ...
await state.restoreSnapshot(snap.id);
```

---

## 🔄 Execution Replay

Tamper-proof audit trail with cryptographic verification.

```typescript
import { ExecutionReplayManager } from '@weave_protocol/domere';

const replay = new ExecutionReplayManager('encryption-key');

// Record actions
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

// Get trail
const trail = await replay.getExecutionTrail('thr_xxx');
console.log(trail.integrity_valid);  // true
console.log(trail.merkle_root);      // For blockchain

// Generate report
const report = await replay.generateAuditReport({
  start_time: new Date('2026-01-01'),
  end_time: new Date('2026-01-31')
});
```

---

## 🤝 Multi-Agent Handoff

Secure delegation with permission inheritance.

```typescript
import { HandoffManager } from '@weave_protocol/domere';

const handoff = new HandoffManager('signing-key', {
  max_delegation_depth: 5
});

// Create handoff token
const token = await handoff.createHandoff({
  thread_id: 'thr_xxx',
  from_agent: 'orchestrator',
  to_agent: 'researcher',
  delegated_intent: 'Find Q3 data',
  constraints: ['read-only'],
  permissions: [{ resource: 'database', actions: ['read'] }],
  max_actions: 10,
  expires_in_ms: 300000
});

// Verify before acting
const v = await handoff.verifyHandoff(token.token, 'researcher');
if (v.valid) {
  console.log(`${v.remaining_actions} actions left`);
}

// Track chain
const chain = await handoff.getDelegationChain('thr_xxx');
console.log(`Depth: ${chain.depth}, Valid: ${chain.integrity_valid}`);
```

---

## 📋 Compliance (SOC2/HIPAA)

Automated compliance tracking and reporting.

```typescript
import { ComplianceManager } from '@weave_protocol/domere';

const compliance = new ComplianceManager('signing-key');

// HIPAA: Log PHI access
await compliance.logPHIAccess({
  thread_id: 'thr_xxx',
  agent_id: 'medical-ai',
  patient_id: 'patient_123',
  access_reason: 'Treatment',
  data_accessed: ['diagnosis'],
  legal_basis: 'treatment'
});

// SOC2: Log access control
await compliance.logAccessControl({
  thread_id: 'thr_xxx',
  agent_id: 'admin-bot',
  resource: 'reports',
  action: 'grant',
  success: true
});

// Generic checkpoint
await compliance.checkpoint({
  thread_id: 'thr_xxx',
  framework: 'SOC2',
  control: 'CC6.1',
  event_type: 'access',
  event_description: 'Data accessed',
  data_classification: 'confidential',
  agent_id: 'agent-1',
  sign: true
});

// Generate report
const report = await compliance.generateReport({
  framework: 'HIPAA',
  period_start: new Date('2026-01-01'),
  period_end: new Date('2026-03-31')
});
console.log(`Score: ${report.compliance_score}`);
```

---

## ⛓️ Blockchain Anchoring

Immutable proof on Solana and Ethereum.

```typescript
import { EthereumAnchor } from '@weave_protocol/domere';

const anchor = new EthereumAnchor({
  contract_address: '0xAA8b52adD3CEce6269d14C6335a79df451543820'
});

await anchor.anchorThread({
  thread_id: 'thr_xxx',
  merkle_root: trail.merkle_root,
  intent_hash: 'abc123...',
  compliant: true
});
```

| Chain | Network | Address |
|-------|---------|---------|
| Solana | Devnet | `BeCYVJYfbUu3k2TPGmh9VoGWeJwzm2hg2NdtnvbdBNCj` |
| Ethereum | Mainnet | `0xAA8b52adD3CEce6269d14C6335a79df451543820` |

---

## 📚 API Reference

### Orchestrator
| Method | Description |
|--------|-------------|
| `start()` | Start orchestrator |
| `registerAgent(params)` | Register new agent |
| `submitTask(params)` | Submit task to queue |
| `heartbeat(agentId, tasks)` | Process agent heartbeat |
| `taskCompleted(agentId, taskId, result)` | Report completion |
| `getStats()` | Get orchestrator stats |

### TaskScheduler
| Method | Description |
|--------|-------------|
| `createTask(params)` | Create task with dependencies |
| `assignTask(taskId, agentId?)` | Assign to agent |
| `completeTask(taskId, agentId, result)` | Mark complete |
| `failTask(taskId, agentId, error)` | Mark failed (auto-retry) |
| `reassignFromAgent(agentId)` | Reassign failed agent's tasks |

### AgentRegistry
| Method | Description |
|--------|-------------|
| `register(params)` | Register agent |
| `heartbeat(payload)` | Process heartbeat |
| `findAgents(query)` | Find matching agents |
| `drain(agentId)` | Stop accepting tasks |
| `deregister(agentId)` | Remove agent |

### StateManager
| Method | Description |
|--------|-------------|
| `get(key)` / `set(key, value)` | Basic operations |
| `acquireLock(request)` | Acquire lock |
| `releaseLock(key, holder)` | Release lock |
| `createBranch(name)` | Create branch |
| `merge(source, target)` | Merge branches |
| `createSnapshot()` | Create snapshot |

---

## 🔗 Related Packages

| Package | Description |
|---------|-------------|
| [@weave_protocol/mund](https://www.npmjs.com/package/@weave_protocol/mund) | Secret & threat scanning |
| [@weave_protocol/hord](https://www.npmjs.com/package/@weave_protocol/hord) | Secure vault & sandbox |
| [@weave_protocol/api](https://www.npmjs.com/package/@weave_protocol/api) | Universal REST API |

## 📄 License

Apache 2.0

---

**Made with ❤️ for AI Safety**
