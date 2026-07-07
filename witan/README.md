# 🏛️ Witan - Council Protocol

[![npm version](https://img.shields.io/npm/v/@weave_protocol/witan.svg)](https://www.npmjs.com/package/@weave_protocol/witan)
[![license](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**Multi-agent consensus, communication, governance, and recovery for AI orchestration systems.**

Part of the [Weave Protocol Security Suite](https://github.com/Tyox-all/Weave_Protocol).

*Witan* = Old English for "council of advisors" (the Witenagemot advised Anglo-Saxon kings)

## ✨ Features

| Module | Capabilities |
|--------|--------------|
| **Consensus Engine** | Proposals, voting, quorum, weighted votes, veto |
| **Communication Bus** | Direct messaging, pub/sub channels, broadcast |
| **Policy Engine** | Rate limits, quotas, governance rules |
| **Recovery Manager** | Checkpoints, transactions, rollback, disaster recovery |

Built on [Dōmere](https://www.npmjs.com/package/@weave_protocol/domere) orchestration primitives (TaskScheduler, AgentRegistry, StateManager).

## 📦 Installation

```bash
npm install @weave_protocol/witan
```

## 🚀 Quick Start

```typescript
import { WitanCouncil } from '@weave_protocol/witan';

// Create council
const council = new WitanCouncil({
  signing_key: 'your-secret-key',
  max_agents: 10,
  default_quorum: 0.6,
  enable_auto_recovery: true
});

await council.start();

// Register agents
for (let i = 0; i < 10; i++) {
  await council.registerAgent({
    name: `agent-${i}`,
    capabilities: ['research', 'analysis'],
    voting_weight: 1
  });
}

// Submit tasks
await council.submitTask({
  intent: 'Analyze market data',
  priority: 'high'
});

// Propose decisions for vote
const proposal = await council.propose({
  title: 'Increase compute budget',
  description: 'Proposal to increase daily compute quota by 50%',
  type: 'resource',
  proposer_id: 'agent-0',
  payload: { new_quota: 150 }
});

// Agents vote
await council.vote(proposal.id, 'agent-1', 'approve', 'Needed for scaling');
await council.vote(proposal.id, 'agent-2', 'approve');
await council.vote(proposal.id, 'agent-3', 'reject', 'Cost concerns');
```

---

## 🗳️ Consensus Engine

Multi-agent voting with quorum, thresholds, and weighted votes.

```typescript
import { ConsensusEngine } from '@weave_protocol/witan';

const consensus = new ConsensusEngine('signing-key', {
  default_quorum: 0.5,      // 50% must vote
  default_threshold: 0.6,   // 60% approval needed
  default_voting_duration_ms: 300000  // 5 minutes
});

// Create proposal
const proposal = await consensus.createProposal({
  title: 'Deploy new model',
  description: 'Replace GPT-4 with Claude for all tasks',
  proposal_type: 'action',
  proposer_id: 'orchestrator',
  eligible_voters: ['agent-1', 'agent-2', 'agent-3', 'agent-4', 'agent-5'],
  voting_config: {
    quorum: 0.6,
    threshold: 0.7,
    weighted_voting: true,
    weights: new Map([
      ['agent-1', 2],  // Lead agent gets double weight
      ['agent-2', 1],
      ['agent-3', 1],
      ['agent-4', 1],
      ['agent-5', 1]
    ]),
    veto_enabled: true,
    veto_holders: ['orchestrator']
  }
});

// Cast votes
await consensus.vote(proposal.id, 'agent-1', 'approve', 'Better reasoning');
await consensus.vote(proposal.id, 'agent-2', 'approve');
await consensus.vote(proposal.id, 'agent-3', 'reject', 'Cost increase');
await consensus.vote(proposal.id, 'agent-4', 'abstain');

// Check result
const result = await consensus.finalizeProposal(proposal.id);
console.log(result.decision);        // 'approved' | 'rejected' | 'no_quorum'
console.log(result.participation_rate);
console.log(result.approve_weight);

// Subscribe to events
consensus.onEvent((event) => {
  if (event.type === 'passed') {
    console.log(`Proposal ${event.proposal_id} passed!`);
  }
});
```

---

## 📨 Communication Bus

Agent-to-agent messaging with channels and pub/sub.

```typescript
import { CommunicationBus } from '@weave_protocol/witan';

const bus = new CommunicationBus('signing-key', {
  default_ttl_ms: 300000,
  max_pending_messages: 1000
});

// Register agents
await bus.registerAgent('agent-1');
await bus.registerAgent('agent-2');

// Direct message
await bus.send({
  from: 'agent-1',
  to: 'agent-2',
  type: 'data-handoff',
  payload: { dataset_id: 'ds_123', format: 'json' },
  priority: 'high',
  require_ack: true
});

// Create topic channel
const channel = await bus.createChannel({
  name: 'research-updates',
  type: 'topic',
  owner: 'orchestrator',
  initial_members: ['agent-1', 'agent-2', 'agent-3']
});

// Publish to channel
await bus.publish({
  from: 'agent-1',
  channel: 'research-updates',
  type: 'finding',
  payload: { insight: 'Market trending upward' }
});

// Broadcast to all
await bus.broadcast({
  from: 'orchestrator',
  type: 'priority-change',
  payload: { all_tasks: 'high' },
  priority: 'critical'
});

// Receive messages (in agent loop)
const messages = await bus.receive('agent-2', { limit: 10 });
for (const msg of messages) {
  console.log(`From ${msg.from}: ${msg.type}`);
  await bus.acknowledge(msg.id, 'agent-2');
}

// Subscribe with handler
const unsubscribe = bus.subscribe('agent-3', async (message) => {
  console.log('Received:', message.type);
}, { types: ['finding', 'alert'] });
```

---

## 📜 Policy Engine

Governance rules, rate limits, quotas, and constraints.

```typescript
import { PolicyEngine } from '@weave_protocol/witan';

const policy = new PolicyEngine();

// Rate limit: 100 requests per minute per agent
await policy.createRateLimit({
  name: 'api-rate-limit',
  targets: [{ type: 'all' }],
  max_requests: 100,
  window_ms: 60000,
  action: 'throttle'
});

// Quota: Max 1000 tokens per agent per day
await policy.createQuota({
  name: 'daily-token-quota',
  targets: [{ type: 'agent', ids: ['agent-1', 'agent-2'] }],
  resource: 'tokens',
  max_value: 1000
});

// Schedule: Only allow actions during business hours
await policy.createSchedulePolicy({
  name: 'business-hours-only',
  targets: [{ type: 'all' }],
  allowed_hours: { start: 9, end: 17 },
  allowed_days: [1, 2, 3, 4, 5],  // Mon-Fri
  action: 'deny'
});

// Concurrency limit
await policy.createConcurrencyLimit({
  name: 'max-parallel-tasks',
  targets: [{ type: 'agent', pattern: 'agent-.*' }],
  max_concurrent: 5
});

// Enforce policy
const decision = await policy.enforce({
  agent_id: 'agent-1',
  action: 'api_call',
  resource: 'openai',
  timestamp: new Date()
});

if (!decision.allowed) {
  console.log(`Denied: ${decision.message}`);
  if (decision.retry_after_ms) {
    console.log(`Retry in ${decision.retry_after_ms}ms`);
  }
}

// Track violations
policy.onViolation((violation) => {
  console.log(`Policy violation: ${violation.policy_id} by ${violation.agent_id}`);
});
```

---

## 🔄 Recovery Manager

Checkpoints, transactions, and disaster recovery.

```typescript
import { RecoveryManager } from '@weave_protocol/witan';

const recovery = new RecoveryManager('signing-key', {
  max_checkpoints: 100,
  auto_checkpoint_interval_ms: 300000,  // Every 5 min
  enable_auto_recovery: true
});

// Create checkpoint
const checkpoint = await recovery.checkpoint({
  name: 'Pre-deployment',
  created_by: 'orchestrator',
  tags: ['deployment', 'critical']
});

// Begin transaction
const txn = await recovery.beginTransaction({
  initiator: 'agent-1',
  description: 'Update configuration',
  auto_checkpoint: true
});

// Record operations
await recovery.recordOperation(txn.id, {
  type: 'state_change',
  target_type: 'state',
  target_id: 'config',
  action: 'update',
  before: { version: 1 },
  after: { version: 2 },
  success: true,
  reversible: true,
  rollback_action: 'restore'
});

// Commit or rollback
try {
  // ... do work ...
  await recovery.commitTransaction(txn.id);
} catch (error) {
  await recovery.rollbackTransaction(txn.id);
}

// Restore from checkpoint
await recovery.restore(checkpoint.id, 'admin');

// Create recovery plan
await recovery.createRecoveryPlan({
  name: 'Agent failure recovery',
  trigger: {
    type: 'agent_failure',
    failure_count: 3,
    failure_window_ms: 60000
  },
  actions: [
    { type: 'restore_checkpoint', checkpoint_age_ms: 300000, order: 1, continue_on_failure: false },
    { type: 'notify', notify_targets: ['admin'], order: 2, continue_on_failure: true }
  ],
  auto_execute: true
});

// Report failure (may trigger recovery)
const result = await recovery.reportFailure({
  type: 'agent',
  id: 'agent-5',
  error: 'Connection timeout'
});
if (result.recovered) {
  console.log(`Auto-recovered using plan ${result.plan_id}`);
}
```

---

## 🎛️ Witan Council (Unified Interface)

Single entry point combining all components.

```typescript
import { WitanCouncil } from '@weave_protocol/witan';

const council = new WitanCouncil({
  signing_key: process.env.WITAN_KEY!,
  max_agents: 10,
  default_quorum: 0.5,
  default_threshold: 0.6,
  enable_auto_recovery: true,
  auto_checkpoint_interval_ms: 300000
});

await council.start();

// Register agents
const agentId = await council.registerAgent({
  name: 'researcher',
  capabilities: ['search', 'summarize'],
  voting_weight: 2
});

// Submit tasks (uses Dōmere scheduler)
await council.submitTask({
  intent: 'Research competitor analysis',
  priority: 'high',
  required_capabilities: ['search']
});

// Create proposals
const proposal = await council.propose({
  title: 'Add new data source',
  description: 'Integrate Bloomberg API',
  type: 'resource',
  proposer_id: agentId
});

// Send messages
await council.sendMessage({
  from: agentId,
  to: 'agent-2',
  type: 'collaboration-request',
  payload: { task: 'joint-analysis' }
});

// Set policies
await council.setRateLimit({
  name: 'inference-limit',
  max_requests: 60,
  window_ms: 60000
});

// Checkpoint
await council.checkpoint('Before risky operation', agentId);

// Transactions
const txn = await council.beginTransaction(agentId, 'Config update');
// ... operations ...
await council.commitTransaction(txn.id);

// Agent heartbeat loop
setInterval(async () => {
  const { ok, tasks_to_run, messages } = await council.heartbeat(agentId, []);
  
  // Process tasks
  for (const task of tasks_to_run || []) {
    await council.orchestrator.taskStarted(agentId, task.id);
    // ... do work ...
    await council.orchestrator.taskCompleted(agentId, task.id, result);
  }
  
  // Process messages
  for (const msg of messages || []) {
    console.log(`Message from ${msg.from}: ${msg.type}`);
  }
}, 5000);

// Get stats
const stats = council.getStats();
console.log(`${stats.orchestration.agents_ready} agents ready`);
console.log(`${stats.consensus.proposals_open} proposals open`);

// Subscribe to events
council.onEvent((event) => {
  console.log(`[${event.source}] ${event.event.type}`);
});

await council.stop();
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           WITAN COUNCIL                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐  ┌─────────────┐  │
│  │   Consensus   │  │     Comms     │  │    Policy     │  │  Recovery   │  │
│  │    Engine     │  │      Bus      │  │    Engine     │  │   Manager   │  │
│  ├───────────────┤  ├───────────────┤  ├───────────────┤  ├─────────────┤  │
│  │ • Proposals   │  │ • Direct      │  │ • Rate Limits │  │ • Checkpts  │  │
│  │ • Voting      │  │ • Channels    │  │ • Quotas      │  │ • Txns      │  │
│  │ • Quorum      │  │ • Broadcast   │  │ • Schedules   │  │ • Rollback  │  │
│  │ • Veto        │  │ • Pub/Sub     │  │ • Constraints │  │ • Plans     │  │
│  └───────────────┘  └───────────────┘  └───────────────┘  └─────────────┘  │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                         DŌMERE PRIMITIVES                                   │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐  ┌─────────────┐  │
│  │    Task       │  │    Agent      │  │    State      │  │   Exec      │  │
│  │  Scheduler    │  │   Registry    │  │   Manager     │  │  Replay     │  │
│  └───────────────┘  └───────────────┘  └───────────────┘  └─────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔗 Related Packages

| Package | Description |
|---------|-------------|
| [@weave_protocol/domere](https://www.npmjs.com/package/@weave_protocol/domere) | Judge Protocol - Orchestration & verification |
| [@weave_protocol/mund](https://www.npmjs.com/package/@weave_protocol/mund) | Guardian Protocol - Threat scanning |
| [@weave_protocol/hord](https://www.npmjs.com/package/@weave_protocol/hord) | Vault Protocol - Secure storage |

## 📄 License

Apache 2.0

---

**Made with ❤️ for AI Safety**

## 💰 Autonomous Spending Caps *(v1.1.0)*

Every enterprise agent question today is "what's my ceiling on this thing?" — measured in dollars, not just tool calls. Witan's spending caps are the answer.

Per-window budgets (run / hour / day / week / month) that gate LLM calls and tool calls. Caps can **block**, **require consensus/approval**, or **notify**. Multi-provider LLM pricing built in — Anthropic, OpenAI, Google, and local (free). Backed by an in-memory store in v1.1 with a pluggable interface for the v1.2 Redis/SQLite backends.

### Quick start (programmatic)

```typescript
import { SpendingTracker } from '@weave_protocol/witan/spending';

const tracker = new SpendingTracker({
  caps: [
    { window: 'day', budget: { usd: 5.00 }, onExceeded: 'require_approval' },
    { window: 'run', budget: { tool_calls: 100 }, onExceeded: 'block' },
    {
      window: 'day',
      budget: { tools: { send_payment: { max_amount_usd: 500 } } },
      onExceeded: 'require_approval',
    },
  ],
});

// Before every action
const check = await tracker.checkAction({
  kind: 'tool',
  tool: 'send_payment',
  args: { amount: 1000 },
  amountUSD: 1000,
});

if (check.blocked) throw new Error(check.reason);
if (check.requiresApproval) {
  const approved = await check.approve!();
  if (!approved) throw new Error('denied');
}

// After the action completes
await tracker.recordTool({ tool: 'send_payment', args: { amount: 1000 }, amountUSD: 1000 });
```

### WARD.md integration

Extend your `WARD.md` with a `spending_limits:` section. `@weave_protocol/witan/spending` reads it via `loadSpendingCapsFromWardFile()`.

```yaml
spending_limits:
  - window: day
    budget:
      usd: 5.00
    on_exceeded: require_approval
    label: daily budget

  - window: run
    budget:
      tool_calls: 100
    on_exceeded: block

  - window: day
    budget:
      tools:
        send_payment:
          max_amount_usd: 500
    on_exceeded: require_approval
```

Backward compatible: the legacy `behavioral_limits.maxCostUSD` is still honored as a run-window USD cap with `onExceeded: block`.

### CLI

```bash
weave-witan-spending caps        # print caps parsed from WARD.md
weave-witan-spending simulate    # dry-run: what would trigger?
weave-witan-spending simulate --scenario=payment-1000
```

### The three cap actions

| Action | Behavior |
|---|---|
| `block` | Deny the action outright. `check.blocked = true` |
| `require_approval` | Dispatch to `approvalHandler`; on TTY, prompt interactively; block on denial |
| `notify` | Allow the action; fire `onNotify` for observability/logging |

### Approval handling

Three modes, in order of precedence:

1. **Programmatic**: pass `approvalHandler: async (event) => boolean` — plug in Slack, PagerDuty, custom UI, whatever
2. **Interactive**: if no handler and process is a TTY, an in-terminal yellow-box prompt asks `Approve? [y/N]`
3. **Safe default**: no handler + non-TTY → deny (never silent approval)

### Multi-provider LLM pricing

Built-in pricing for the major providers (per million tokens):

| Provider | Models |
|---|---|
| Anthropic | claude-3-5-haiku, claude-3-5-sonnet, claude-3-7-sonnet, claude-opus-4-x, claude-sonnet-4-x, claude-haiku-4-x |
| OpenAI | gpt-4o, gpt-4o-mini, gpt-4-turbo, gpt-4, o1, o1-mini, o3, o3-mini |
| Google | gemini-1.5-flash / 8b / pro, gemini-2.0-flash, gemini-2.5-flash / pro |
| Local (Ollama, LM Studio, etc.) | free ($0) |

Register custom pricing:

```typescript
import { registerPricing } from '@weave_protocol/witan/spending';
registerPricing('mycompany', 'internal-llm-v2', { input: 0.10, output: 0.30 });
```

### v1.2 roadmap

- Persistent stores (Redis, SQLite) — for multi-process / cross-restart tracking
- Real human approval workflows (Slack escalation, email approval links)
- Adapter integrations for all 5 harness surfaces (currently: langchain only)
- Dashboard integration in `@weave_protocol/api`
- Real-time cap violation stream via WebSocket
