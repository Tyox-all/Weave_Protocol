---
name: witan
description: "Use this skill whenever multi-agent consensus, governance, or policy enforcement is needed. Triggers: requiring approval from multiple agents, voting on actions, enforcing policies, managing agent permissions, coordinating agent communication, or any request involving 'consensus', 'vote', 'approve', 'policy', 'governance', 'quorum', 'multi-agent decision', or 'escalate'. Use Witan for high-risk operations requiring collective agreement."
license: Apache 2.0
---

# 👥 Witan - Consensus & Governance Guide

## Overview

Witan provides multi-agent consensus and governance. Use it when decisions require approval from multiple agents, when enforcing policies, or when coordinating communication between agents. Named after the Anglo-Saxon council of advisors.

## Quick Start

```typescript
import { ConsensusEngine, PolicyEngine } from '@weave_protocol/witan';

const consensus = new ConsensusEngine({
  protocol: 'weighted_majority',
  threshold: 0.66,
  timeout: 30000
});

// Propose action requiring consensus
const result = await consensus.propose({
  action: 'deploy_to_production',
  requiredApprovals: ['security-agent', 'qa-agent', 'ops-agent']
});
```

## MCP Tools Available

When running as an MCP server, these tools are available:

| Tool | Use When |
|------|----------|
| `witan_propose` | Submitting an action for consensus |
| `witan_vote` | Casting a vote on a proposal |
| `witan_check_status` | Checking proposal status |
| `witan_enforce_policy` | Checking if action is allowed by policy |
| `witan_create_policy` | Creating a new governance policy |
| `witan_broadcast` | Sending message to all agents |
| `witan_send` | Sending message to specific agent |
| `witan_escalate` | Escalating decision to higher authority |

---

## Common Tasks

### Propose Action for Consensus

```typescript
// MCP tool call
witan_propose({
  action: "deploy_to_production",
  description: "Deploy v2.0.0 to production environment",
  required_approvals: ["security-agent", "qa-agent", "ops-agent"],
  protocol: "unanimous",
  timeout: 60000
})

// Response
{
  proposal_id: "prop_abc123",
  action: "deploy_to_production",
  status: "pending",
  votes: {
    required: 3,
    received: 0,
    approved: 0,
    rejected: 0
  },
  expires_at: "2024-01-15T10:31:00Z"
}
```

### Cast a Vote

```typescript
witan_vote({
  proposal_id: "prop_abc123",
  agent_id: "security-agent",
  vote: "approve",
  reason: "Security review passed, no vulnerabilities found"
})

// Response
{
  proposal_id: "prop_abc123",
  vote_recorded: true,
  current_status: "pending",
  votes: {
    required: 3,
    received: 1,
    approved: 1,
    rejected: 0
  }
}
```

### Check Proposal Status

```typescript
witan_check_status({ proposal_id: "prop_abc123" })

// Response
{
  proposal_id: "prop_abc123",
  status: "approved",  // pending | approved | rejected | expired
  votes: {
    required: 3,
    received: 3,
    approved: 3,
    rejected: 0
  },
  result: {
    consensus_reached: true,
    decision: "approved",
    completed_at: "2024-01-15T10:30:45Z"
  }
}
```

### Enforce Policy

```typescript
witan_enforce_policy({
  action: "access_financial_data",
  actor: "junior-agent",
  context: {
    data_classification: "confidential",
    time: "2024-01-15T22:00:00Z"
  }
})

// Response
{
  allowed: false,
  policy_id: "pol_fin_001",
  policy_name: "Financial Data Access",
  reason: "Junior agents cannot access confidential data outside business hours",
  recommendation: "Escalate to senior-agent for approval"
}
```

### Create Policy

```typescript
witan_create_policy({
  name: "Production Deployment",
  description: "Rules for production deployments",
  rules: [
    {
      condition: "action == 'deploy_to_production'",
      require: "consensus",
      approvers: ["security-agent", "qa-agent"],
      protocol: "unanimous"
    },
    {
      condition: "time.hour < 9 || time.hour > 17",
      require: "escalation",
      escalate_to: "on-call-agent"
    }
  ]
})

// Response
{
  policy_id: "pol_deploy_001",
  name: "Production Deployment",
  status: "active",
  created_at: "2024-01-15T10:30:00Z"
}
```

### Broadcast Message

```typescript
witan_broadcast({
  message: "System maintenance scheduled for 2024-01-20 02:00 UTC",
  priority: "high",
  require_ack: true
})

// Response
{
  broadcast_id: "bcast_xyz789",
  recipients: 5,
  acknowledged: 0,
  status: "sent"
}
```

### Escalate Decision

```typescript
witan_escalate({
  action: "delete_customer_data",
  reason: "Requires human approval per data retention policy",
  escalate_to: "human-supervisor",
  context: {
    customer_id: "cust_123",
    data_type: "personal_information"
  }
})

// Response
{
  escalation_id: "esc_def456",
  status: "pending_human_review",
  escalated_to: "human-supervisor",
  notification_sent: true
}
```

---

## Consensus Protocols

| Protocol | Use Case | Threshold |
|----------|----------|-----------|
| `unanimous` | Critical decisions (deployments, deletions) | 100% |
| `majority` | Standard decisions | >50% |
| `weighted_majority` | Decisions with expert weighting | Configurable |
| `quorum` | Decisions requiring minimum participation | N of M |

### Weighted Voting Example

```typescript
const consensus = new ConsensusEngine({
  protocol: 'weighted_majority',
  weights: {
    'security-agent': 3,
    'qa-agent': 2,
    'ops-agent': 1
  },
  threshold: 0.66
});
```

---

## Policy Rules

| Rule Type | Description |
|-----------|-------------|
| `require: "consensus"` | Action requires multi-agent approval |
| `require: "escalation"` | Action must be escalated |
| `require: "permission"` | Actor must have specific permission |
| `deny` | Action is explicitly forbidden |
| `allow` | Action is explicitly allowed |

---

## Communication Patterns

| Pattern | Tool | Use Case |
|---------|------|----------|
| Broadcast | `witan_broadcast` | Announcements to all agents |
| Point-to-point | `witan_send` | Direct agent communication |
| Request-response | `witan_propose` + `witan_vote` | Consensus gathering |
| Escalation | `witan_escalate` | Human-in-the-loop |

---

## Failure Recovery

Witan handles agent failures automatically:

```typescript
const consensus = new ConsensusEngine({
  protocol: 'majority',
  timeout: 30000,
  fallback: {
    on_timeout: 'escalate',
    on_agent_failure: 'exclude_and_recalculate',
    escalate_to: 'supervisor-agent'
  }
});
```

---

## Best Practices

1. **Use unanimous consensus** for irreversible actions
2. **Define clear policies** before deployment
3. **Set appropriate timeouts** to avoid blocking
4. **Implement escalation paths** for edge cases
5. **Log all consensus decisions** with Domere for audit

---

## Quick Reference

| Task | Tool |
|------|------|
| Request multi-agent approval | `witan_propose` |
| Vote on proposal | `witan_vote` |
| Check if action allowed | `witan_enforce_policy` |
| Define governance rules | `witan_create_policy` |
| Alert all agents | `witan_broadcast` |
| Request human review | `witan_escalate` |

---

## Links

- **npm:** https://www.npmjs.com/package/@weave_protocol/witan
- **GitHub:** https://github.com/Tyox-all/Weave_Protocol
