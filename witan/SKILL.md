---
name: consensus-governance
description: Coordinate multi-agent consensus, enforce policies, and manage governance. Use when requiring approval from multiple agents, voting on actions, enforcing policies, or escalating decisions to human review.
---

# Consensus & Governance with Witan

## Overview

Witan provides multi-agent consensus, policy enforcement, and governance. Use for decisions requiring collective agreement or human escalation.

## MCP Tools

| Tool | Purpose |
|------|---------|
| `witan_propose` | Submit action for consensus |
| `witan_vote` | Cast vote on proposal |
| `witan_check_status` | Check proposal status |
| `witan_enforce_policy` | Check if action is allowed |
| `witan_create_policy` | Create governance policy |
| `witan_broadcast` | Message all agents |
| `witan_escalate` | Escalate to human review |

## Quick Examples

### Propose action for consensus
```
witan_propose({
  action: "deploy_to_production",
  required_approvals: ["security-agent", "qa-agent"],
  protocol: "unanimous"
})
→ { proposal_id: "prop_abc123", status: "pending" }
```

### Vote on proposal
```
witan_vote({
  proposal_id: "prop_abc123",
  agent_id: "security-agent",
  vote: "approve"
})
→ { vote_recorded: true, current_status: "pending" }
```

### Enforce policy
```
witan_enforce_policy({
  action: "access_financial_data",
  actor: "junior-agent"
})
→ { allowed: false, reason: "Requires senior approval" }
```

### Escalate to human
```
witan_escalate({
  action: "delete_customer_data",
  reason: "Requires human approval",
  escalate_to: "human-supervisor"
})
→ { escalation_id: "esc_def456", status: "pending_human_review" }
```

## Consensus Protocols

| Protocol | Use Case |
|----------|----------|
| `unanimous` | Critical decisions (deployments, deletions) |
| `majority` | Standard decisions (>50%) |
| `weighted_majority` | Expert-weighted voting |
| `quorum` | Minimum participation required |

## When to Use

1. High-risk operations requiring multi-agent approval
2. Irreversible actions (deletions, deployments)
3. Actions outside normal agent permissions
4. Human-in-the-loop decisions

## Links

- npm: https://www.npmjs.com/package/@weave_protocol/witan
