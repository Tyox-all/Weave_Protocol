---
name: domere
description: "Use this skill whenever compliance, verification, audit logging, or orchestration is needed. Triggers: creating audit checkpoints, generating compliance reports (SOC2, HIPAA, PCI-DSS, ISO27001), verifying agent actions, tracking intent drift, orchestrating multi-agent tasks, blockchain anchoring, or any request involving 'compliance', 'audit', 'checkpoint', 'verify', 'orchestrate', 'SOC2', 'HIPAA', 'PCI-DSS', 'ISO27001', or 'blockchain anchor'. Use Domere for enterprise governance requirements."
license: Apache 2.0
---

# ⚖️ Domere - Compliance & Verification Guide

## Overview

Domere provides enterprise-grade verification, orchestration, compliance, and audit infrastructure. Use it for regulatory compliance (SOC2, HIPAA, PCI-DSS, ISO27001), audit logging, intent verification, and multi-agent orchestration.

## Quick Start

```typescript
import { ComplianceManager } from '@weave_protocol/domere';

const compliance = new ComplianceManager(['pci-dss', 'iso27001', 'soc2', 'hipaa']);

// Create checkpoint
const checkpoint = await compliance.createCheckpoint({
  action: 'data_access',
  resource: 'customer_records',
  actor: 'agent-001'
});

// Generate report
const report = await compliance.generateReport('pci-dss', {
  startDate: '2024-01-01',
  endDate: '2024-12-31'
});
```

## MCP Tools Available

When running as an MCP server, these tools are available:

| Tool | Use When |
|------|----------|
| `domere_create_checkpoint` | Logging an auditable action |
| `domere_verify_intent` | Checking if action matches declared intent |
| `domere_detect_drift` | Identifying deviation from expected behavior |
| `domere_generate_report` | Creating compliance reports |
| `domere_list_frameworks` | Listing available compliance frameworks |
| `domere_anchor_blockchain` | Anchoring checkpoint to Solana/Ethereum |
| `domere_orchestrate_task` | Scheduling multi-agent tasks |
| `domere_register_agent` | Registering an agent in the registry |

---

## Common Tasks

### Create Audit Checkpoint

```typescript
// MCP tool call
domere_create_checkpoint({
  action: "data_access",
  resource: "customer_records",
  actor: "agent-001",
  metadata: {
    reason: "Customer support request #12345",
    approved_by: "supervisor-002"
  }
})

// Response
{
  checkpoint_id: "chk_abc123",
  timestamp: "2024-01-15T10:30:00Z",
  hash: "sha256:...",
  frameworks: ["pci-dss", "soc2"]
}
```

### Verify Intent (Drift Detection)

```typescript
domere_verify_intent({
  declared_intent: "Summarize customer feedback",
  actual_action: "Accessed payment records",
  actor: "agent-001"
})

// Response
{
  verified: false,
  drift_detected: true,
  drift_severity: "high",
  explanation: "Action 'Accessed payment records' does not match intent 'Summarize customer feedback'",
  recommendation: "Block action and escalate for review"
}
```

### Generate Compliance Report

```typescript
domere_generate_report({
  framework: "soc2",
  start_date: "2024-01-01",
  end_date: "2024-03-31",
  format: "pdf"
})

// Response
{
  report_id: "rpt_xyz789",
  framework: "soc2",
  period: "Q1 2024",
  findings: {
    total_checkpoints: 1547,
    compliant: 1532,
    non_compliant: 15,
    compliance_rate: 0.99
  },
  download_url: "/reports/rpt_xyz789.pdf"
}
```

### Anchor to Blockchain

```typescript
domere_anchor_blockchain({
  checkpoint_id: "chk_abc123",
  chain: "solana",
  network: "mainnet"
})

// Response
{
  anchored: true,
  chain: "solana",
  network: "mainnet",
  transaction_id: "5xK9p...",
  program_id: "6g7raTAHU2h331VKtfVtkS5pmuvR8vMYwjGsZF1CUj2o",
  timestamp: "2024-01-15T10:31:00Z"
}
```

### Orchestrate Multi-Agent Task

```typescript
domere_orchestrate_task({
  task: "Analyze Q3 financial data",
  agents: ["data-agent", "analysis-agent", "report-agent"],
  dependencies: {
    "analysis-agent": ["data-agent"],
    "report-agent": ["analysis-agent"]
  },
  timeout: 300000
})

// Response
{
  task_id: "task_def456",
  status: "scheduled",
  agents: ["data-agent", "analysis-agent", "report-agent"],
  estimated_completion: "2024-01-15T10:35:00Z"
}
```

---

## Compliance Frameworks

| Framework | Coverage |
|-----------|----------|
| **SOC2** | Trust service criteria (security, availability, processing integrity, confidentiality, privacy) |
| **HIPAA** | Protected health information (PHI) handling |
| **PCI-DSS** | Payment card data security |
| **ISO27001** | Information security management |

### Framework-Specific Checkpoints

```typescript
// PCI-DSS: Cardholder data access
domere_create_checkpoint({
  action: "cardholder_data_access",
  resource: "payment_cards",
  framework: "pci-dss",
  controls: ["3.4", "7.1", "10.2"]
})

// HIPAA: PHI access
domere_create_checkpoint({
  action: "phi_access",
  resource: "patient_records",
  framework: "hipaa",
  controls: ["164.312(a)", "164.312(b)"]
})
```

---

## Blockchain Anchoring

Domere supports immutable audit trail anchoring:

| Chain | Network | Program/Contract |
|-------|---------|------------------|
| Solana | Mainnet | `6g7raTAHU2h331VKtfVtkS5pmuvR8vMYwjGsZF1CUj2o` |
| Solana | Devnet | `BeCYVJYfbUu3k2TPGmh9VoGWeJwzm2hg2NdtnvbdBNCj` |
| Ethereum | Mainnet | `0xAA8b52adD3CEce6269d14C6335a79df451543820` |

**Why anchor to blockchain?**
- Immutable proof of checkpoint existence
- Tamper-evident audit trail
- Third-party verifiable timestamps
- Regulatory evidence for auditors

---

## Orchestration Features

| Feature | Description |
|---------|-------------|
| **Task Scheduler** | Coordinate multi-agent workflows |
| **Agent Registry** | Track agent capabilities and status |
| **Shared State** | Concurrent access with locks |
| **Dependency Graph** | Define task dependencies |
| **Failure Recovery** | Automatic retry and failover |

---

## Best Practices

1. **Create checkpoints** for all sensitive actions
2. **Use intent verification** to detect drift before execution
3. **Anchor critical checkpoints** to blockchain for immutability
4. **Generate periodic reports** for compliance audits
5. **Register all agents** in the orchestrator for visibility

---

## Quick Reference

| Task | Tool |
|------|------|
| Log an action | `domere_create_checkpoint` |
| Check if action matches intent | `domere_verify_intent` |
| Create audit report | `domere_generate_report` |
| Make checkpoint immutable | `domere_anchor_blockchain` |
| Schedule multi-agent work | `domere_orchestrate_task` |
| List compliance options | `domere_list_frameworks` |

---

## Links

- **npm:** https://www.npmjs.com/package/@weave_protocol/domere
- **GitHub:** https://github.com/Tyox-all/Weave_Protocol
