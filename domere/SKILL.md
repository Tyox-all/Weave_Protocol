---
name: compliance-auditing
description: Create audit checkpoints, generate compliance reports (SOC2, HIPAA, PCI-DSS, ISO27001), verify intent, and anchor to blockchain. Use when logging actions for audit, generating compliance reports, detecting drift, or anchoring records immutably.
---

# Compliance Auditing with Domere

## Overview

Domere provides compliance verification, audit logging, intent tracking, and blockchain anchoring. Use for enterprise governance and regulatory compliance.

## MCP Tools

| Tool | Purpose |
|------|---------|
| `domere_create_checkpoint` | Log an auditable action |
| `domere_verify_intent` | Check if action matches declared intent |
| `domere_generate_report` | Create compliance report |
| `domere_list_frameworks` | List available frameworks |
| `domere_anchor_blockchain` | Anchor to Solana/Ethereum |
| `domere_orchestrate_task` | Schedule multi-agent task |

## Quick Examples

### Create audit checkpoint
```
domere_create_checkpoint({
  action: "data_access",
  resource: "customer_records",
  actor: "agent-001"
})
→ { checkpoint_id: "chk_abc123", hash: "sha256:..." }
```

### Verify intent (drift detection)
```
domere_verify_intent({
  declared_intent: "Summarize feedback",
  actual_action: "Accessed payment records"
})
→ { verified: false, drift_detected: true, drift_severity: "high" }
```

### Generate compliance report
```
domere_generate_report({ framework: "soc2", start_date: "2024-01-01", end_date: "2024-03-31" })
→ { compliance_rate: 0.99, findings: {...} }
```

### Anchor to blockchain
```
domere_anchor_blockchain({ checkpoint_id: "chk_abc123", chain: "solana" })
→ { transaction_id: "5xK9p...", anchored: true }
```

## Compliance Frameworks

- **SOC2**: Trust service criteria
- **HIPAA**: Protected health information
- **PCI-DSS**: Payment card security
- **ISO27001**: Information security management

## Blockchain Addresses

- Solana Mainnet: `6g7raTAHU2h331VKtfVtkS5pmuvR8vMYwjGsZF1CUj2o`
- Ethereum: `0xAA8b52adD3CEce6269d14C6335a79df451543820`

## When to Use

1. Log all sensitive actions with checkpoints
2. Verify intent before executing high-risk operations
3. Anchor critical checkpoints to blockchain
4. Generate periodic compliance reports

## Links

- npm: https://www.npmjs.com/package/@weave_protocol/domere
