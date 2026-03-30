---
name: compliance-auditing
description: "Create compliance checkpoints, generate audit reports, and anchor to blockchain. Use when: audit, checkpoint, SOC2, HIPAA, PCI-DSS, ISO27001, GDPR, blockchain anchor, compliance report, consent management, DSAR, data breach, retention policy, automated decision."
---

# ⚖️ Domere - Compliance & Auditing

Enterprise compliance, verification, and GDPR tooling for AI agents.

## Installation

```bash
npm install @weave_protocol/domere
```

## MCP Tools

### Compliance Frameworks

| Tool | Purpose |
|------|---------|
| `domere_checkpoint` | Create tamper-evident audit checkpoint |
| `domere_verify` | Verify checkpoint integrity |
| `domere_compliance_report` | Generate framework-specific report |
| `domere_list_frameworks` | List available frameworks |

### GDPR Tools

| Tool | Purpose |
|------|---------|
| `domere_gdpr_record_consent` | Record consent with legal basis (Art 6) |
| `domere_gdpr_withdraw_consent` | Process consent withdrawal (Art 7) |
| `domere_gdpr_check_consent` | Verify valid consent exists |
| `domere_gdpr_handle_dsar` | Manage Data Subject Access Requests |
| `domere_gdpr_right_to_erasure` | Execute right to be forgotten (Art 17) |
| `domere_gdpr_data_portability` | Export data in portable format (Art 20) |
| `domere_gdpr_log_processing` | Maintain processing records (Art 30) |
| `domere_gdpr_breach_notify` | 72-hour breach notification (Art 33-34) |
| `domere_gdpr_retention_check` | Enforce retention policies (Art 5) |
| `domere_gdpr_automated_decision` | Track AI decisions & human review (Art 22) |
| `domere_gdpr_report` | Generate GDPR compliance reports |

## Supported Frameworks

- **SOC2** - Trust Services Criteria
- **HIPAA** - Healthcare data protection
- **PCI-DSS** - Payment card security
- **ISO27001** - Information security
- **GDPR** - EU data protection

## Usage Examples

### Create Checkpoint

```typescript
import { ComplianceManager } from '@weave_protocol/domere';

const compliance = new ComplianceManager(['soc2', 'gdpr']);
const checkpoint = await compliance.createCheckpoint({
  action: 'data_access',
  resource: 'customer_records',
  actor: 'agent-001'
});
```

### GDPR Consent Management

```typescript
import { GDPRManager } from '@weave_protocol/domere';

const gdpr = new GDPRManager({ name: 'Acme Corp', email: 'dpo@acme.com' });

// Record consent
const consent = gdpr.recordConsent({
  subjectId: 'user-123',
  purpose: 'marketing',
  legalBasis: 'consent',
  granted: true,
  source: 'web_form',
  version: '2.1'
});

// Check consent
const hasConsent = gdpr.hasValidConsent('user-123', 'marketing');
```

### Handle DSAR

```typescript
// Create access request
const dsar = gdpr.createDSAR({
  subjectId: 'user-123',
  type: 'access',
  verificationMethod: 'email'
});
// Due in 30 days per GDPR

// Complete with data export
gdpr.completeDSAR(dsar.id, {
  type: 'access',
  completedAt: new Date(),
  dataIncluded: true,
  dataFormat: 'json'
});
```

### Data Breach Response

```typescript
// Report breach
const breach = gdpr.reportBreach({
  description: 'Unauthorized database access',
  severity: 'high',
  affectedSubjects: 1500,
  affectedCategories: ['identification', 'contact'],
  cause: 'cyber_attack',
  consequences: ['Identity theft risk']
});

// Notify authority within 72 hours
gdpr.notifySupervisoryAuthority(breach.id, 'ICO UK', 'REF-12345');
```

### Blockchain Anchoring

```typescript
// Anchor checkpoint to Solana
const anchor = await compliance.anchorToBlockchain(checkpoint.id, 'solana');
// Returns transaction ID for immutable proof
```

## Blockchain Addresses

- **Solana Mainnet:** `6g7raTAHU2h331VKtfVtkS5pmuvR8vMYwjGsZF1CUj2o`
- **Solana Devnet:** `BeCYVJYfbUu3k2TPGmh9VoGWeJwzm2hg2NdtnvbdBNCj`
- **Ethereum:** `0xAA8b52adD3CEce6269d14C6335a79df451543820`
