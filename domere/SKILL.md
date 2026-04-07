---
name: compliance-auditing
description: "Create compliance checkpoints, generate audit reports, and anchor to blockchain. Use when: audit, checkpoint, SOC2, HIPAA, PCI-DSS, ISO27001, GDPR, CCPA, CPRA, blockchain anchor, compliance report, consent management, DSAR, consumer request, opt-out, data breach, retention policy, automated decision."
---

# ⚖️ Domere - Compliance & Auditing

Enterprise compliance, verification, GDPR and CCPA tooling for AI agents.

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

### CCPA/CPRA Tools

| Tool | Purpose |
|------|---------|
| `ccpa_register_consumer` | Register California consumer |
| `ccpa_record_opt_out` | Do Not Sell / Do Not Share (§1798.120) |
| `ccpa_process_gpc` | Global Privacy Control signal (§1798.135) |
| `ccpa_submit_request` | Submit consumer request (§1798.100-106) |
| `ccpa_verify_request` | Verify consumer identity |
| `ccpa_extend_request` | Extend 45-day deadline (+45 days) |
| `ccpa_complete_request` | Complete with response |
| `ccpa_deny_request` | Deny with valid reason |
| `ccpa_get_overdue_requests` | Alert: overdue requests |
| `ccpa_annual_metrics` | Required annual disclosure (§1798.185) |
| `ccpa_generate_report` | Generate CCPA compliance reports |

## Supported Frameworks

- **SOC2** - Trust Services Criteria
- **HIPAA** - Healthcare data protection
- **PCI-DSS** - Payment card security
- **ISO27001** - Information security
- **GDPR** - EU data protection (30-day deadline)
- **CCPA/CPRA** - California consumer privacy (45-day deadline)

## Usage Examples

### GDPR Consent Management
```typescript
import { GDPRManager } from '@weave_protocol/domere';

const gdpr = new GDPRManager({ name: 'Acme Corp', email: 'dpo@acme.com' });

const consent = gdpr.recordConsent({
  subjectId: 'user-123',
  purpose: 'marketing',
  legalBasis: 'consent',
  granted: true,
  source: 'web_form',
  version: '2.1'
});
```

### CCPA Opt-Out Management
```typescript
import { CCPAManager } from '@weave_protocol/domere';

const ccpa = new CCPAManager({
  name: 'Acme Corp',
  privacyPolicyUrl: 'https://acme.com/privacy',
  doNotSellUrl: 'https://acme.com/do-not-sell',
  contactEmail: 'privacy@acme.com'
});

// Register consumer
const consumer = ccpa.registerConsumer({
  email: 'user@example.com',
  californiaResident: true
});

// Record opt-out
ccpa.recordOptOut({
  consumerId: consumer.id,
  optOutType: 'sale',
  source: 'web_form'
});

// Or process Global Privacy Control signal
ccpa.processGPC(consumer.id); // Opts out of sale + sharing
```

### CCPA Consumer Request
```typescript
// Submit request - 45 day deadline
const request = ccpa.submitRequest({
  consumerId: consumer.id,
  type: 'know_specific',
  source: 'web_form'
});

// Verify identity
ccpa.verifyRequest(request.id, 'email_verification');

// Complete
ccpa.completeRequest(request.id, {
  actions: [{ type: 'disclosed', dataCategory: 'identifiers', recordCount: 5 }],
  format: 'json'
});
```

### Blockchain Anchoring
```typescript
const anchor = await compliance.anchorToBlockchain(checkpoint.id, 'solana');
```

## Blockchain Addresses

- **Solana Mainnet:** `6g7raTAHU2h331VKtfVtkS5pmuvR8vMYwjGsZF1CUj2o`
- **Solana Devnet:** `BeCYVJYfbUu3k2TPGmh9VoGWeJwzm2hg2NdtnvbdBNCj`
- **Ethereum:** `0xAA8b52adD3CEce6269d14C6335a79df451543820`
