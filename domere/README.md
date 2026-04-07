# ⚖️ @weave_protocol/domere

**Enterprise Compliance, Verification, GDPR & CCPA for AI Agents**

[![npm](https://img.shields.io/npm/v/@weave_protocol/domere.svg)](https://www.npmjs.com/package/@weave_protocol/domere)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/domere.svg)](https://www.npmjs.com/package/@weave_protocol/domere)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Part of the [Weave Protocol](https://github.com/Tyox-all/Weave_Protocol) security suite.

---

## ✨ Features

| Category | Features |
|----------|----------|
| **Verification** | Intent tracking, drift detection, execution replay, multi-agent handoff |
| **Orchestration** | Task scheduler, agent registry, shared state with locks |
| **Compliance** | SOC2, HIPAA, PCI-DSS, ISO27001, **GDPR**, **CCPA** checkpoints & reporting |
| **Blockchain** | Solana & Ethereum anchoring for immutable audit trails |
| **GDPR** | Consent management, DSAR handling, breach notification, retention enforcement |
| **CCPA** | Consumer requests, opt-out management, sale disclosure, annual metrics |

---

## 📦 Installation

```bash
npm install @weave_protocol/domere
```

---

## 🚀 Quick Start

### Basic Compliance Checkpoint

```typescript
import { ComplianceManager } from '@weave_protocol/domere';

const compliance = new ComplianceManager(['soc2', 'hipaa', 'gdpr']);

// Create tamper-evident checkpoint
const checkpoint = await compliance.createCheckpoint({
  action: 'data_access',
  resource: 'patient_records',
  actor: 'agent-medical-01',
  metadata: { reason: 'treatment_review' }
});

console.log(checkpoint.hash); // SHA-256 hash for verification
```

### Claude Desktop Integration

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "domere": {
      "command": "npx",
      "args": ["-y", "@weave_protocol/domere"]
    }
  }
}
```

---

## 🇪🇺 GDPR Compliance

Domere includes comprehensive GDPR support with 11 MCP tools.

### GDPR Tools Overview

| Tool | GDPR Article | Purpose |
|------|--------------|---------|
| `domere_gdpr_record_consent` | Art 6, 7 | Record consent with legal basis |
| `domere_gdpr_withdraw_consent` | Art 7(3) | Process consent withdrawal |
| `domere_gdpr_check_consent` | Art 6 | Verify valid consent exists |
| `domere_gdpr_handle_dsar` | Art 15-22 | Manage all subject rights requests |
| `domere_gdpr_right_to_erasure` | Art 17 | Execute "right to be forgotten" |
| `domere_gdpr_data_portability` | Art 20 | Export data in portable format |
| `domere_gdpr_log_processing` | Art 30 | Maintain processing records |
| `domere_gdpr_breach_notify` | Art 33-34 | 72-hour breach notification workflow |
| `domere_gdpr_retention_check` | Art 5(1)(e) | Enforce storage limitation |
| `domere_gdpr_automated_decision` | Art 22 | Track AI decisions & human review |
| `domere_gdpr_report` | Various | Generate compliance reports |

### Consent Management

```typescript
import { GDPRManager } from '@weave_protocol/domere';

const gdpr = new GDPRManager({
  name: 'Acme Corporation',
  email: 'dpo@acme.com',
  address: '123 Main St, London',
  dpoContact: 'Jane Smith'
});

const consent = gdpr.recordConsent({
  subjectId: 'user-abc-123',
  purpose: 'marketing',
  legalBasis: 'consent',
  granted: true,
  source: 'web_form',
  version: '2.1.0'
});
```

### Data Subject Access Requests (DSAR)

```typescript
// Create DSAR - automatically sets 30-day deadline
const dsar = gdpr.createDSAR({
  subjectId: 'user-abc-123',
  type: 'access',
  verificationMethod: 'email'
});

// Check for overdue requests
const overdue = gdpr.getOverdueDSARs();
```

---

## 🇺🇸 CCPA/CPRA Compliance

Domere v1.3.4+ includes comprehensive California Consumer Privacy Act (CCPA) and California Privacy Rights Act (CPRA) support with 18 MCP tools.

### CCPA vs GDPR Quick Reference

| Aspect | GDPR | CCPA |
|--------|------|------|
| Deadline | 30 days | 45 days (extendable +45) |
| Terminology | Data Subject | Consumer |
| Controller | Data Controller | Business |
| Key Right | Right to Erasure | Right to Opt-Out of Sale |
| Signal | — | Global Privacy Control (GPC) |

### CCPA Tools Overview

| Tool | CCPA Section | Purpose |
|------|--------------|---------|
| `ccpa_register_consumer` | 1798.140 | Register consumer for tracking |
| `ccpa_get_consumer` | 1798.140 | Lookup consumer by ID or email |
| `ccpa_record_opt_out` | 1798.120 | Record Do Not Sell/Share opt-out |
| `ccpa_process_gpc` | 1798.135 | Process Global Privacy Control signal |
| `ccpa_withdraw_opt_out` | 1798.120 | Consumer withdraws opt-out |
| `ccpa_get_opt_outs` | 1798.120 | List consumer's active opt-outs |
| `ccpa_check_opt_out` | 1798.120 | Check if opt-out is active |
| `ccpa_submit_request` | 1798.100-106 | Submit consumer request |
| `ccpa_verify_request` | 1798.185 | Verify consumer identity |
| `ccpa_extend_request` | 1798.105 | Extend deadline by 45 days |
| `ccpa_complete_request` | 1798.100-106 | Complete with response |
| `ccpa_deny_request` | 1798.105 | Deny with valid reason |
| `ccpa_get_pending_requests` | — | List pending requests |
| `ccpa_get_overdue_requests` | — | List overdue requests (alert!) |
| `ccpa_generate_report` | 1798.185 | Generate compliance report |
| `ccpa_annual_metrics` | 1798.185(a)(7) | Required annual disclosure |
| `ccpa_get_checkpoints` | — | Audit trail for compliance |
| `ccpa_verify_chain` | — | Verify checkpoint integrity |

### Consumer Opt-Out Management

```typescript
import { CCPAManager } from '@weave_protocol/domere';

const ccpa = new CCPAManager({
  id: 'biz-001',
  name: 'Acme Corporation',
  address: '123 Main St, San Francisco, CA',
  privacyPolicyUrl: 'https://acme.com/privacy',
  doNotSellUrl: 'https://acme.com/do-not-sell',
  contactEmail: 'privacy@acme.com',
  meetsThreshold: true
});

// Register consumer
const consumer = ccpa.registerConsumer({
  email: 'user@example.com',
  californiaResident: true
});

// Record opt-out (Do Not Sell My Personal Information)
const optOut = ccpa.recordOptOut({
  consumerId: consumer.id,
  optOutType: 'sale',
  source: 'web_form'
});

// Check if consumer has opted out
const hasOptedOut = ccpa.hasActiveOptOut(consumer.id, 'sale');
```

### Global Privacy Control (GPC)

```typescript
// Process GPC signal - automatically opts out of sale AND sharing
const optOuts = ccpa.processGPC(consumer.id);
console.log(`Created ${optOuts.length} opt-outs via GPC`); // 2
```

### Consumer Requests (45-day deadline)

```typescript
// Submit Right to Know request
const request = ccpa.submitRequest({
  consumerId: consumer.id,
  type: 'know_specific',
  source: 'web_form'
});

console.log(`Due: ${request.dueDate}`); // 45 days from now

// Verify identity before processing
ccpa.verifyRequest(request.id, 'email_verification');

// Need more time? Extend once by 45 days
ccpa.extendRequest(request.id, 'Complex request');

// Complete with response
ccpa.completeRequest(request.id, {
  actions: [
    { type: 'disclosed', dataCategory: 'identifiers', recordCount: 5 },
    { type: 'disclosed', dataCategory: 'commercial_info', recordCount: 23 }
  ],
  format: 'json'
});
```

### Annual Metrics Disclosure

```typescript
// Required annual disclosure per CCPA Section 1798.185(a)(7)
const metrics = ccpa.generateAnnualMetrics(2025);

console.log('Right to Know:', metrics.requestsToKnow);
console.log('Right to Delete:', metrics.requestsToDelete);
console.log('Right to Opt-Out:', metrics.requestsToOptOut);
```

### Personal Information Categories

| Category | Examples |
|----------|----------|
| `identifiers` | Name, SSN, driver's license, passport |
| `customer_records` | Paper/electronic customer records |
| `protected_classifications` | Age, race, religion, sexual orientation |
| `commercial_info` | Products purchased, purchase history |
| `biometric` | Fingerprints, face recognition |
| `internet_activity` | Browsing history, search history |
| `geolocation` | Precise physical location |
| `sensory_data` | Audio, video, thermal data |
| `professional_info` | Employment information |
| `education_info` | Non-public education records |
| `inferences` | Consumer profiles, predictions |
| `sensitive_personal_info` | CPRA sensitive categories |

---

## 🔗 Blockchain Anchoring

Anchor checkpoints to blockchain for immutable audit proof:

```typescript
const anchor = await compliance.anchorToBlockchain(checkpoint.id, 'solana');
console.log(`Transaction: ${anchor.transactionId}`);
```

**Blockchain Addresses:**
- **Solana Mainnet:** `6g7raTAHU2h331VKtfVtkS5pmuvR8vMYwjGsZF1CUj2o`
- **Solana Devnet:** `BeCYVJYfbUu3k2TPGmh9VoGWeJwzm2hg2NdtnvbdBNCj`
- **Ethereum:** `0xAA8b52adD3CEce6269d14C6335a79df451543820`

---

## 📊 Compliance Frameworks

| Framework | Status | Description |
|-----------|--------|-------------|
| SOC2 | ✅ Implemented | Trust Services Criteria |
| HIPAA | ✅ Implemented | Healthcare data protection |
| PCI-DSS | ✅ Implemented | Payment card security |
| ISO27001 | ✅ Implemented | Information security management |
| GDPR | ✅ Implemented | EU data protection regulation |
| CCPA/CPRA | ✅ Implemented | California consumer privacy |

---

## 🛠️ MCP Tools Reference

### Core Compliance Tools

```
domere_checkpoint          Create tamper-evident checkpoint
domere_verify              Verify checkpoint integrity
domere_compliance_report   Generate framework report
domere_anchor_blockchain   Anchor to Solana/Ethereum
```

### GDPR Tools

```
domere_gdpr_record_consent      Record/update consent
domere_gdpr_withdraw_consent    Withdraw consent
domere_gdpr_check_consent       Check consent status
domere_gdpr_handle_dsar         Create/manage DSARs
domere_gdpr_right_to_erasure    Execute data deletion
domere_gdpr_data_portability    Export subject data
domere_gdpr_breach_notify       Breach management
domere_gdpr_retention_check     Retention enforcement
domere_gdpr_automated_decision  Article 22 tracking
domere_gdpr_report              Compliance reporting
```

### CCPA/CPRA Tools

```
ccpa_register_consumer      Register California consumer
ccpa_get_consumer           Lookup consumer
ccpa_record_opt_out         Do Not Sell / Do Not Share
ccpa_process_gpc            Global Privacy Control signal
ccpa_withdraw_opt_out       Withdraw opt-out
ccpa_check_opt_out          Check opt-out status
ccpa_submit_request         Submit consumer request
ccpa_verify_request         Verify identity
ccpa_extend_request         Extend 45-day deadline
ccpa_complete_request       Complete with response
ccpa_deny_request           Deny with reason
ccpa_get_pending_requests   List pending requests
ccpa_get_overdue_requests   Alert: overdue requests
ccpa_generate_report        Compliance reports
ccpa_annual_metrics         Required annual disclosure
ccpa_get_checkpoints        Audit trail
ccpa_verify_chain           Verify checkpoint integrity
```

---

## 🤖 AI Agent Skill

**Skill name:** `compliance-auditing`

**Triggers:** audit, checkpoint, SOC2, HIPAA, PCI-DSS, ISO27001, GDPR, CCPA, CPRA, blockchain, consent, DSAR, consumer request, opt-out, breach, retention

---

## 📄 License

Apache 2.0 - See [LICENSE](../LICENSE)

---

## 🔗 Links

- **GitHub:** https://github.com/Tyox-all/Weave_Protocol
- **npm:** https://www.npmjs.com/package/@weave_protocol/domere
- **Main README:** [Weave Protocol](../README.md)
