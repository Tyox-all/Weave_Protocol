# ⚖️ @weave_protocol/domere

**Enterprise Compliance, Verification & GDPR for AI Agents**

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
| **Compliance** | SOC2, HIPAA, PCI-DSS, ISO27001, **GDPR** checkpoints & reporting |
| **Blockchain** | Solana & Ethereum anchoring for immutable audit trails |
| **GDPR** | Consent management, DSAR handling, breach notification, retention enforcement |

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

Domere v1.3.0 includes comprehensive GDPR support with 11 new MCP tools.

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

// Initialize with data controller info
const gdpr = new GDPRManager({
  name: 'Acme Corporation',
  email: 'dpo@acme.com',
  address: '123 Main St, London',
  dpoContact: 'Jane Smith'
});

// Record consent with full audit trail
const consent = gdpr.recordConsent({
  subjectId: 'user-abc-123',
  purpose: 'marketing',           // or: analytics, profiling, etc.
  legalBasis: 'consent',          // Art 6(1)(a)
  granted: true,
  source: 'web_form',
  version: '2.1.0'
});

// Check if consent is valid
const canMarket = gdpr.hasValidConsent('user-abc-123', 'marketing');

// Withdraw consent (creates audit record)
gdpr.withdrawConsent(consent.id, 'User requested opt-out');
```

### Data Subject Access Requests (DSAR)

```typescript
// Create DSAR - automatically sets 30-day deadline
const dsar = gdpr.createDSAR({
  subjectId: 'user-abc-123',
  type: 'access',                 // or: erasure, portability, rectification, etc.
  verificationMethod: 'email'
});

console.log(`Due date: ${dsar.dueDate}`); // 30 days from now

// Verify identity
gdpr.verifyDSAR(dsar.id, 'privacy-team');

// Process request
gdpr.processDSAR(dsar.id, 'analyst-01');

// Complete with response
gdpr.completeDSAR(dsar.id, {
  type: 'access',
  completedAt: new Date(),
  dataIncluded: true,
  dataFormat: 'json',
  dataLocation: '/exports/user-abc-123.json'
});

// Check for overdue requests
const overdue = gdpr.getOverdueDSARs();
if (overdue.length > 0) {
  console.warn(`⚠️ ${overdue.length} DSARs are past deadline!`);
}
```

### Right to Erasure

```typescript
// Execute erasure with audit trail
const result = await gdpr.executeErasure('user-abc-123', 'User request');

console.log(`Erased ${result.erasedRecords} records`);
// Subject data anonymized, audit trail preserved
```

### Data Portability

```typescript
// Export all subject data in portable format
const exportData = gdpr.exportSubjectData('user-abc-123', 'json');

// Returns:
// - subject profile
// - consent records
// - DSAR history
// - automated decisions
// All in machine-readable format
```

### Data Breach Management

```typescript
// Report a breach immediately upon detection
const breach = gdpr.reportBreach({
  description: 'Unauthorized database access detected',
  severity: 'critical',
  affectedSubjects: 15000,
  affectedCategories: ['identification', 'contact', 'financial'],
  cause: 'cyber_attack',
  consequences: ['Identity theft risk', 'Financial fraud risk']
});

// 72-hour deadline starts now!
console.log(`⚠️ Must notify authority by ${new Date(breach.detectedAt.getTime() + 72*60*60*1000)}`);

// Add mitigation actions
gdpr.addBreachMitigation(breach.id, {
  action: 'Revoked compromised credentials',
  performedBy: 'security-team',
  effective: true
});

gdpr.addBreachMitigation(breach.id, {
  action: 'Enabled additional monitoring',
  performedBy: 'security-team',
  effective: true
});

// Notify supervisory authority (within 72 hours!)
gdpr.notifySupervisoryAuthority(breach.id, 'ICO UK', 'ICO-2024-12345');

// Notify affected subjects if high risk
gdpr.notifyAffectedSubjects(breach.id, 'email', 15000);

// Close breach with lessons learned
gdpr.closeBreach(breach.id, 
  'SQL injection via unvalidated input',
  ['Input validation on all endpoints', 'WAF rules updated', 'Quarterly pen testing']
);
```

### Retention Policy Enforcement

```typescript
// Create retention policy
const policy = gdpr.createRetentionPolicy({
  name: 'Customer Contact Data',
  description: 'Contact information for inactive customers',
  dataCategories: ['contact', 'identification'],
  retentionPeriod: {
    duration: 730,  // 2 years
    unit: 'days',
    reviewCycle: 90
  },
  legalBasis: 'Legitimate interest - customer service',
  deletionMethod: 'anonymization',
  status: 'active',
  nextReviewDate: new Date('2025-01-01')
});

// Execute retention check
const check = gdpr.executeRetentionCheck(policy.id);
console.log(`Deleted ${check.recordsDeleted} expired records`);
```

### Automated Decision Tracking (Article 22)

```typescript
// Record AI-powered decision
const decision = gdpr.recordAutomatedDecision({
  subjectId: 'user-abc-123',
  decisionType: 'credit_scoring',
  algorithm: 'credit-model-v3.2',
  inputData: ['payment_history', 'income', 'employment'],
  outcome: 'approved',
  significance: 'legal_effects',  // Triggers human review requirement
  legalBasis: 'contract',
  explanation: 'Score of 720 exceeds threshold of 650'
});

if (decision.humanReviewRequired) {
  console.log('⚠️ Human review required per Article 22');
  
  // Complete human review
  gdpr.completeHumanReview(
    decision.id,
    'reviewer@company.com',
    'Approved - decision upheld after manual verification'
  );
}

// Check pending reviews
const pending = gdpr.getPendingHumanReviews();
console.log(`${pending.length} decisions awaiting human review`);
```

### GDPR Reporting

```typescript
// Generate compliance report
const report = gdpr.generateReport('full_compliance', {
  start: new Date('2024-01-01'),
  end: new Date('2024-12-31')
});

console.log(`Compliance Score: ${report.summary.complianceScore}%`);
console.log(`DSARs Completed: ${report.summary.dsarCompleted}/${report.summary.dsarRequests}`);
console.log(`Avg Response Time: ${report.summary.avgResponseTime} days`);
console.log(`Breaches: ${report.summary.breaches}`);
console.log(`Human Reviews: ${report.summary.humanReviews}`);
```

---

## 🔗 Blockchain Anchoring

Anchor checkpoints to blockchain for immutable audit proof:

```typescript
// Anchor to Solana
const anchor = await compliance.anchorToBlockchain(checkpoint.id, 'solana');
console.log(`Transaction: ${anchor.transactionId}`);

// Verify later
const verified = await compliance.verifyBlockchainAnchor(checkpoint.id);
console.log(`Verified: ${verified.valid}`);
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

---

## 🛠️ MCP Tools Reference

### Core Compliance Tools

```
domere_checkpoint          Create tamper-evident checkpoint
domere_verify              Verify checkpoint integrity
domere_compliance_report   Generate framework report
domere_list_frameworks     List available frameworks
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
domere_gdpr_log_processing      Article 30 records
domere_gdpr_breach_notify       Breach management
domere_gdpr_retention_check     Retention enforcement
domere_gdpr_automated_decision  Article 22 tracking
domere_gdpr_report              Compliance reporting
```

---

## 🤖 AI Agent Skill

This package includes a `SKILL.md` for Claude AI integration.

**Skill name:** `compliance-auditing`

**Triggers:** audit, checkpoint, SOC2, HIPAA, PCI-DSS, ISO27001, GDPR, blockchain, consent, DSAR, breach, retention

---

## 📄 License

Apache 2.0 - See [LICENSE](../LICENSE)

---

## 🔗 Links

- **GitHub:** https://github.com/Tyox-all/Weave_Protocol
- **npm:** https://www.npmjs.com/package/@weave_protocol/domere
- **Main README:** [Weave Protocol](../README.md)
