# ⚖️ @weave_protocol/domere

**Enterprise Compliance, Verification, GDPR & CCPA for AI Agents**

[![npm](https://img.shields.io/npm/v/@weave_protocol/domere.svg)](https://www.npmjs.com/package/@weave_protocol/domere)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/domere.svg)](https://www.npmjs.com/package/@weave_protocol/domere)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Part of the [Weave Protocol](https://github.com/Tyox-all/Weave_Protocol) security suite.

---

## 🆕 What's new

**1.7.0: anchor Ward's decision receipts.** Ward signs every allow and deny decision into a hash-chained log. A chain can't show that its newest receipts were cut off. `domere_anchor_receipts` fixes that: it batches signed log checkpoints from any number of agents into one Merkle root, and prepares the transaction that stores the root on Solana or Ethereum. A log that was truncated or rewritten before an anchored checkpoint then fails `weave-ward receipts verify`.

**1.6.0: GDPR and CCPA records survive restarts.** With `DOMERE_STORAGE=sqlite`:
- consents, DSARs, breaches and opt-outs persist in the same database file as threads;
- erased data is removed from disk too, using `secure_delete` and a WAL checkpoint after deletes.

Checkpoint-chain verification now recomputes every hash, so an edited record fails. A new tool, `domere_gdpr_verify_chain`, runs that check.

**1.5.0: the MCP server serves all the GDPR and CCPA tools.** That makes 42 tools, now 43. A DSAR can't be processed or completed until the requester's identity is verified (GDPR Art. 12(6)).

**1.4.1: real blockchain anchoring.** Dōmere prepares real Ethereum calldata (Keccak-256, ABI-encoded) and Solana instructions (real PDAs) for you to sign and submit. It no longer fakes submissions or verification.

**1.4.0: SQLite storage.** Threads, hops and evidence persist with `DOMERE_STORAGE=sqlite`.

## ✨ Features

| Category | Features |
|----------|----------|
| **Verification** | Intent tracking, drift detection, execution replay, multi-agent handoff |
| **Orchestration** | Task scheduler, agent registry, shared state with locks |
| **Compliance** | SOC2, HIPAA, PCI-DSS, ISO27001, **GDPR**, **CCPA** checkpoints & reporting |
| **Blockchain** | Prepares Solana & Ethereum anchors for you to sign and submit |
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

## 💾 Storage

Threads, hops, anchors and arbitration cases are kept in memory by default. For persistence, use SQLite (Node 22.5+, no extra dependency): set `DOMERE_STORAGE=sqlite` and optionally `DOMERE_DATABASE_URL` (default `~/.weave/domere.sqlite`, created with `0600` permissions). In code: `createStorage('sqlite', { path })`.

**GDPR and CCPA records use the same file** (1.6.0+). With `DOMERE_STORAGE=sqlite`, consents, DSARs, breaches, opt-outs, consumer requests and both checkpoint chains survive a restart. In code, pass a store: `new GDPRManager(controller, { store: new SqliteRecordStore(path) })`, and call `flush()` after changing records you hold a reference to. The MCP server flushes after every call.

- **Erasure erases.** A right-to-erasure request deletes the subject's records from disk. Dōmere uses SQLite's `secure_delete` and checkpoints the WAL afterward, so no copy remains in free pages or the write-ahead log.
- **Edits are detected.** `domere_gdpr_verify_chain` and `ccpa_verify_chain` recompute every checkpoint hash and check each link, so a record edited or removed in the database fails verification. Removing only the newest checkpoint can't be detected from the chain alone, so anchor the latest hash (`domere_prepare_anchor`) or back it up if that matters to you.

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
| `domere_gdpr_verify_chain` | — | Verify checkpoint integrity (recomputes hashes) |

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
| `ccpa_verify_chain` | — | Verify checkpoint integrity (recomputes hashes) |

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

Dōmere **prepares** anchors; you sign and submit them with your own wallet. It never holds keys, broadcasts transactions, or reads chain state.

```text
domere_estimate_anchor_cost  { "network": "solana" }
domere_prepare_anchor        { "thread_id": "thr_...", "network": "ethereum" }
→ Ethereum: { to, data, chain_id, ... } — ABI-encoded anchorThread(...) calldata to sign and send
→ Solana:   { instructions: [{ program_id, accounts, data_base64 }] } — add to a transaction
            (it needs a recent blockhash), then sign and send. The thread_anchor PDA is derived for you.
```

### Anchoring Ward receipts

[Ward](https://www.npmjs.com/package/@weave_protocol/ward) writes a signed, hash-chained receipt for every tool-call decision. To prove later that no receipts were removed or changed:

```bash
weave-ward receipts checkpoint --agent=build-bot      # prints a signed checkpoint of the log's head
```

Give one or more checkpoints (one per agent, any number of agents) to `domere_anchor_receipts`:

```text
domere_anchor_receipts  { "checkpoints": [ {...}, {...} ], "network": "solana" }
→ bundle:       { anchor_id, merkle_root, manifest_hash, receipts, checkpoints }  — keep this
→ transaction:  the unsigned anchor, as from domere_prepare_anchor
```

Sign and send the transaction with your wallet. The chain then stores the bundle's `merkle_root` under its `anchor_id`, with the receipt count. To verify:

```bash
weave-ward receipts verify ~/.weave/receipts/build-bot.jsonl --checkpoints=receipts-anchor.json
```

This fails if any receipt up to the checkpoint is missing or changed. `domere_verify_receipt_anchor` rechecks the bundle offline: the checkpoint signatures, the root and the manifest hash. To finish, compare its `merkle_root` with the value stored on-chain. Library: `prepareReceiptAnchor`, `verifyReceiptAnchorBundle`.

Submitting and verifying on-chain aren't implemented, and the API returns `501` for them. Before 1.4.1, preparing an anchor crashed, Ethereum function selectors were computed with SHA-256 instead of Keccak-256, the Solana PDA was a placeholder, and submit/verify returned invented transaction ids.

**Default program and contract addresses** (override with `anchoring` config):
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

### Core tools

```
domere_create_thread         Start an intent-tracked thread
domere_add_hop               Record an agent hop (signed, hash-chained)
domere_get_thread            Thread status, hop count, merkle root
domere_close_thread          Close with an outcome
domere_verify_thread         Verify every hop's sequence, signature and hash
domere_list_threads          List threads
domere_detect_language       Detect languages in content
domere_analyze_content       Language-aware content analysis
domere_check_injection       Prompt-injection check
domere_check_drift           Drift between declared and current intent
domere_estimate_anchor_cost  Anchoring cost estimate
domere_prepare_anchor        Prepare an anchor to sign and submit yourself
domere_anchor_receipts       Batch Ward receipt checkpoints into one anchor
domere_verify_receipt_anchor Check a receipt anchor bundle offline
```

The `domere` MCP server serves these 14 tools plus the GDPR (12) and CCPA (19) tools below: 45 in all. The GDPR and CCPA records name your organization, so set:

| Variable | Used for |
|---|---|
| `DOMERE_ORG_NAME`, `DOMERE_ORG_EMAIL` | GDPR data controller, CCPA business |
| `DOMERE_ORG_ADDRESS`, `DOMERE_DPO_CONTACT` | Optional controller details |
| `DOMERE_PRIVACY_POLICY_URL`, `DOMERE_DO_NOT_SELL_URL` | CCPA business details |
| `DOMERE_CCPA_MEETS_THRESHOLD` | `false` if the CCPA thresholds don't apply (default `true`) |

Unset values appear as `(not configured)` rather than an invented organization. GDPR and CCPA records persist with threads when `DOMERE_STORAGE=sqlite` (1.6.0+). A data subject access request (DSAR) can only be processed or completed after the requester's identity is verified (GDPR Art. 12(6)).

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
domere_gdpr_verify_chain        Verify the checkpoint chain
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

## 🕸️ Part of Weave Protocol

One [WARD.md](https://github.com/Tyox-all/Weave_Protocol) policy for every agent you run, locally or at scale, plus the tools around it.

| Package | What it does |
|---|---|
| [Ward](https://www.npmjs.com/package/@weave_protocol/ward) | The WARD.md policy standard and the tool-call evaluator every adapter shares |
| [Mund](https://www.npmjs.com/package/@weave_protocol/mund) | Scans content for prompt injection, secrets, PII and exfiltration |
| [Hord](https://www.npmjs.com/package/@weave_protocol/hord) | Encrypted vaults, PII tokenization, sandboxes, capability tokens, attestations |
| [Dōmere](https://www.npmjs.com/package/@weave_protocol/domere) | Audit threads, compliance checkpoints, GDPR and CCPA records, anchoring |
| [Witan](https://www.npmjs.com/package/@weave_protocol/witan) | Multi-agent consensus and spending caps |
| [Hundredmen](https://www.npmjs.com/package/@weave_protocol/hundredmen) | MCP proxy that enforces WARD.md on tool calls |
| [Tollere](https://www.npmjs.com/package/@weave_protocol/tollere) | Supply-chain checks: typosquats, CVEs, suspicious version diffs |
| [Browser](https://www.npmjs.com/package/@weave_protocol/browser) | WARD.md and injection scanning for Playwright browser agents |
| Adapters | WARD.md in [Claude Code](https://www.npmjs.com/package/@weave_protocol/adapter-claudecode), [Antigravity](https://www.npmjs.com/package/@weave_protocol/adapter-antigravity), [MSAF](https://www.npmjs.com/package/@weave_protocol/adapter-msaf), [Gemini CLI](https://www.npmjs.com/package/@weave_protocol/adapter-geminicli), [Codex](https://www.npmjs.com/package/@weave_protocol/adapter-codex), [OpenCode](https://www.npmjs.com/package/@weave_protocol/adapter-opencode) and [Cursor](https://www.npmjs.com/package/@weave_protocol/adapter-cursor) |
| [Adversary](https://www.npmjs.com/package/@weave_protocol/adversary) · [AgentSecBench](https://www.npmjs.com/package/@weave_protocol/agentsecbench) | Red-team engine and locked benchmark |
| [API](https://www.npmjs.com/package/@weave_protocol/api) · [CLI](https://www.npmjs.com/package/@weave_protocol/cli) · [LangChain](https://www.npmjs.com/package/@weave_protocol/langchain) | REST API and dashboard, setup CLI, LangChain.js integration |
| [full](https://www.npmjs.com/package/@weave_protocol/full) | Every defensive package in one install |
| [Yoxallismus](https://www.npmjs.com/package/@weave_protocol/yoxallismus) | Post-quantum hybrid cipher (experimental beta) |

---

## 📄 License

Apache 2.0 - See [LICENSE](../LICENSE)

---

## 🔗 Links

- **GitHub:** https://github.com/Tyox-all/Weave_Protocol
- **npm:** https://www.npmjs.com/package/@weave_protocol/domere
- **Main README:** [Weave Protocol](../README.md)
