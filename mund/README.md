# 🛡️ Mund - The Guardian Protocol

**MCP Security Scanner for AI Agents**

[![npm version](https://img.shields.io/npm/v/@weave_protocol/mund.svg)](https://www.npmjs.com/package/@weave_protocol/mund)
[![npm downloads](https://img.shields.io/npm/dm/@weave_protocol/mund.svg)](https://www.npmjs.com/package/@weave_protocol/mund)
[![MCP Registry](https://img.shields.io/badge/MCP-Registry-blue)](https://registry.modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Mund (Old English: "protection, guardian") is a real-time security scanner for AI agent systems. It detects prompt injection, secrets, PII, dangerous code patterns, and data exfiltration attempts.

**🆕 New in v0.3.1:** [Canary tokens](#-canary-tokens-system-prompt-leakage) catch leaked system prompts, and [rug-pull detection](#rug-pull-detection) flags MCP servers whose tools change after you approved them.

**v0.3.0:** `mund-mcp scan` scans files on disk and outputs text, JSON, or **SARIF for GitHub code scanning**. It checks npm dependencies against **OSV.dev**, with an offline cache. Every scan gets a **0–100 risk score**, and the README adds [OWASP coverage tables](#️-owasp-coverage). This release also fixes 23 secret rules that had never matched anything.

**v0.2.0:** Automated threat intelligence with MITRE ATT&CK mapping and community feeds.

## ✨ Features

| Category | What It Detects |
|----------|-----------------|
| **Prompt Injection** | Role manipulation, instruction override, jailbreak attempts, hidden Unicode |
| **Secrets** | API keys (OpenAI, Anthropic, AWS, GitHub, Stripe), tokens, private keys, database URLs |
| **PII** | SSN, credit cards, emails, phone numbers, IP addresses |
| **Code Patterns** | Shell injection, SQL injection, dangerous chmod, curl\|bash, eval |
| **Exfiltration** | Suspicious URLs, DNS tunneling, base64-encoded data blocks |
| **MCP Servers** | Malicious tool descriptions, typosquatting, dangerous permissions, embedded secrets |
| **Dependencies** | Known-vulnerable npm packages in `package-lock.json`, via OSV.dev with an offline cache |
| **Threat Intel** | 20+ built-in patterns, MITRE ATT&CK mapping, auto-updating community feeds |

## 📦 Installation

```bash
# npm
npm install @weave_protocol/mund

# Or run directly
npx @weave_protocol/mund
```

## 🚀 Quick Start

### Claude Desktop Integration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mund": {
      "command": "npx",
      "args": ["-y", "@weave_protocol/mund"]
    }
  }
}
```

Restart Claude Desktop. Mund's security tools are now available.

### Programmatic Usage

```typescript
import { AnalyzerEngine, getAnalyzers } from '@weave_protocol/mund';

const engine = new AnalyzerEngine(getAnalyzers());
const issues = await engine.analyzeAll(content, rules);

if (issues.some(i => i.severity === 'critical')) {
  console.error('Critical security issues detected!');
}
```

### Scan Files and Upload to GitHub Code Scanning

`mund-mcp scan` checks files on disk, plus the npm dependencies in any
`package-lock.json` (looked up on OSV.dev). Every report includes a
0–100 risk score and a severity label.

```bash
npx @weave_protocol/mund scan .                                  # human-readable
npx @weave_protocol/mund scan src --format=json                  # machine-readable
npx @weave_protocol/mund scan . --format=sarif -o mund.sarif     # SARIF 2.1.0
```

| Option | Meaning |
|--------|---------|
| `--format=text\|json\|sarif` | Output format (default `text`) |
| `--output=FILE`, `-o` | Write to a file instead of stdout |
| `--fail-on=LEVEL` | Exit 1 if any finding is at or above `critical`, `high` (default), `medium`, `low`; `none` never fails |
| `--no-osv` | Skip dependency lookups |
| `--offline` | Use only the local OSV cache (also `MUND_OFFLINE=1`; cache path `MUND_OSV_CACHE`) |

When OSV.dev can't be reached, results come from the cache of the last
successful lookup and the report says so. Packages that were never
looked up are listed as **unchecked**, never as clean.

**GitHub Actions:**

```yaml
permissions:
  security-events: write
steps:
  - uses: actions/checkout@v4
  - run: npx -y @weave_protocol/mund scan . --format=sarif -o mund.sarif --fail-on=none
  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: mund.sarif
      category: mund
```

**Risk score:** each finding takes a share of the remaining headroom
(critical 80%, high 40%, medium 15%, low 5%), so the score climbs quickly
for severe findings and never goes past 100.

| Score | Label |
|-------|-------|
| 80–100 | critical |
| 40–79 | high |
| 15–39 | medium |
| 1–14 | low |
| 0 | none |

`mund_scan_content` and `mund_scan_mcp_server` return `risk_score` and
`risk_label`, and `mund_scan_content` also accepts `format: "sarif"`.

---

## 🧠 Automated Threat Intelligence

**New in v0.2.0:** Mund includes automated threat intelligence with MITRE ATT&CK mapping and auto-updating community feeds.

### Built-in Detection Patterns

| Category | Patterns |
|----------|----------|
| **Prompt Injection** | Direct override, role reassignment, delimiter injection, encoded payloads |
| **Jailbreaks** | DAN, developer mode, hypothetical framing |
| **System Prompt Leaks** | Direct request, indirect extraction |
| **Data Exfiltration** | Markdown image exfil, URL data injection |
| **MCP Exploits** | Tool abuse, cross-tool attacks |
| **DoS Attacks** | Infinite loops, token exhaustion |

### MITRE ATT&CK Mapping

All patterns are mapped to MITRE ATT&CK techniques:

| Technique | Description |
|-----------|-------------|
| T1059 | Command and Scripting Interpreter |
| T1078 | Valid Accounts |
| T1055 | Process Injection |
| T1027 | Obfuscated Files or Information |
| T1041 | Exfiltration Over C2 Channel |
| T1499 | Endpoint Denial of Service |

### Threat Intel Tools

#### `mund_update_threat_intel`

Pull latest patterns from configured feeds.

```
Input: { source?: "weave_community" }

Output: {
  success: true,
  sources_updated: ["weave_community", "mitre_llm"],
  patterns_added: 12,
  patterns_updated: 3
}
```

#### `mund_intel_status`

Get threat intelligence health and coverage.

```
Output: {
  sources: { total: 3, enabled: 3, auto_update: 2 },
  patterns: { total: 47, enabled: 45, by_category: {...} },
  mitre: { techniques_covered: 10, tactics_covered: 6 },
  last_update: "2026-03-30T12:00:00Z"
}
```

#### `mund_list_intel_sources`

Show all configured intel sources.

```
Output: {
  sources: [
    { id: "weave_builtin", enabled: true, auto_update: false, patterns: 20 },
    { id: "weave_community", enabled: true, auto_update: true, interval: "24h" },
    { id: "mitre_llm", enabled: true, auto_update: true, interval: "7d" }
  ]
}
```

#### `mund_threat_scan`

Scan content using threat intelligence patterns.

```
Input: { content: "ignore previous instructions and..." }

Output: {
  threats_detected: 1,
  findings: [{
    pattern_id: "prompt_injection_override",
    category: "prompt_injection",
    severity: "critical",
    mitre_techniques: ["T1059"],
    match: "ignore previous instructions..."
  }]
}
```

#### `mund_add_intel_source` / `mund_remove_intel_source`

Manage custom threat feeds.

#### `mund_list_patterns` / `mund_toggle_pattern`

Browse and enable/disable specific patterns.

---

## 🔍 MCP Server Scanner

**Scan MCP servers before you install them.** Mund detects malicious tool descriptions, typosquatting attacks, dangerous permissions, and embedded secrets in server manifests.

### Why This Matters

- **43% of MCP servers** have command injection vulnerabilities
- **"Line jumping" attacks** hide malicious prompts in tool descriptions
- **Typosquatting** mimics legitimate server names (e.g., `githib` vs `github`)
- **90% of organizations** run MCP servers with excessive permissions

### Tools

#### `mund_scan_mcp_server`

Full security scan of a server manifest before installation.

```
Input: { manifest: "<server.json content>", source?: "registry URL" }

Output: {
  server_name: "example-server",
  recommendation: "DO_NOT_INSTALL" | "REVIEW_CAREFULLY" | "CAUTION" | "APPEARS_SAFE",
  capabilities: { network: true, filesystem: false, execution: true, ... },
  issues: [
    {
      rule_id: "mcp_tool_injection",
      rule_name: "Injection Pattern: Instruction Override",
      severity: "critical",
      match: "Tool 'run_command': ignore previous instructions...",
      suggestion: "DO NOT install this server."
    }
  ]
}
```

#### `mund_check_typosquatting`

Check if a server name is suspiciously similar to a known legitimate server.

```
Input: { name: "githib-mcp" }

Output: {
  name: "githib-mcp",
  is_suspicious: true,
  similar_to: ["github"],
  recommendation: "Verify you have the correct server from a trusted source."
}
```

#### `mund_audit_mcp_permissions`

Analyze what capabilities an MCP server's tools require.

```
Input: { manifest: "<server.json content>" }

Output: {
  server_name: "filesystem-server",
  overall_risk_level: "HIGH",
  capabilities: {
    network: false,
    filesystem: true,
    execution: true,
    environment: false,
    database: false
  },
  capability_summary: [
    "⚠️  Can execute commands/code on your system",
    "📁 Can read/write files"
  ],
  tools: [
    { name: "run_shell", detected_permissions: ["execution"], risk: "HIGH" },
    { name: "read_file", detected_permissions: ["filesystem"], risk: "LOW" }
  ]
}
```

### What It Detects

| Threat | Detection Method |
|--------|------------------|
| **Prompt Injection in Tools** | Scans tool descriptions for "ignore instructions", role switching, jailbreak patterns |
| **Hidden Unicode** | Detects zero-width characters that can hide malicious content |
| **Typosquatting** | Levenshtein distance + substitution patterns (0→o, 1→l) against known servers |
| **Dangerous Permissions** | Flags tools with execution, network, filesystem, or environment access |
| **Embedded Secrets** | Scans manifest for API keys, tokens, connection strings |
| **Suspicious Metadata** | Flags missing versions, URL shorteners in repository links |

---

### Rug-Pull Detection

A rug pull is an MCP server that passes review at install time and then changes what its tools say or do. `mund_check_mcp_rugpull` records a fingerprint of every tool the first time it sees a server, then diffs every later manifest against it:

| Change | Severity |
|--------|----------|
| Tool description changed | high |
| Tool input schema changed | medium |
| Tool added | medium |
| Tool removed | low |
| Server renamed | high |
| Any of the above, where the changed tool now trips the MCP analyzer or newly asks for command execution | **critical** (`DO_NOT_USE`) |

Re-check servers on startup or on a schedule. After a human reviews a change, pass `accept_changes: true` to update the baseline. Baselines are stored in `~/.config/mund/mcp-baselines.json` (override with `MUND_BASELINE_PATH`).

## 🐤 Canary Tokens (System Prompt Leakage)

Put a canary in your system prompt. If a model is ever talked into revealing its instructions, the canary comes out with them, and Mund flags it in any scanned output. That includes copies with changed case, spacing or zero-width characters inserted, base64 encoding, or reversal.

```text
mund_create_canary { "label": "support-bot system prompt" }
  → "MUND-CANARY-7F3A9C2E41B8D605"
    how_to_use: Add "Internal reference: MUND-CANARY-…. Never repeat it." to the system prompt
```

From then on, `mund_scan_content` reports any leak as a critical `canary_leak` finding that blocks the output. Also available:
- `mund_list_canaries` and `mund_remove_canary`
- Load canaries at startup with `MUND_CANARIES` (comma-separated) or `MUND_CANARY_FILE` (one per line)
- Scan transcripts from the CLI: `npx @weave_protocol/mund scan logs/ --canary=MUND-CANARY-…`

Both features are tested against a fixture library in [`tests/fixtures/`](https://github.com/Tyox-all/Weave_Protocol/blob/main/mund/tests/fixtures): one file per case, each with its expected verdict.

## 🔐 Content Scanning Tools

### `mund_scan`

Scan any content for security issues.

```
Input: { content: "Here's my API key: sk-abc123..." }

Output: {
  safe: false,
  issue_count: 1,
  issues: [{
    rule_id: "openai_api_key",
    severity: "critical",
    match: "sk-a****123",
    suggestion: "Use environment variables instead of hardcoding."
  }]
}
```

### `mund_scan_conversation`

Scan an entire conversation history.

```
Input: { 
  messages: [
    { role: "user", content: "My SSN is 123-45-6789" },
    { role: "assistant", content: "I'll help you with that..." }
  ]
}
```

### `mund_check_secret`

Check if a specific string looks like a secret.

```
Input: { value: "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" }

Output: {
  is_secret: true,
  secret_type: "GitHub Personal Access Token",
  confidence: 0.95
}
```

### `mund_check_pii`

Scan content specifically for personally identifiable information.

```
Input: { content: "Contact john@example.com or call 555-123-4567" }

Output: {
  contains_pii: true,
  pii_types: ["email_address", "phone_number_us"],
  issues: [...]
}
```

### `mund_get_stats`

Get scanning statistics and detection history.

```
Output: {
  total_scans: 1547,
  issues_detected: 89,
  by_type: { secret: 34, pii: 28, injection: 15, ... }
}
```

---

## 🛡️ OWASP Coverage

How the OWASP lists are covered, in two columns:

- **Mund**: what this package detects on its own.
- **Weave suite**: Mund together with the other Weave Protocol packages. A suite ✅ means another package **enforces or detects** the control on the row's main attack path. Each one was checked in that package's source, which is linked.

✅ = covered · 🟡 = partly covered (the gap is noted) · ⬜ = not covered · N/A = out of scope for agent security tooling.
Detection is pattern-based: it catches known shapes of an attack, not every variant.

### OWASP Top 10 for LLM Applications (2025)

| ID | Risk | Mund | Weave suite | Coverage and gaps |
|----|------|:----:|:-----------:|-------------------|
| LLM01 | Prompt Injection | 🟡 | 🟡 | Mund: 4 injection rules, MCP description/schema/resource injection, hidden Unicode. **Browser** adds DOM-aware IPI scanning, including hidden CSS text ([ipi.ts](https://github.com/Tyox-all/Weave_Protocol/blob/main/browser/src/ipi.ts)). Gap: paraphrased or novel injections can evade patterns. |
| LLM02 | Sensitive Information Disclosure | ✅ | ✅ | Mund: 31 secret rules, 5 PII rules, exfiltration patterns. **Hord** adds reversible PII tokenization and redaction ([redaction/engine.ts](https://github.com/Tyox-all/Weave_Protocol/blob/main/hord/src/redaction/engine.ts)). |
| LLM03 | Supply Chain | 🟡 | ✅ | Mund: OSV.dev CVEs for npm lockfiles, MCP typosquatting. **Tollere** covers npm, PyPI, Cargo, Go and Maven CVEs, typosquats, maintainer reputation, sandwich attacks, Docker images and IDE extensions ([cve.ts](https://github.com/Tyox-all/Weave_Protocol/blob/main/tollere/src/cve.ts), [sandwich.ts](https://github.com/Tyox-all/Weave_Protocol/blob/main/tollere/src/sandwich.ts), [docker.ts](https://github.com/Tyox-all/Weave_Protocol/blob/main/tollere/src/docker.ts)). Gap: no model or dataset provenance. |
| LLM04 | Data and Model Poisoning | N/A | N/A | Out of scope: training-time risk. |
| LLM05 | Improper Output Handling | 🟡 | ✅ | Mund: dangerous-code rules, `mund_validate_command`, `mund_check_url`. **Hundredmen** scans every tool call's arguments before execution and blocks or holds risky ones ([interceptor.ts](https://github.com/Tyox-all/Weave_Protocol/blob/main/hundredmen/src/interceptor.ts)). Gap: output rendered to a browser (XSS) isn't checked. |
| LLM06 | Excessive Agency | 🟡 | ✅ | **Hundredmen**: approve or block per call, auto-block of high-risk calls in strict mode, approval queues by category ([interceptor.ts](https://github.com/Tyox-all/Weave_Protocol/blob/main/hundredmen/src/interceptor.ts)). **Hord**: signed, expiring, scope-limited capability tokens with a delegation-depth cap ([capability/token.ts](https://github.com/Tyox-all/Weave_Protocol/blob/main/hord/src/capability/token.ts)). |
| LLM07 | System Prompt Leakage | ✅ | ✅ | Mund: **canary tokens** catch a leaked prompt in any scanned output, including spaced-out, zero-width, base64 and reversed copies ([canary.ts](https://github.com/Tyox-all/Weave_Protocol/blob/main/mund/src/canary.ts), [fixtures](https://github.com/Tyox-all/Weave_Protocol/blob/main/mund/tests/fixtures/canary)); it also flags extraction attempts and secrets inside prompts. Gap: a paraphrased leak that leaves out the canary isn't caught. |
| LLM08 | Vector and Embedding Weaknesses | ⬜ | ⬜ | Not covered. |
| LLM09 | Misinformation | N/A | N/A | Out of scope: content accuracy, not security. |
| LLM10 | Unbounded Consumption | ⬜ | ✅ | **Witan**: per-window USD, token and tool-call caps that block, require approval, or notify ([spending/tracker.ts](https://github.com/Tyox-all/Weave_Protocol/blob/main/witan/src/spending/tracker.ts)), plus rate-limit and quota policies ([policy.ts](https://github.com/Tyox-all/Weave_Protocol/blob/main/witan/src/policy.ts)). |

### OWASP Top 10 for Agentic Applications

| ID | Risk | Mund | Weave suite | Coverage and gaps |
|----|------|:----:|:-----------:|-------------------|
| ASI01 | Agent Goal Hijack | 🟡 | 🟡 | Mund: injection and MCP tool-poisoning checks. **Hundredmen** and **Domere** flag drift from the declared intent ([thread/drift.ts](https://github.com/Tyox-all/Weave_Protocol/blob/main/domere/src/thread/drift.ts)). Gap: drift is scored by word overlap, not meaning, so a reworded hijack can pass. |
| ASI02 | Tool Misuse and Exploitation | 🟡 | ✅ | **Hundredmen** intercepts every MCP tool call: argument scanning, server reputation, intent analysis, then approve, block or hold for review ([interceptor.ts](https://github.com/Tyox-all/Weave_Protocol/blob/main/hundredmen/src/interceptor.ts)). |
| ASI03 | Identity and Privilege Abuse | 🟡 | ✅ | **Hord**: HMAC-signed capability tokens with expiry, revocation and a delegation-depth cap ([capability/token.ts](https://github.com/Tyox-all/Weave_Protocol/blob/main/hord/src/capability/token.ts)). **Domere**: signed handoff tokens bound to one agent, with expiry and revocation ([handoff/verification.ts](https://github.com/Tyox-all/Weave_Protocol/blob/main/domere/src/handoff/verification.ts)). Mund catches leaked credentials. |
| ASI04 | Agentic Supply Chain Vulnerabilities | ✅ | ✅ | Mund: static MCP manifest scanning, OSV CVEs, and **rug-pull detection**, which baselines every tool and escalates changes that turn malicious ([rugpull.ts](https://github.com/Tyox-all/Weave_Protocol/blob/main/mund/src/rugpull.ts), [fixtures](https://github.com/Tyox-all/Weave_Protocol/blob/main/mund/tests/fixtures/rugpull)). **Tollere**: package, container and extension supply chain. |
| ASI05 | Unexpected Code Execution | 🟡 | 🟡 | Mund: dangerous-code rules and command validation. **Hundredmen** can block or hold execution calls. Gap: **Hord**'s sandbox enforces a timeout and a temp working directory, but not memory, network or filesystem isolation ([sandbox/executor.ts](https://github.com/Tyox-all/Weave_Protocol/blob/main/hord/src/sandbox/executor.ts)). |
| ASI06 | Memory and Context Poisoning | 🟡 | 🟡 | Mund scans content before it enters context, and **Hord** stores memory encrypted. Gap: stored memory isn't scanned on write or integrity-checked. |
| ASI07 | Insecure Inter-Agent Communication | ⬜ | ✅ | **Domere**: handoffs carry a signed token with an intent hash, are bound to the receiving agent, and expire or can be revoked ([handoff/verification.ts](https://github.com/Tyox-all/Weave_Protocol/blob/main/domere/src/handoff/verification.ts)). |
| ASI08 | Cascading Failures | ⬜ | 🟡 | **Witan**: checkpoints, transaction rollback and recovery plans ([recovery.ts](https://github.com/Tyox-all/Weave_Protocol/blob/main/witan/src/recovery.ts)). Gap: recovers after failure; no circuit breaker to contain one. |
| ASI09 | Human-Agent Trust Exploitation | ⬜ | ⬜ | Not covered. |
| ASI10 | Rogue Agents | ⬜ | 🟡 | **Hord**: signed, hash-chained attestations of agent actions ([attestation/service.ts](https://github.com/Tyox-all/Weave_Protocol/blob/main/hord/src/attestation/service.ts)). **Hundredmen** monitors and can block calls. Gap: no behavioral baseline to spot a rogue agent automatically. |

**Totals:** Mund alone has **3 ✅** out of 20; the Weave suite has **10 ✅**. Next on the path to more green: injection detection measured against Adversary's corpus (LLM01 / ASI01), real sandbox isolation in Hord (ASI05), and scanning memory on write (ASI06).

---

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MUND_TRANSPORT` | `stdio` or `http` | `stdio` |
| `MUND_PORT` | HTTP server port | `3000` |
| `MUND_LOG_LEVEL` | `debug`, `info`, `warn`, `error` | `info` |
| `MUND_BLOCK_MODE` | Block on critical issues | `false` |
| `MUND_STORAGE` | `memory` or `sqlite` | `memory` |

### 🔔 Notifications

Mund can alert on detections via Slack, Teams, email, or webhooks:

```bash
# Slack
MUND_SLACK_WEBHOOK=https://hooks.slack.com/services/...
MUND_SLACK_CHANNEL=#security-alerts

# Microsoft Teams
MUND_TEAMS_WEBHOOK=https://outlook.office.com/webhook/...

# Email
MUND_EMAIL_SMTP_HOST=smtp.gmail.com
MUND_EMAIL_TO=security@company.com

# Generic Webhook
MUND_WEBHOOK_URL=https://api.company.com/alerts
```

---

## 📜 Detection Rules

Mund uses YAML-based rules in `rules/default.yaml`. Example:

```yaml
- id: openai_api_key
  name: OpenAI API Key
  type: secret
  severity: critical
  pattern: 'sk-[a-zA-Z0-9]{48}'
  action: alert
  enabled: true

- id: prompt_injection_ignore
  name: Instruction Override Attempt
  type: injection
  severity: high
  pattern: 'ignore\s+(previous|all|prior)\s+instructions'
  action: alert
  enabled: true
```

### Severity Levels

| Level | Action | Example |
|-------|--------|---------|
| `critical` | Block + Alert | API keys, private keys, MCP injection |
| `high` | Alert | SSN, credit cards, jailbreak attempts |
| `medium` | Log + Alert | Email addresses, suspicious URLs |
| `low` | Log | IP addresses, potential obfuscation |
| `info` | Log | Informational patterns |

---

## 🏗️ Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                       Mund MCP Server                         │
├───────────────────────────────────────────────────────────────┤
│  Tools                                                        │
│  ├── mund_scan               Content scanning                 │
│  ├── mund_scan_conversation  Conversation scanning            │
│  ├── mund_check_secret       Secret detection                 │
│  ├── mund_check_pii          PII detection                    │
│  ├── mund_get_stats          Statistics                       │
│  ├── mund_scan_mcp_server    MCP server scanning              │
│  ├── mund_check_typosquatting   Name verification             │
│  ├── mund_audit_mcp_permissions Permission audit              │
│  ├── mund_update_threat_intel   Pull latest patterns   [NEW]  │
│  ├── mund_intel_status          Health & coverage      [NEW]  │
│  ├── mund_list_intel_sources    Show intel sources     [NEW]  │
│  ├── mund_threat_scan           Scan with intel        [NEW]  │
│  ├── mund_add_intel_source      Add custom feed        [NEW]  │
│  ├── mund_remove_intel_source   Remove feed            [NEW]  │
│  ├── mund_list_patterns         Browse patterns        [NEW]  │
│  └── mund_toggle_pattern        Enable/disable         [NEW]  │
├───────────────────────────────────────────────────────────────┤
│  Analyzers                                                    │
│  ├── SecretScanner           API keys, tokens, credentials    │
│  ├── PIIDetector             Personal information             │
│  ├── InjectionDetector       Prompt injection attempts        │
│  ├── CodeAnalyzer            Dangerous code patterns          │
│  ├── ExfiltrationDetector    Data exfiltration attempts       │
│  ├── McpServerAnalyzer       MCP manifest security            │
│  └── ThreatIntelManager      MITRE ATT&CK patterns     [NEW]  │
├───────────────────────────────────────────────────────────────┤
│  Notifications                                                │
│  └── Slack, Teams, Email, Webhooks                            │
└───────────────────────────────────────────────────────────────┘
```

---

## 🔗 Part of Weave Protocol

Mund is the security layer of the [Weave Protocol](https://github.com/Tyox-all/Weave_Protocol) security suite:

| Package | Purpose |
|---------|---------|
| **🛡️ Mund** | Security scanning, MCP server vetting, threat intelligence |
| **🏛️ Hord** | Encrypted vault storage (Yoxallismus cipher) |
| **⚖️ Domere** | Compliance & verification (PCI-DSS, ISO27001, GDPR) |
| **👥 Witan** | Multi-agent consensus & governance |
| **🔍 Hundredmen** | Real-time MCP proxy & drift detection |
| **🔌 API** | REST interface for all packages |

---

## 📄 License

MIT License - see [LICENSE](LICENSE)

---

## 🔗 Links

- **npm:** https://www.npmjs.com/package/@weave_protocol/mund
- **MCP Registry:** Search "mund" at https://registry.modelcontextprotocol.io
- **GitHub:** https://github.com/Tyox-all/Weave_Protocol
- **Weave Protocol:** https://github.com/Tyox-all/Weave_Protocol
