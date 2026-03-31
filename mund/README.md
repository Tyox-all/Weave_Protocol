# 🛡️ Mund - The Guardian Protocol

**MCP Security Scanner for AI Agents**

[![npm version](https://img.shields.io/npm/v/@weave_protocol/mund.svg)](https://www.npmjs.com/package/@weave_protocol/mund)
[![npm downloads](https://img.shields.io/npm/dm/@weave_protocol/mund.svg)](https://www.npmjs.com/package/@weave_protocol/mund)
[![MCP Registry](https://img.shields.io/badge/MCP-Registry-blue)](https://registry.modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Mund (Old English: "protection, guardian") is a real-time security scanner for AI agent systems. It detects prompt injection, secrets, PII, dangerous code patterns, and data exfiltration attempts.

**🆕 New in v0.2.0:** Automated threat intelligence with MITRE ATT&CK mapping and community feeds.

## ✨ Features

| Category | What It Detects |
|----------|-----------------|
| **Prompt Injection** | Role manipulation, instruction override, jailbreak attempts, hidden Unicode |
| **Secrets** | API keys (OpenAI, Anthropic, AWS, GitHub, Stripe), tokens, private keys, database URLs |
| **PII** | SSN, credit cards, emails, phone numbers, IP addresses |
| **Code Patterns** | Shell injection, SQL injection, dangerous chmod, curl\|bash, eval |
| **Exfiltration** | Suspicious URLs, DNS tunneling, base64-encoded data blocks |
| **MCP Servers** | Malicious tool descriptions, typosquatting, dangerous permissions, embedded secrets |
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
