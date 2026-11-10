# 🛡️ Mund - The Guardian Protocol

**MCP Security Scanner for AI Agents**

[![npm version](https://img.shields.io/npm/v/@weave_protocol/mund.svg)](https://www.npmjs.com/package/@weave_protocol/mund)
[![npm downloads](https://img.shields.io/npm/dm/@weave_protocol/mund.svg)](https://www.npmjs.com/package/@weave_protocol/mund)
[![MCP Registry](https://img.shields.io/badge/MCP-Registry-blue)](https://registry.modelcontextprotocol.io/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Mund (Old English: "protection, guardian") is a real-time security scanner for AI agent systems. It detects prompt injection, secrets, PII, dangerous code patterns, and data exfiltration attempts.

## 🆕 What's new

**0.6.0: a local injection classifier.** A small model now backs up the rules. It runs offline in under a millisecond, with no API key or download, and catches paraphrased overrides that no pattern names. Measured on public test sets: Gandalf goes from 65% to 88%, jackhhao jailbreaks from 57% to 77%, and SPML (a source it never trained on) from 24% to 38%. Benign texts flagged rose from 0 to 2 of 2,062 (0.10%), and none of Mund's benign corpus. It warns and never blocks on its own; `MUND_CLASSIFIER=0` turns it off. Method, every number, and what it can't catch: [DETECTION_CLAIMS.md](DETECTION_CLAIMS.md#local-classifier-060).

Two new rules flag requests that map an agent's guardrails, and requests for working malware or phishing kits. Descriptions and defensive work stay clean. Across 5,825 MITRE ATT&CK and OWASP texts, the texts Mund flags fell from 86 to 15, and all 15 are pages quoting real injection strings. With them, Mund flags every payload in Weave's red-team corpus.

**0.5.2: injection detection by intent.** Mund now looks for what an injection is trying to do, not one fixed phrase. That covers:
- overriding instructions, in six languages;
- hijacking the task;
- text written to an AI reader;
- hiding actions from the user;
- false authority;
- persona jailbreaks;
- extracting the system prompt;
- payment and exfiltration directives.

It also reads text a person never sees: hidden HTML, base64, Unicode tag characters, and words split by zero-width characters.

| Detected at medium or higher | 0.5.1 | 0.5.2 |
|---|---|---|
| [Lakera Gandalf](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) injections | 17.9% | **65.2%** |
| [jackhhao](https://huggingface.co/datasets/jackhhao/jailbreak-classification) jailbreaks | 30.9% | **58.3%** |
| [deepset](https://huggingface.co/datasets/deepset/prompt-injections) prompt injections (mostly German) | 4.9% | **24.6%** |
| False positives, 466 benign prompts from those sets | 0 | **0** |

These sets were not used to write the rules. A fix to the `shell_injection` rule also stops it flagging every line that contains braces. See [what the injection rules look for](#what-the-injection-rules-look-for-052).

**0.5.0: library API.** `scan(content)` returns findings and a 0–100 risk score, using the same analyzers and rules as the MCP tool.

**0.4.0: pre-install checks.** Mund checks skills and MCP servers before they're installed. See [pre-install checks](#-pre-install-checks-for-skills-and-mcp-servers).

**Earlier:**
- 0.3.1 added [canary tokens](#-canary-tokens-system-prompt-leakage) and [rug-pull detection](#rug-pull-detection).
- 0.3.0 added `mund-mcp scan` with SARIF output, OSV.dev dependency checks and risk scores.
- 0.2.0 added threat intelligence with MITRE ATT&CK mapping.

## ✨ Features

| Category | What It Detects |
|----------|-----------------|
| **Prompt Injection** | Instruction override in six languages, task hijack, concealment, false authority, persona jailbreaks, system-prompt extraction, and text hidden in HTML, base64, Unicode tags or zero-width characters |
| **Secrets** | API keys (OpenAI, Anthropic, AWS, GitHub, Stripe), tokens, private keys, database URLs |
| **PII** | SSN, credit cards, emails, phone numbers, IP addresses |
| **Code Patterns** | Shell injection, SQL injection, dangerous chmod, curl\|bash, eval, plus requests to read credential files, dump the environment, clear security logs or escalate privileges |
| **Exfiltration** | Directives to send private data to a URL or address, URLs with `{SESSION_TOKEN}`-style placeholders, suspicious URLs, DNS tunneling, encoded data blocks |
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
import { scan } from '@weave_protocol/mund';

const { issues, risk } = await scan(untrustedText);
// risk: { score: 0-100, label: 'none' | 'low' | 'medium' | 'high' | 'critical', counts }

if (risk.label === 'high' || risk.label === 'critical') {
  throw new Error(`Blocked: ${issues.map(i => i.rule_name).join(', ')}`);
}

// Only some analyzers, or your own rules
await scan(text, { types: ['injection', 'exfiltration'] });
```

Treat findings at `medium` or higher as actionable. `AnalyzerEngine`, the individual analyzers, `DEFAULT_RULES` and `computeRiskScore` are exported for lower-level use.

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

Mund includes automated threat intelligence with MITRE ATT&CK mapping and auto-updating community feeds.

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

## 🚪 Pre-Install Checks for Skills and MCP Servers

Mund checks agent skills and MCP servers **before they get to act**. Every check is backed by a fixture; see [DETECTION_CLAIMS.md](DETECTION_CLAIMS.md).

```bash
npx @weave_protocol/mund agent-audit --live            # audit installed skills + configured MCP servers
npx @weave_protocol/mund check-skill ./my-skill/       # check one skill before you install it
```

- **Skills:** hidden Unicode (invisible tag characters, bidi overrides), prompt injection, exfiltration instructions, dangerous commands, and embedded secrets, across `SKILL.md` and every file the skill ships.
- **MCP servers, static:** package typosquats (including scopes imitating `@modelcontextprotocol`), unpinned packages, plain-HTTP or data-collection URLs, inline secrets, and shell-pipeline launchers.
- **MCP servers, live (`--live`):** connects, lists the tools, scans their descriptions, and compares them with the rug-pull baseline.

Verdicts are **block**, **warn** or **allow**. Configs are read from Claude Code (`.mcp.json`, `~/.claude.json`, Claude Desktop) or, with `--harness=antigravity`, from Antigravity (`.agents/`, `~/.gemini/config/`).

**Safety:** the live check never starts a project or workspace server you haven't approved, or a server whose package or URL it already distrusts. Those get static checks only.

**Enforcement** comes from the harness adapters, which run these checks as hooks:
- [`@weave_protocol/adapter-claudecode`](../adapter-claudecode#mund-pre-install-hooks): `weave-claude-code mund install`
- [`@weave_protocol/adapter-antigravity`](../adapter-antigravity#mund-pre-install-hooks): `weave-antigravity mund install`

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
| ASI05 | Unexpected Code Execution | 🟡 | ✅ | Mund: dangerous-code rules and command validation. **Hundredmen** can block or hold execution calls. **Hord**'s sandbox isolates network, filesystem and environment (`sandbox-exec` on macOS, `bwrap` on Linux), kills the process group on memory or time overruns, and reports what it enforced; strict mode refuses to run without full isolation ([sandbox/isolation.ts](https://github.com/Tyox-all/Weave_Protocol/blob/main/hord/src/sandbox/isolation.ts), [escape tests](https://github.com/Tyox-all/Weave_Protocol/blob/main/hord/tests/sandbox-isolation.test.ts)). |
| ASI06 | Memory and Context Poisoning | 🟡 | 🟡 | Mund scans content before it enters context, and **Hord** stores memory encrypted. Gap: stored memory isn't scanned on write or integrity-checked. |
| ASI07 | Insecure Inter-Agent Communication | ⬜ | ✅ | **Domere**: handoffs carry a signed token with an intent hash, are bound to the receiving agent, and expire or can be revoked ([handoff/verification.ts](https://github.com/Tyox-all/Weave_Protocol/blob/main/domere/src/handoff/verification.ts)). |
| ASI08 | Cascading Failures | ⬜ | 🟡 | **Witan**: checkpoints, transaction rollback and recovery plans ([recovery.ts](https://github.com/Tyox-all/Weave_Protocol/blob/main/witan/src/recovery.ts)). Gap: recovers after failure; no circuit breaker to contain one. |
| ASI09 | Human-Agent Trust Exploitation | ⬜ | ⬜ | Not covered. |
| ASI10 | Rogue Agents | ⬜ | 🟡 | **Hord**: signed, hash-chained attestations of agent actions ([attestation/service.ts](https://github.com/Tyox-all/Weave_Protocol/blob/main/hord/src/attestation/service.ts)). **Hundredmen** monitors and can block calls. Gap: no behavioral baseline to spot a rogue agent automatically. |

**Totals:** Mund alone has **3 ✅** out of 20; the Weave suite has **11 ✅**. Next on the path to more green: injection detection measured against Adversary's corpus (LLM01 / ASI01) and scanning memory on write (ASI06).

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

Mund's rules are built in and exported as `DEFAULT_RULES`. Add your own with the `mund_add_rule` tool, or pass them to `scan()`:

```typescript
import { scan, DEFAULT_RULES, type DetectionRule } from '@weave_protocol/mund';

const internalHost: DetectionRule = {
  id: 'internal_hostname',
  name: 'Internal hostname',
  description: 'Mentions of our internal network',
  type: 'exfiltration',
  pattern: '(?i)\\b[a-z0-9-]+\\.corp\\.example\\.com\\b',
  severity: 'medium',
  action: 'alert',
  enabled: true,
};

await scan(text, { rules: [...DEFAULT_RULES, internalHost] });
```

Patterns are JavaScript regular expressions. A leading `(?i)` makes one case-insensitive.

### What the injection rules look for (0.5.2)

The injection rules look for intent, not a single phrase, and run on normalized text with zero-width characters removed and Unicode normalized. These families of rules fire on any phrasing that matches them:

| Rule | Catches |
|---|---|
| `prompt_injection_ignore` | Ignoring, forgetting or overriding earlier instructions (EN, DE, ES, FR, IT, PT) |
| `prompt_injection_new_task` | A new task, role or directive that replaces the agent's own |
| `prompt_injection_ai_addressed` | Text written to an AI reader ("if you are an AI…") |
| `prompt_injection_concealment` | Hiding actions from the user |
| `prompt_injection_authority` | False system, admin or developer authority |
| `prompt_injection_jailbreak` | Unrestricted personas, "no ethical guidelines", developer mode, forced prefixes |
| `prompt_injection_decode_execute` | Decode or translate, then act on the result |
| `prompt_injection_system` | System-prompt and instruction extraction |
| `prompt_injection_data_harvest` | Collecting the user's history, contacts or credentials |
| `transaction_directive` | Moving money to an account |
| `exfiltration_directive`, `templated_exfil_url` | Sending private data to a URL or address, and URLs with `{SESSION_TOKEN}`-style placeholders |
| `credential_file_access`, `environment_dump`, `log_tampering`, `privilege_escalation` | Dangerous operations requested in content |

Mund also reads text a person doesn't see:
- hidden HTML elements, `noscript`, `template` and comments;
- base64 that decodes to prose;
- Unicode tag characters;
- words split by zero-width characters;
- tool-call syntax embedded in content.

Treat a hit at `medium` or higher as actionable. That is the threshold Weave's CI uses: it holds detection on our attack corpus and false positives on a benign corpus (`tests/fixtures/benign`) to a committed baseline.

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
│  ├── mund_update_threat_intel   Pull latest patterns          │
│  ├── mund_intel_status          Health & coverage             │
│  ├── mund_list_intel_sources    Show intel sources            │
│  ├── mund_threat_scan           Scan with intel               │
│  ├── mund_add_intel_source      Add custom feed               │
│  ├── mund_remove_intel_source   Remove feed                   │
│  ├── mund_list_patterns         Browse patterns               │
│  └── mund_toggle_pattern        Enable/disable                │
├───────────────────────────────────────────────────────────────┤
│  Analyzers                                                    │
│  ├── SecretScanner           API keys, tokens, credentials    │
│  ├── PIIDetector             Personal information             │
│  ├── InjectionDetector       Prompt injection attempts        │
│  ├── CodeAnalyzer            Dangerous code patterns          │
│  ├── ExfiltrationDetector    Data exfiltration attempts       │
│  ├── McpServerAnalyzer       MCP manifest security            │
│  └── ThreatIntelManager      MITRE ATT&CK patterns            │
├───────────────────────────────────────────────────────────────┤
│  Notifications                                                │
│  └── Slack, Teams, Email, Webhooks                            │
└───────────────────────────────────────────────────────────────┘
```

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

Apache-2.0 — see [LICENSE](LICENSE)

---

## 🔗 Links

- **npm:** https://www.npmjs.com/package/@weave_protocol/mund
- **MCP Registry:** Search "mund" at https://registry.modelcontextprotocol.io
- **GitHub:** https://github.com/Tyox-all/Weave_Protocol
- **Weave Protocol:** https://github.com/Tyox-all/Weave_Protocol
