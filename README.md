# 🕸️ Weave Protocol

**Enterprise Security Suite for AI Agents**

[![npm](https://img.shields.io/npm/v/@weave_protocol/mund.svg?label=mund)](https://www.npmjs.com/package/@weave_protocol/mund)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/mund.svg)](https://www.npmjs.com/package/@weave_protocol/mund)
[![npm](https://img.shields.io/npm/v/@weave_protocol/hord.svg?label=hord)](https://www.npmjs.com/package/@weave_protocol/hord)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/hord.svg)](https://www.npmjs.com/package/@weave_protocol/hord)
[![npm](https://img.shields.io/npm/v/@weave_protocol/domere.svg?label=domere)](https://www.npmjs.com/package/@weave_protocol/domere)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/domere.svg)](https://www.npmjs.com/package/@weave_protocol/domere)
[![npm](https://img.shields.io/npm/v/@weave_protocol/witan.svg?label=witan)](https://www.npmjs.com/package/@weave_protocol/witan)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/witan.svg)](https://www.npmjs.com/package/@weave_protocol/witan)
[![npm](https://img.shields.io/npm/v/@weave_protocol/hundredmen.svg?label=hundredmen)](https://www.npmjs.com/package/@weave_protocol/hundredmen)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/hundredmen.svg)](https://www.npmjs.com/package/@weave_protocol/hundredmen)
[![npm](https://img.shields.io/npm/v/@weave_protocol/tollere.svg?label=tollere)](https://www.npmjs.com/package/@weave_protocol/tollere)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/tollere.svg)](https://www.npmjs.com/package/@weave_protocol/tollere)
[![npm](https://img.shields.io/npm/v/@weave_protocol/langchain.svg?label=langchain)](https://www.npmjs.com/package/@weave_protocol/langchain)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/langchain.svg)](https://www.npmjs.com/package/@weave_protocol/langchain)
[![npm](https://img.shields.io/npm/v/@weave_protocol/api.svg?label=api)](https://www.npmjs.com/package/@weave_protocol/api)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/api.svg)](https://www.npmjs.com/package/@weave_protocol/api)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A TypeScript monorepo providing security, encryption, compliance, and governance tools for AI agent systems. Built for the Model Context Protocol (MCP) ecosystem.

---

## 🆕 What's New

### 🛂 Tollere - Supply Chain Security (v0.1.0)

> *Old English `tollere` — the customs inspector who stood at the gate and examined every good crossing the boundary.*

Catch typosquats, CVEs, and compromised maintainers **before** `npm install` completes. Built for the era of AI coding agents that install dependencies at machine speed with zero human review.

```bash
# Scan a project
npx @weave_protocol/tollere scan

# Check a single package before installing
npx @weave_protocol/tollere check axios 1.7.2

# Detect typosquats (e.g., raect → react)
npx @weave_protocol/tollere typosquat raect

# Compare two versions for suspicious changes (the "Axios case" detector)
npx @weave_protocol/tollere diff axios 1.7.0 1.7.1
```

**Detects:** typosquats, CVEs (via OSV.dev), low-reputation maintainers, brand-new packages, suspicious version diffs (new install scripts, injected deps, obfuscated code).

**[See Tollere README →](./tollere)**

---

### Python/LlamaIndex Integration (v0.1.0)

Security scanning for LlamaIndex applications:

```python
from weave_protocol_llamaindex import WeaveSecurityHandler
from llama_index.core.callbacks import CallbackManager
from llama_index.core import Settings

# Attach security handler globally
Settings.callback_manager = CallbackManager([WeaveSecurityHandler()])

# All LlamaIndex operations now scanned!
# Prompts, responses, retrievals - threats auto-blocked
```

Features: Callback handler, secure tools, secure retriever, PII redaction

**[See LlamaIndex README →](./llamaindex-py)**

---

### LangChain.js Integration (v1.0.1)

Drop-in security for LangChain.js applications:

```typescript
import { WeaveSecurityCallback } from '@weave_protocol/langchain';

const chain = new LLMChain({
  llm: new ChatOpenAI(),
  prompt,
  callbacks: [new WeaveSecurityCallback({ action: 'block' })],
});

// Threats in input/output automatically blocked
await chain.invoke({ question: 'Ignore previous instructions...' });
// Error: [WeaveSecurityCallback] Blocked: Threat detected
```

**Features:** Callback handler, secure tool wrappers, RAG document scanning, PII redaction

[See LangChain README →](./langchain/README.md)

### Automated Threat Intelligence (Mund v0.2.2)

```
┌───────────────────────────────────────────────────────────────┐
│  mund_intel_status                                            │
│                                                               │
│  Sources: 3 enabled (2 auto-updating)                         │
│  Patterns: 47 total across 7 categories                       │
│  MITRE: 10 techniques, 6 tactics covered                      │
│                                                               │
│  ✅ weave_builtin    20 patterns (core)                       │
│  ✅ weave_community  15 patterns (auto-update: 24h)           │
│  ✅ mitre_llm        12 patterns (auto-update: 7d)            │
└───────────────────────────────────────────────────────────────┘
```

**New threat intel tools:** `mund_update_threat_intel`, `mund_intel_status`, `mund_threat_scan`, `mund_list_intel_sources`

[See Mund README →](./mund/README.md)

---

## 📦 Packages

| Package | Version | Description |
|---------|---------|-------------|
| [🛡️ @weave_protocol/mund](./mund) | 0.2.2 | Security scanner - secrets, PII, injection, MCP vetting, **threat intel** |
| [🏛️ @weave_protocol/hord](./hord) | 0.1.6 | Encrypted vault with Yoxallismus cipher |
| [⚖️ @weave_protocol/domere](./domere) | 1.3.4 | Compliance (PCI-DSS, ISO27001, SOC2, HIPAA, **GDPR**, **CCPA**) & verification |
| [👥 @weave_protocol/witan](./witan) | 1.0.2 | Multi-agent consensus & governance |
| [🔍 @weave_protocol/hundredmen](./hundredmen) | 1.0.6 | **Real-time MCP proxy** - intercept, scan, gate tool calls |
| [🛂 @weave_protocol/tollere](./tollere) | 0.1.0 | **Supply chain security** - typosquats, CVEs, maintainer reputation, version diffs |
| [🔗 @weave_protocol/langchain](./langchain) | 1.0.1 | **LangChain.js** security callbacks & tool wrappers |
| [🐍 weave-protocol-llamaindex](./llamaindex-py) | 0.1.0 | **Python/LlamaIndex** security callbacks & tools |
| [🔌 @weave_protocol/api](./api) | 1.0.12 | REST API for all packages |

---

## 🤖 AI Agent Skills

Each package includes a `SKILL.md` file following the [Claude Agent Skills specification](https://docs.anthropic.com/en/docs/claude-code/skills). These teach AI agents how to use Weave Protocol tools effectively.

| Package | Skill Name | Triggers |
|---------|------------|----------|
| 🛡️ Mund | `security-scanning` | scan, detect secrets, check injection, vet MCP server, threat intel |
| 🏛️ Hord | `encrypting-data` | encrypt, decrypt, vault, Yoxallismus, protect |
| ⚖️ Domere | `compliance-auditing` | audit, checkpoint, SOC2, HIPAA, PCI-DSS, GDPR, blockchain |
| 👥 Witan | `consensus-governance` | consensus, vote, approve, policy, escalate |
| 🔍 Hundredmen | `security-inspection` | intercept, drift, reputation, approve, block, live feed |
| 🛂 Tollere | `supply-chain-security` | npm install, dependency check, typosquat, CVE, package audit |
| 🔗 Langchain | `langchain-security` | LangChain, callback, secure tool, RAG security, PII redaction |
| 🔌 API | `weave-api-calling` | REST API, HTTP endpoint, curl, fetch |

**Installation:**

Copy skill files to your Claude skills directory:

```bash
# Clone repo
git clone https://github.com/Tyox-all/Weave_Protocol.git

# Copy skills to Claude Code
mkdir -p ~/.claude/skills/weave-protocol
cp Weave_Protocol/*/SKILL.md ~/.claude/skills/weave-protocol/

# Or for Claude.ai (upload as custom skills)
# Settings > Features > Custom Skills > Upload ZIP
```

Once installed, Claude automatically invokes the appropriate skill when you ask it to scan content, encrypt data, create compliance checkpoints, or coordinate multi-agent consensus.

---

## 🚀 Quick Start

### Install All Packages

```bash
npm install @weave_protocol/mund @weave_protocol/hord @weave_protocol/domere @weave_protocol/hundredmen @weave_protocol/tollere @weave_protocol/langchain
```

### Claude Desktop Integration

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mund": {
      "command": "npx",
      "args": ["-y", "@weave_protocol/mund"]
    },
    "hord": {
      "command": "npx",
      "args": ["-y", "@weave_protocol/hord"]
    },
    "domere": {
      "command": "npx",
      "args": ["-y", "@weave_protocol/domere"]
    },
    "hundredmen": {
      "command": "npx",
      "args": ["-y", "@weave_protocol/hundredmen"]
    },
    "tollere": {
      "command": "npx",
      "args": ["-y", "@weave_protocol/tollere"]
    }
  }
}
```

### MCP Registry

Mund is available on the official MCP Registry:

```bash
# Search for it
https://registry.modelcontextprotocol.io
# Server ID: io.github.Tyox-all/mund
```

---

## ✨ Package Details

### 🛡️ Mund - The Guardian

Real-time security scanning for AI agents.

| Category | Features |
|----------|----------|
| **Secrets** | API keys, tokens, passwords, certificates (30+ patterns) |
| **PII** | SSN, credit cards, emails, phone numbers, addresses |
| **Injection** | Prompt injection, jailbreak attempts, instruction override |
| **Exfiltration** | Data leakage, encoding tricks, steganography |
| **Code** | Dangerous patterns, eval/exec, SQL injection, XSS |
| **MCP Servers** | Malicious tool descriptions, typosquatting, dangerous permissions |
| **Threat Intel** | MITRE ATT&CK patterns, community feeds, auto-updates |

```typescript
// Scan content
const result = await mund.scan("Here's my key: sk-abc123...");
// { safe: false, issues: [{ severity: "critical", ... }] }

// Scan MCP server before install
const serverScan = await mund.scanMcpServer(serverJson);
// { recommendation: "DO_NOT_INSTALL", issues: [...] }

// Check threat intel status
const status = await mund.intelStatus();
// { patterns: 47, mitre_techniques: 10, sources: 3 }
```

📄 **Skill:** [`security-scanning`](./mund/SKILL.md)

---

### 🏛️ Hord - The Vault

Encrypted storage with the Yoxallismus dual-tumbler cipher.

| Category | Features |
|----------|----------|
| **Encryption** | AES-256-GCM, ChaCha20-Poly1305 |
| **Key Derivation** | Argon2id with configurable parameters |
| **Yoxallismus** | Dual-layer tumbler/deadbolt obfuscation |
| **Memory Safety** | Secure buffer handling, auto-zeroing |
| **MCP Server** | Claude Desktop integration, vault management tools |

```typescript
import { YoxallismusCipher } from '@weave_protocol/hord';

const cipher = new YoxallismusCipher('master-key');

// Lock (encrypt + obfuscate)
const locked = await cipher.lock(sensitiveData);

// Unlock (de-obfuscate + decrypt)
const unlocked = await cipher.unlock(locked);
```

**Yoxallismus Cipher:** A dual-layer encryption combining AES-256-GCM with tumbler/deadbolt obfuscation. Data is first encrypted, then the ciphertext is scrambled using position-dependent transformations that require both the key and the original encryption context to reverse.

📄 **Skill:** [`encrypting-data`](./hord/SKILL.md)

---

### ⚖️ Domere - The Judge

Enterprise-grade verification, orchestration, compliance, and audit infrastructure.

| Category | Features |
|----------|----------|
| **Verification** | Intent tracking, drift detection, execution replay, multi-agent handoff |
| **Orchestration** | Task scheduler, agent registry, shared state with locks |
| **Compliance** | SOC2, HIPAA, PCI-DSS, ISO27001, **GDPR** checkpoints & reporting |
| **Blockchain** | Solana & Ethereum anchoring for immutable audit trails |

**Blockchain Anchoring:**
- Solana Mainnet: `6g7raTAHU2h331VKtfVtkS5pmuvR8vMYwjGsZF1CUj2o`
- Solana Devnet: `BeCYVJYfbUu3k2TPGmh9VoGWeJwzm2hg2NdtnvbdBNCj`
- Ethereum: `0xAA8b52adD3CEce6269d14C6335a79df451543820`

```typescript
import { ComplianceManager } from '@weave_protocol/domere';

const compliance = new ComplianceManager(['pci-dss', 'iso27001', 'soc2', 'hipaa']);

// Create tamper-evident checkpoint
const checkpoint = await compliance.createCheckpoint({
  action: 'data_access',
  resource: 'customer_records',
  actor: 'agent-001'
});

// Generate audit report
const report = await compliance.generateReport('pci-dss', {
  startDate: '2024-01-01',
  endDate: '2024-12-31'
});
```

📄 **Skill:** [`compliance-auditing`](./domere/SKILL.md)

---

### 👥 Witan - The Council

Multi-agent consensus and governance.

| Category | Features |
|----------|----------|
| **Consensus** | Unanimous, majority, weighted, quorum protocols |
| **Policy** | Rule enforcement, permission management, escalation |
| **Communication** | Agent bus, broadcast, point-to-point messaging |
| **Recovery** | Failure detection, automatic failover, state recovery |

```typescript
import { ConsensusEngine, PolicyEngine } from '@weave_protocol/witan';

const consensus = new ConsensusEngine({
  protocol: 'weighted_majority',
  threshold: 0.66,
  timeout: 30000
});

// Propose action requiring consensus
const result = await consensus.propose({
  action: 'deploy_to_production',
  requiredApprovals: ['security-agent', 'qa-agent', 'ops-agent']
});
```

📄 **Skill:** [`consensus-governance`](./witan/SKILL.md)

---

### 🔍 Hundredmen - The Watchers

Real-time MCP security proxy that intercepts, scans, and gates AI agent tool calls.

| Category | Features |
|----------|----------|
| **Interception** | Proxy all MCP tool calls in real-time |
| **Drift Detection** | "Said X, doing Y" analysis - catch unauthorized actions |
| **Reputation** | Server trust scores, community reports, malicious detection |
| **Manual Gates** | Require approval for high-risk operations |
| **Live Feed** | Real-time stream of agent activity |

```typescript
import { Interceptor, ReputationManager } from '@weave_protocol/hundredmen';

const interceptor = new Interceptor({
  mode: 'active',           // 'passive' | 'active' | 'strict'
  driftDetectionEnabled: true,
  reputationEnabled: true,
  minReputationScore: 30,
});

// Create session and declare intent
const session = interceptor.createSession('my-agent');
interceptor.declareIntent(session.id, 'Read and summarize the README file');

// Intercept a tool call
const call = await interceptor.intercept(
  session.id,
  'filesystem',
  'read_file',
  { path: '/README.md' }
);

// Check decision
if (call.status === 'approved') {
  // Execute the actual call
} else if (call.status === 'pending') {
  console.log('Manual approval required:', call.decisionReason);
} else {
  console.log('Blocked:', call.decisionReason);
}
```

📄 **Skill:** [`security-inspection`](./hundredmen/SKILL.md)

---

### 🛂 Tollere - The Customs Inspector

Supply chain security for AI-generated code. Catches malicious packages **before** they reach `node_modules/`.

| Category | Features |
|----------|----------|
| **Typosquats** | Edit-distance + pattern matching against popular packages (raect → react, lodahs → lodash) |
| **CVEs** | Live queries against OSV.dev (GHSA, PyPA, npm advisories, etc.) |
| **Maintainer Reputation** | 0-100 score based on account age, repo links, license, activity |
| **Version Diffs** | Detects new install scripts, injected deps, obfuscated code (the Axios attack pattern) |
| **Multi-Ecosystem** | npm, PyPI, Cargo, Go, Maven |
| **CLI + MCP + SDK** | Three ways to integrate: command line, Claude Desktop, programmatic |

```typescript
import { scanPackage, scanPackageJson } from '@weave_protocol/tollere';

// Scan one package before installing
const risk = await scanPackage('axios', '1.7.2');
if (risk.riskLevel === 'block') {
  throw new Error(`Blocked: ${risk.issues[0].description}`);
}

// Scan an entire package.json
const report = await scanPackageJson(packageJsonContents);
console.log(`Recommendation: ${report.recommendation}`);
// → "BLOCK_INSTALL" | "REVIEW_REQUIRED" | "PROCEED"
```

> *"Every install is a transaction. Tollere is the customs inspector."*

📄 **Skill:** [`supply-chain-security`](./tollere/SKILL.md)

---

### 🔗 Langchain - The Bridge

Security integration for LangChain.js applications.

| Category | Features |
|----------|----------|
| **Callbacks** | Drop-in `WeaveSecurityCallback` for any chain/agent |
| **Tool Wrappers** | Wrap tools with threat scanning and approval gates |
| **Retrievers** | Scan RAG documents, auto-redact PII |
| **Presets** | Strict, warning, and production configurations |

```typescript
import { WeaveSecurityCallback, createSecureRetriever } from '@weave_protocol/langchain';

// Callback for any LangChain component
const callback = new WeaveSecurityCallback({
  action: 'block',        // block | warn | log
  minSeverity: 'medium',
  scanTools: true,
  scanRetrievers: true,
});

// Secure RAG retriever with PII redaction
const secureRetriever = createSecureRetriever(vectorStore.asRetriever(), {
  name: 'company-docs',
  scanDocuments: true,
  redactSensitive: true,
});
```

📄 **Skill:** [`langchain-security`](./langchain/SKILL.md)

---

## 🏗️ Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                       AI Agent System                         │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │  🛡️ Mund │  │ 🏛️ Hord  │  │ ⚖️ Domere│  │ 👥 Witan │      │
│  │ Guardian │  │  Vault   │  │  Judge   │  │ Council  │      │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘      │
│       │             │             │             │             │
│  Security      Encryption    Compliance     Consensus        │
│  Scanning      Storage       Verification   Governance       │
│       │             │             │             │             │
│       └─────────────┴─────────────┴─────────────┘             │
│                           │                                   │
│  ┌──────────────┐  ┌──────┴──────┐  ┌──────────────┐         │
│  │🔍 Hundredmen │  │ 🛂 Tollere  │  │  🔌 API      │         │
│  │  Watchers    │  │   Customs   │  │   REST       │         │
│  └──────────────┘  └─────────────┘  └──────────────┘         │
│        │                  │                  │                │
│  Runtime Calls    Supply Chain        Universal Access        │
│        │                  │                  │                │
│        └──────────────────┴──────────────────┘                │
│                           │                                   │
│                    ┌──────┴───────┐                           │
│                    │ 🔗 Langchain │                           │
│                    │   Bridge     │                           │
│                    └──────────────┘                           │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

---

## 🔌 REST API

The `@weave_protocol/api` package provides HTTP endpoints for all functionality:

```bash
# Start the API server
npx @weave_protocol/api

# Or with Docker
docker run -p 3000:3000 weave-protocol/api
```

**Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/mund/scan` | Scan content for security issues |
| POST | `/mund/scan-mcp-server` | Scan MCP server manifest |
| POST | `/hord/encrypt` | Encrypt data |
| POST | `/hord/decrypt` | Decrypt data |
| POST | `/hord/yoxallismus/lock` | Lock with Yoxallismus cipher |
| POST | `/hord/yoxallismus/unlock` | Unlock with Yoxallismus cipher |
| POST | `/domere/checkpoint` | Create compliance checkpoint |
| GET | `/domere/compliance/frameworks` | List available frameworks |
| POST | `/domere/compliance/report` | Generate compliance report |

📄 **Skill:** [`weave-api-calling`](./api/SKILL.md)

---

## 🔐 Security Model

Weave Protocol implements defense-in-depth across the entire AI agent lifecycle:

1. **🛂 Tollere** inspects every dependency before it enters your project
2. **🛡️ Mund** scans all inputs for threats before processing
3. **🏛️ Hord** encrypts sensitive data at rest and in transit
4. **⚖️ Domere** logs all actions with tamper-evident checksums
5. **👥 Witan** requires consensus for high-risk operations
6. **🔍 Hundredmen** intercepts and gates tool calls in real-time
7. **🔗 Langchain** secures LangChain.js chains and agents

### CORS Model Integration

The Weave Protocol maps to the CORS Model for AI agent security:

| CORS Layer | Weave Package | Function |
|------------|---------------|----------|
| **Supply Chain** | 🛂 Tollere | Vets dependencies before install |
| **Origin Validation** | 🛡️ Mund | Validates input sources, detects injection |
| **Context Integrity** | 🏛️ Hord | Protects data integrity through encryption |
| **Deterministic Enforcement** | ⚖️ Domere | Ensures consistent policy application |
| **Runtime Interception** | 🔍 Hundredmen | Gates tool calls, detects drift |

---

## 🛠️ Development

```bash
# Clone
git clone https://github.com/Tyox-all/Weave_Protocol.git
cd Weave_Protocol

# Install dependencies (each package)
cd mund && npm install && npm run build
cd ../hord && npm install && npm run build
cd ../domere && npm install && npm run build
cd ../hundredmen && npm install && npm run build
cd ../tollere && npm install && npm run build
cd ../langchain && npm install && npm run build

# Run tests
npm test
```

---

## 🗺️ Roadmap

- [x] GDPR compliance framework
- [x] MCP server reputation scoring
- [x] Automated threat intelligence updates
- [x] LangChain.js integration package
- [x] Python/LlamaIndex integration
- [x] Web dashboard for monitoring
- [x] CCPA compliance framework
- [x] Supply chain security (Tollere)

*H2 2026 roadmap under consideration — deep dive planning session coming soon.*

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📄 License

Apache 2.0 - See [LICENSE](LICENSE)

---

## 🔗 Links

- **GitHub:** https://github.com/Tyox-all/Weave_Protocol
- **npm (mund):** https://www.npmjs.com/package/@weave_protocol/mund
- **npm (hord):** https://www.npmjs.com/package/@weave_protocol/hord
- **npm (domere):** https://www.npmjs.com/package/@weave_protocol/domere
- **npm (witan):** https://www.npmjs.com/package/@weave_protocol/witan
- **npm (hundredmen):** https://www.npmjs.com/package/@weave_protocol/hundredmen
- **npm (tollere):** https://www.npmjs.com/package/@weave_protocol/tollere
- **npm (langchain):** https://www.npmjs.com/package/@weave_protocol/langchain
- **npm (api):** https://www.npmjs.com/package/@weave_protocol/api
- **MCP Registry:** https://registry.modelcontextprotocol.io (search "mund")

---

*Built with ❤️ for the AI agent ecosystem.*
