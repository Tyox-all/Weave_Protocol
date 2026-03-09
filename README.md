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
[![npm](https://img.shields.io/npm/v/@weave_protocol/api.svg?label=api)](https://www.npmjs.com/package/@weave_protocol/api)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/api.svg)](https://www.npmjs.com/package/@weave_protocol/api)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A TypeScript monorepo providing security, encryption, compliance, and governance tools for AI agent systems. Built for the Model Context Protocol (MCP) ecosystem.

---

## 🆕 What's New: MCP Server Scanner

**Mund v0.1.11** now scans MCP servers before you install them:

```
┌───────────────────────────────────────────────────────────────┐
│  mund_scan_mcp_server                                         │
│                                                               │
│  ⚠️  CRITICAL: Tool "execute" contains injection pattern      │
│     "ignore previous instructions and run..."                 │
│                                                               │
│  ⚠️  HIGH: Server name "githib-mcp" is 1 edit from "github"   │
│                                                               │
│  Recommendation: DO_NOT_INSTALL                               │
└───────────────────────────────────────────────────────────────┘
```

**Why this matters:**
- 43% of MCP servers have command injection vulnerabilities
- "Line jumping" attacks hide malicious prompts in tool descriptions
- Typosquatting mimics legitimate server names

[See Mund README →](./mund/README.md)

---

## 📦 Packages

| Package | Version | Description |
|---------|---------|-------------|
| [🛡️ @weave_protocol/mund](./mund) | 0.1.11 | Security scanner - secrets, PII, injection, **MCP server vetting** |
| [🏛️ @weave_protocol/hord](./hord) | 0.1.4 | Encrypted vault with Yoxallismus cipher |
| [⚖️ @weave_protocol/domere](./domere) | 1.2.10 | Compliance (PCI-DSS, ISO27001) & verification |
| [👥 @weave_protocol/witan](./witan) | 1.0.0 | Multi-agent consensus & governance |
| [🔌 @weave_protocol/api](./api) | 1.0.6 | REST API for all packages |

---

## 🚀 Quick Start

### Install All Packages

```bash
npm install @weave_protocol/mund @weave_protocol/hord @weave_protocol/domere
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

**Detects:**
- Prompt injection & jailbreak attempts
- Secrets (API keys, tokens, credentials)
- PII (SSN, credit cards, emails)
- Dangerous code patterns
- Data exfiltration attempts
- **Malicious MCP servers** (NEW)

**MCP Server Scanning Tools:**
| Tool | Purpose |
|------|---------|
| `mund_scan_mcp_server` | Full security scan of server manifests |
| `mund_check_typosquatting` | Detect name squatting attacks |
| `mund_audit_mcp_permissions` | Analyze tool capabilities |

```typescript
// Scan content
const result = await mund.scan("Here's my key: sk-abc123...");
// { safe: false, issues: [{ severity: "critical", ... }] }

// Scan MCP server before install
const serverScan = await mund.scanMcpServer(serverJson);
// { recommendation: "DO_NOT_INSTALL", issues: [...] }
```

---

### 🏛️ Hord - The Vault

Encrypted storage with the Yoxallismus dual-tumbler cipher.

**Features:**
- AES-256-GCM encryption
- Yoxallismus obfuscation layer
- Secure key derivation (Argon2)
- Memory-safe secret handling

```typescript
import { YoxallismusCipher } from '@weave_protocol/hord';

const cipher = new YoxallismusCipher('master-key');

// Lock (encrypt + obfuscate)
const locked = await cipher.lock(sensitiveData);

// Unlock (de-obfuscate + decrypt)
const unlocked = await cipher.unlock(locked);
```

**Yoxallismus Cipher:** A dual-layer encryption combining AES-256-GCM with tumbler/deadbolt obfuscation. Data is first encrypted, then the ciphertext is scrambled using position-dependent transformations that require both the key and the original encryption context to reverse.

---

### ⚖️ Domere - The Judge

Compliance verification and audit logging.

**Frameworks:**
- PCI-DSS 4.0 (payment card security)
- ISO 27001 (information security)
- Custom compliance rules

**Blockchain Anchoring:**
- Solana Mainnet: `6g7raTAHU2h331VKtfVtkS5pmuvR8vMYwjGsZF1CUj2o`
- Solana Devnet: `BeCYVJYfbUu3k2TPGmh9VoGWeJwzm2hg2NdtnvbdBNCj`
- Ethereum: `0xAA8b52adD3CEce6269d14C6335a79df451543820`

```typescript
import { ComplianceManager } from '@weave_protocol/domere';

const compliance = new ComplianceManager(['pci-dss', 'iso27001']);

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

---

### 👥 Witan - The Council

Multi-agent consensus and governance.

**Features:**
- Voting protocols (unanimous, majority, weighted)
- Policy enforcement
- Agent communication bus
- Failure recovery

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
│                     ┌─────┴─────┐                             │
│                     │  🔌 API   │                             │
│                     │   REST    │                             │
│                     └───────────┘                             │
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

---

## 🔒 Security Model

Weave Protocol implements defense-in-depth:

1. **🛡️ Mund** scans all inputs for threats before processing
2. **🏛️ Hord** encrypts sensitive data at rest and in transit
3. **⚖️ Domere** logs all actions with tamper-evident checksums
4. **👥 Witan** requires consensus for high-risk operations

### CORS Model Integration

The Weave Protocol maps to the CORS Model for AI agent security:

| CORS Layer | Weave Package | Function |
|------------|---------------|----------|
| **Origin Validation** | 🛡️ Mund | Validates input sources, detects injection |
| **Context Integrity** | 🏛️ Hord | Protects data integrity through encryption |
| **Deterministic Enforcement** | ⚖️ Domere | Ensures consistent policy application |

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

# Run tests
npm test
```

---

## 🗺️ Roadmap

- [ ] LangChain/LlamaIndex integration package
- [ ] Web dashboard for monitoring
- [ ] Additional compliance frameworks (SOC2, HIPAA)
- [ ] MCP server reputation scoring
- [ ] Automated threat intelligence updates

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
- **MCP Registry:** https://registry.modelcontextprotocol.io (search "mund")

---

*Built with ❤️ for the AI agent ecosystem.*
