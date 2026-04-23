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

### 🛂 Tollere v0.2.2 — Multi-Channel Supply Chain Security

> *Old English `tollere` — the customs inspector who stood at the gate and examined every good crossing the boundary.*

Catches typosquats, CVEs, compromised maintainers, **Docker tag overwriting**, **IDE extension impersonation**, and **sandwich-pattern attacks** before the install completes. Validated against the real-world Checkmarx KICS supply chain compromise (April 2026) — Tollere catches the v2.1.20 tag reassignment in real-time.

```bash
npx @weave_protocol/tollere scan                          # scan package.json
npx @weave_protocol/tollere docker checkmarx/kics:v2.1.20 # 🆕 Docker images
npx @weave_protocol/tollere ext ms-python.python vscode   # 🆕 IDE extensions
npx @weave_protocol/tollere sandwich some-package         # 🆕 sandwich pattern
```

**Coverage:** npm, PyPI, Cargo, Go, Maven, Docker Hub, VS Code Marketplace (covers Cursor + Windsurf), Open VSX (VSCodium/Gitpod), JetBrains Marketplace (IntelliJ/PyCharm/WebStorm/etc).

**[See Tollere README →](./tollere)**

---

### 📊 Web Dashboard for Monitoring (API v1.0.12)

Real-time security monitoring UI bundled with the API package:

```bash
npx @weave_protocol/api
# → Open http://localhost:3000/dashboard
```

Live activity feed, threat intel status, compliance frameworks, MCP server reputation. **[See API README →](./api)**

---

### 🐍 Python/LlamaIndex Integration (v0.1.0)

Security scanning for LlamaIndex applications:

```python
from weave_protocol_llamaindex import WeaveSecurityHandler
from llama_index.core.callbacks import CallbackManager
from llama_index.core import Settings

Settings.callback_manager = CallbackManager([WeaveSecurityHandler()])
# All LlamaIndex operations now scanned - threats auto-blocked
```

**[See LlamaIndex README →](./llamaindex-py)**

---

### 🔗 LangChain.js Integration (v1.0.1)

Drop-in security for LangChain.js applications:

```typescript
import { WeaveSecurityCallback } from '@weave_protocol/langchain';

const chain = new LLMChain({
  llm: new ChatOpenAI(),
  prompt,
  callbacks: [new WeaveSecurityCallback({ action: 'block' })],
});
```

**[See LangChain README →](./langchain/README.md)**

---

## 📦 Packages

| Package | Version | Description |
|---------|---------|-------------|
| [🛡️ @weave_protocol/mund](./mund) | 0.2.2 | Security scanner - secrets, PII, injection, MCP vetting, **threat intel** |
| [🏛️ @weave_protocol/hord](./hord) | 0.1.6 | Encrypted vault with Yoxallismus cipher |
| [⚖️ @weave_protocol/domere](./domere) | 1.3.4 | Compliance (PCI-DSS, ISO27001, SOC2, HIPAA, **GDPR**, **CCPA**) & verification |
| [👥 @weave_protocol/witan](./witan) | 1.0.2 | Multi-agent consensus & governance |
| [🔍 @weave_protocol/hundredmen](./hundredmen) | 1.0.6 | **Real-time MCP proxy** - intercept, scan, gate tool calls |
| [🛂 @weave_protocol/tollere](./tollere) | 0.2.2 | **Supply chain security** - npm, Docker images, IDE extensions, sandwich pattern detection |
| [🔗 @weave_protocol/langchain](./langchain) | 1.0.1 | **LangChain.js** security callbacks & tool wrappers |
| [🐍 weave-protocol-llamaindex](./llamaindex-py) | 0.1.0 | **Python/LlamaIndex** security callbacks & tools |
| [🔌 @weave_protocol/api](./api) | 1.0.12 | REST API for all packages + **dashboard** |

---

## 🤖 AI Agent Skills

Each package includes a `SKILL.md` file following the [Claude Agent Skills specification](https://docs.anthropic.com/en/docs/claude-code/skills). These teach AI agents how to use Weave Protocol tools effectively.

| Package | Skill Name | Triggers |
|---------|------------|----------|
| 🛡️ Mund | `security-scanning` | scan, detect secrets, check injection, vet MCP server, threat intel |
| 🏛️ Hord | `encrypting-data` | encrypt, decrypt, vault, Yoxallismus, protect |
| ⚖️ Domere | `compliance-auditing` | audit, checkpoint, SOC2, HIPAA, PCI-DSS, GDPR, CCPA, blockchain |
| 👥 Witan | `consensus-governance` | consensus, vote, approve, policy, escalate |
| 🔍 Hundredmen | `security-inspection` | intercept, drift, reputation, approve, block, live feed |
| 🛂 Tollere | `supply-chain-security` | npm install, docker pull, install extension, dependency check, typosquat, CVE, sandwich pattern |
| 🔗 Langchain | `langchain-security` | LangChain, callback, secure tool, RAG security, PII redaction |
| 🔌 API | `weave-api-calling` | REST API, HTTP endpoint, curl, fetch |

**Installation:**

```bash
git clone https://github.com/Tyox-all/Weave_Protocol.git
mkdir -p ~/.claude/skills/weave-protocol
cp Weave_Protocol/*/SKILL.md ~/.claude/skills/weave-protocol/
```

Once installed, Claude automatically invokes the appropriate skill for each task.

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
    "mund":       { "command": "npx", "args": ["-y", "@weave_protocol/mund"] },
    "hord":       { "command": "npx", "args": ["-y", "@weave_protocol/hord"] },
    "domere":     { "command": "npx", "args": ["-y", "@weave_protocol/domere"] },
    "hundredmen": { "command": "npx", "args": ["-y", "@weave_protocol/hundredmen"] },
    "tollere":    { "command": "npx", "args": ["-y", "@weave_protocol/tollere"] }
  }
}
```

---

## ✨ Package Details

### 🛡️ Mund — The Guardian

Real-time security scanning for AI agents.

| Category | Features |
|----------|----------|
| **Secrets** | API keys, tokens, passwords, certificates (30+ patterns) |
| **PII** | SSN, credit cards, emails, phone numbers, addresses |
| **Injection** | Prompt injection, jailbreak attempts, instruction override |
| **Code** | Dangerous patterns, eval/exec, SQL injection, XSS |
| **MCP Servers** | Malicious tool descriptions, typosquatting, dangerous permissions |
| **Threat Intel** | MITRE ATT&CK patterns, community feeds, auto-updates |

📄 **Skill:** [`security-scanning`](./mund/SKILL.md)

---

### 🏛️ Hord — The Vault

Encrypted storage with the Yoxallismus dual-tumbler cipher.

| Category | Features |
|----------|----------|
| **Encryption** | AES-256-GCM, ChaCha20-Poly1305 |
| **Key Derivation** | Argon2id with configurable parameters |
| **Yoxallismus** | Dual-layer tumbler/deadbolt obfuscation |
| **Memory Safety** | Secure buffer handling, auto-zeroing |

📄 **Skill:** [`encrypting-data`](./hord/SKILL.md)

---

### ⚖️ Domere — The Judge

Enterprise-grade verification, orchestration, compliance, and audit infrastructure.

| Category | Features |
|----------|----------|
| **Verification** | Intent tracking, drift detection, execution replay |
| **Compliance** | SOC2, HIPAA, PCI-DSS, ISO27001, **GDPR**, **CCPA** |
| **Blockchain** | Solana & Ethereum anchoring for immutable audit trails |

**Blockchain Anchoring:**
- Solana Mainnet: `6g7raTAHU2h331VKtfVtkS5pmuvR8vMYwjGsZF1CUj2o`
- Solana Devnet: `BeCYVJYfbUu3k2TPGmh9VoGWeJwzm2hg2NdtnvbdBNCj`
- Ethereum: `0xAA8b52adD3CEce6269d14C6335a79df451543820`

📄 **Skill:** [`compliance-auditing`](./domere/SKILL.md)

---

### 👥 Witan — The Council

Multi-agent consensus and governance.

| Category | Features |
|----------|----------|
| **Consensus** | Unanimous, majority, weighted, quorum protocols |
| **Policy** | Rule enforcement, permission management, escalation |
| **Communication** | Agent bus, broadcast, point-to-point messaging |

📄 **Skill:** [`consensus-governance`](./witan/SKILL.md)

---

### 🔍 Hundredmen — The Watchers

Real-time MCP security proxy that intercepts, scans, and gates AI agent tool calls.

| Category | Features |
|----------|----------|
| **Interception** | Proxy all MCP tool calls in real-time |
| **Drift Detection** | "Said X, doing Y" - catch unauthorized actions |
| **Reputation** | Server trust scores, community reports |
| **Manual Gates** | Require approval for high-risk operations |

📄 **Skill:** [`security-inspection`](./hundredmen/SKILL.md)

---

### 🛂 Tollere — The Customs Inspector

Supply chain security for AI-generated code. Catches malicious packages, Docker images, and IDE extensions **before** they reach `node_modules/`, your container, or your editor.

| Surface | Coverage |
|---------|----------|
| **Packages** | npm, PyPI, Cargo, Go, Maven (typosquats, CVEs, maintainer reputation) |
| **🆕 Sandwich Pattern** | Malicious code hidden between a clean "filling" version (Checkmarx attack pattern) |
| **🆕 Docker Images** | Tag overwrite detection, phantom tags (Docker Hub) |
| **🆕 IDE Extensions** | VS Code (Cursor, Windsurf), Open VSX (VSCodium, Gitpod), JetBrains (IntelliJ, PyCharm, WebStorm, etc.) |

```bash
npx @weave_protocol/tollere scan
npx @weave_protocol/tollere docker checkmarx/kics:v2.1.20
npx @weave_protocol/tollere ext ms-python.python vscode
```

📄 **Skill:** [`supply-chain-security`](./tollere/SKILL.md)

---

### 🔗 Langchain — The Bridge

Security integration for LangChain.js applications.

| Category | Features |
|----------|----------|
| **Callbacks** | Drop-in `WeaveSecurityCallback` for any chain/agent |
| **Tool Wrappers** | Wrap tools with threat scanning and approval gates |
| **Retrievers** | Scan RAG documents, auto-redact PII |

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
│       │             │             │             │             │
│       └─────────────┴─────────────┴─────────────┘             │
│                           │                                   │
│  ┌──────────────┐  ┌──────┴──────┐  ┌──────────────┐         │
│  │🔍 Hundredmen │  │ 🛂 Tollere  │  │  🔌 API      │         │
│  │  Watchers    │  │   Customs   │  │  REST + UI   │         │
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

## 🔐 Security Model

Defense-in-depth across the entire AI agent lifecycle:

1. **🛂 Tollere** inspects every dependency, image, and extension before it enters your project
2. **🛡️ Mund** scans all inputs for threats before processing
3. **🏛️ Hord** encrypts sensitive data at rest and in transit
4. **⚖️ Domere** logs all actions with tamper-evident checksums
5. **👥 Witan** requires consensus for high-risk operations
6. **🔍 Hundredmen** intercepts and gates tool calls in real-time
7. **🔗 Langchain** secures LangChain.js chains and agents

### CORS Model Integration

| CORS Layer | Weave Package | Function |
|------------|---------------|----------|
| **Supply Chain** | 🛂 Tollere | Vets dependencies, images, extensions before install |
| **Origin Validation** | 🛡️ Mund | Validates input sources, detects injection |
| **Context Integrity** | 🏛️ Hord | Protects data integrity through encryption |
| **Deterministic Enforcement** | ⚖️ Domere | Ensures consistent policy application |
| **Runtime Interception** | 🔍 Hundredmen | Gates tool calls, detects drift |

---

## 🛠️ Development

```bash
git clone https://github.com/Tyox-all/Weave_Protocol.git
cd Weave_Protocol

# Build each package
for pkg in mund hord domere witan hundredmen tollere langchain api; do
  (cd $pkg && npm install && npm run build)
done
```

---

## 🗺️ Roadmap

### Shipped
- [x] GDPR compliance framework
- [x] CCPA compliance framework
- [x] MCP server reputation scoring
- [x] Automated threat intelligence updates
- [x] LangChain.js integration package
- [x] Python/LlamaIndex integration
- [x] Web dashboard for monitoring
- [x] Supply chain security (Tollere) — npm, PyPI, Cargo, Go, Maven
- [x] Multi-channel supply chain — Docker images + IDE extensions + sandwich pattern detection

### H2 2026 Q3 — Adoption Quarter
- [ ] Bundle package + CLI (`weave init`)
- [ ] Browser agent security (`@weave_protocol/browser`)
- [ ] State of AI Agent Security: Q3 Report

### H2 2026 Q4 — Moat Quarter
- [ ] Adversarial agents (`@weave_protocol/adversary`)
- [ ] Yoxallismus v2 (multi-agent, memory-aware cipher)
- [ ] Witan killer use case: autonomous spending caps
- [ ] AgentSecBench (open benchmark + leaderboard)

---

## 🤝 Contributing

Bug reports and feature requests welcome via [GitHub Issues](https://github.com/Tyox-all/Weave_Protocol/issues).

For security issues, please see [SECURITY.md](./SECURITY.md).

For all other inquiries: **TYox-all@tutamail.com**

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

---

## 📄 License

Apache 2.0 — See [LICENSE](./LICENSE)

---

## 🔗 Links

- **GitHub:** https://github.com/Tyox-all/Weave_Protocol
- **npm packages:** https://www.npmjs.com/~tyox-all
- **PyPI:** https://pypi.org/project/weave-protocol-llamaindex/
- **MCP Registry:** https://registry.modelcontextprotocol.io (search "mund")

---

*Built with ❤️ for the AI agent ecosystem.*
