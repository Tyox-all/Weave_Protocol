# 🕸️ Weave Protocol

**Enterprise Security Suite for AI Agents**

[![npm](https://img.shields.io/npm/v/@weave_protocol/cli.svg?label=cli)](https://www.npmjs.com/package/@weave_protocol/cli)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/cli.svg)](https://www.npmjs.com/package/@weave_protocol/cli)
[![npm](https://img.shields.io/npm/v/@weave_protocol/full.svg?label=full)](https://www.npmjs.com/package/@weave_protocol/full)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/full.svg)](https://www.npmjs.com/package/@weave_protocol/full)
[![npm](https://img.shields.io/npm/v/@weave_protocol/ward.svg?label=ward)](https://www.npmjs.com/package/@weave_protocol/ward)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/ward.svg)](https://www.npmjs.com/package/@weave_protocol/ward)
[![npm](https://img.shields.io/npm/v/@weave_protocol/adapter-claudecode.svg?label=adapter-claudecode)](https://www.npmjs.com/package/@weave_protocol/adapter-claudecode)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/adapter-claudecode.svg)](https://www.npmjs.com/package/@weave_protocol/adapter-claudecode)
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

A TypeScript monorepo providing security, encryption, compliance, and governance tools for AI agent systems. Built for the Model Context Protocol (MCP) ecosystem and the new generation of agent harness platforms.

---

## 🚀 Get started in one command

```bash
npx @weave_protocol/cli init
```

The CLI detects your framework (LangChain, LlamaIndex, MCP, OpenAI, Anthropic), asks which Weave Protocol packages you want, and scaffolds the right security middleware for your stack. Or install everything at once:

```bash
npm install @weave_protocol/full
```

---

## 🆕 What's New

### 🛡️ Claude Code adapter v0.1.0 — first cross-platform harness adapter

[`@weave_protocol/adapter-claudecode`](./adapter-claudecode) enforces WARD.md policies inside [Claude Code](https://docs.anthropic.com/en/docs/claude-code) via its native `PreToolUse` hook system. One-time install, then every Claude Code tool call is gated by your project's `WARD.md`.

```bash
# Install once
npm install -g @weave_protocol/adapter-claudecode
weave-claude-code init

# Drop a WARD.md in your project
npx @weave_protocol/ward init

# Now Claude Code refuses anything outside the declared policy
```

```
You: "Delete all the SSH keys"
Claude Code: [about to run Bash with `rm -rf ~/.ssh`]
       ↓ PreToolUse hook fires
       ↓ weave-claude-code reads ./WARD.md
       ↓ checkFilesystem('delete', '~/.ssh/**') → DENY
       ↓
Claude Code refuses: "🛡️  WARD: bash touches ~/.ssh"
```

WARD enforcement now lives in two places: **MCP servers** (via Hundredmen v1.1.0) and **Claude Code tool calls** (via this adapter). Cross-platform harness adapters for Google Antigravity and Microsoft MDASH are next on the roadmap.

**[See adapter-claudecode README →](./adapter-claudecode)**

---

### 🔍 Hundredmen v1.1.0 — WARD.md enforcement at the MCP layer

[Hundredmen](./hundredmen) now reads `WARD.md` files and **enforces them at the MCP interception layer**. WARD just stopped being a spec and started being infrastructure.

```
🔍 Weave Hundredmen MCP Server running
🛡️  WARD.md loaded from ./WARD.md (My Agent Security Policy)
```

```json
// A tool call that violates the policy
{
  "decision": "auto_blocked",
  "decisionReason": "WARD: Tool 'shell_exec' is in the deny list."
}
```

WARD becomes the first gate in Hundredmen's decision flow — ahead of reputation, drift, and approval checks. Filesystem and network checks fire automatically when tool args look like paths or URLs. **Zero config required** if you have a `WARD.md` in your project root.

**[See Hundredmen README →](./hundredmen)**

---

### 🛡️ WARD.md v0.1.0 — Agent Security Policy Standard

> *AGENTS.md tells your agent what to do. SKILL.md tells your agent how to do it. **WARD.md tells your agent what it can't.***

Agents are now infrastructure-as-code. They're defined in markdown files (`AGENTS.md`, `SKILL.md`), version-controlled, and shared across registries. **WARD.md** is the third file in that stack — a portable, declarative format for declaring the security policy of an AI agent.

```bash
npx @weave_protocol/ward init             # create a starter WARD.md
npx @weave_protocol/ward validate WARD.md # validate it (use in CI)
npx @weave_protocol/ward explain WARD.md  # human-readable policy summary
```

A WARD.md file declares ten policy domains: filesystem rules, network allowlists, capability gating, data egress boundaries, behavioral limits (iterations / runtime / cost / tokens), multi-agent trust chains, compliance frameworks, attestation requirements, threat model, and incident response. The format is portable across harness platforms.

**[See Ward README →](./ward)** · **[See the WARD.md spec →](./ward/SPEC.md)**

---

### 🕸️ Weave CLI v0.1.0 + Full Bundle v0.1.0

The **`weave`** command-line tool is live. One command sets up framework-specific security middleware:

```bash
weave init           # detect framework, scaffold security middleware
weave audit          # scan dependencies (delegates to Tollere)
weave dashboard      # launch monitoring UI
weave doctor         # environment health check
```

**[See CLI README →](./cli)** · **[See Full README →](./full)**

---

### 🛂 Tollere v0.2.2 — Multi-Channel Supply Chain Security

> *Old English `tollere` — the customs inspector who stood at the gate and examined every good crossing the boundary.*

Catches typosquats, CVEs, compromised maintainers, **Docker tag overwriting**, **IDE extension impersonation**, and **sandwich-pattern attacks** before the install completes. Validated against the real-world Checkmarx KICS supply chain compromise (April 2026) — Tollere catches the v2.1.20 tag reassignment in real-time.

```bash
npx @weave_protocol/tollere scan                          # scan package.json
npx @weave_protocol/tollere docker checkmarx/kics:v2.1.20 # Docker images
npx @weave_protocol/tollere ext ms-python.python vscode   # IDE extensions
npx @weave_protocol/tollere sandwich some-package         # sandwich pattern
```

**Coverage:** npm, PyPI, Cargo, Go, Maven, Docker Hub, VS Code Marketplace (covers Cursor + Windsurf), Open VSX (VSCodium/Gitpod), JetBrains Marketplace.

**[See Tollere README →](./tollere)**

---

### 📊 Web Dashboard, Python/LlamaIndex, and LangChain.js integrations

Also shipped:

- **Web Dashboard** (API v1.0.12) — live activity feed, threat intel, compliance, MCP reputation. `npx @weave_protocol/api` → http://localhost:3000/dashboard
- **Python/LlamaIndex** (`weave-protocol-llamaindex`) — drop-in security callbacks for LlamaIndex
- **LangChain.js** (`@weave_protocol/langchain`) — `WeaveSecurityCallback` for any chain or agent

---

## 📦 Packages

| Package | Version | Description |
|---------|---------|-------------|
| [🕸️ @weave_protocol/cli](./cli) | 0.1.0 | **The `weave` CLI** — `init`, `audit`, `dashboard`, `doctor` |
| [📦 @weave_protocol/full](./full) | 0.1.0 | **Bundle** — installs all packages in one command |
| [🛡️ @weave_protocol/ward](./ward) | 0.1.0 | **WARD.md** — agent security policy standard (parser, validator, runtime checks) |
| [🛡️ @weave_protocol/adapter-claudecode](./adapter-claudecode) | **0.1.0** | **🆕 Claude Code adapter** — enforces WARD.md via PreToolUse hooks |
| [🛡️ @weave_protocol/mund](./mund) | 0.2.2 | Security scanner — secrets, PII, injection, MCP vetting, threat intel |
| [🏛️ @weave_protocol/hord](./hord) | 0.1.6 | Encrypted vault with Yoxallismus cipher |
| [⚖️ @weave_protocol/domere](./domere) | 1.3.4 | Compliance (PCI-DSS, ISO27001, SOC2, HIPAA, GDPR, CCPA) & verification |
| [👥 @weave_protocol/witan](./witan) | 1.0.2 | Multi-agent consensus & governance |
| [🔍 @weave_protocol/hundredmen](./hundredmen) | 1.1.0 | **Real-time MCP proxy** — intercept, scan, gate tool calls, **enforces WARD.md** |
| [🛂 @weave_protocol/tollere](./tollere) | 0.2.2 | **Supply chain security** — npm, Docker images, IDE extensions, sandwich pattern detection |
| [🔗 @weave_protocol/langchain](./langchain) | 1.0.1 | **LangChain.js** security callbacks & tool wrappers |
| [🐍 weave-protocol-llamaindex](./llamaindex-py) | 0.1.0 | **Python/LlamaIndex** security callbacks & tools |
| [🔌 @weave_protocol/api](./api) | 1.0.12 | REST API for all packages + **dashboard** |

---

## 🤖 AI Agent Skills

Each package includes a `SKILL.md` file following the [Claude Agent Skills specification](https://docs.anthropic.com/en/docs/claude-code/skills). These teach AI agents how to use Weave Protocol tools effectively.

| Package | Skill Name | Triggers |
|---------|------------|----------|
| 🕸️ CLI | `weave-cli` | set up Weave, init project, scaffold security, audit, dashboard, doctor |
| 🛡️ Ward | `ward` | WARD.md, agent security policy, guardrails, lock down agent, define boundaries |
| 🛡️ adapter-claudecode | `adapter-claudecode` | secure Claude Code, install WARD hooks, block Claude Code actions, dogfood policy |
| 🛡️ Mund | `security-scanning` | scan, detect secrets, check injection, vet MCP server, threat intel |
| 🏛️ Hord | `encrypting-data` | encrypt, decrypt, vault, Yoxallismus, protect |
| ⚖️ Domere | `compliance-auditing` | audit, checkpoint, SOC2, HIPAA, PCI-DSS, GDPR, CCPA, blockchain |
| 👥 Witan | `consensus-governance` | consensus, vote, approve, policy, escalate |
| 🔍 Hundredmen | `security-inspection` | intercept, drift, reputation, approve, block, live feed, enforce WARD policy |
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

### Option 1: Guided setup (recommended)

```bash
npx @weave_protocol/cli init
```

### Option 2: Install everything

```bash
npm install @weave_protocol/full
```

### Option 3: Install individual packages

```bash
npm install @weave_protocol/mund @weave_protocol/tollere @weave_protocol/ward
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

If you have a `WARD.md` in your home directory or set `$WEAVE_WARD_PATH`, Hundredmen will auto-enforce it.

### Claude Code Integration

```bash
npm install -g @weave_protocol/adapter-claudecode
weave-claude-code init
```

Drop a `WARD.md` in your project root (or `~/.claude/WARD.md` for user-global). Every Claude Code tool call is now gated.

---

## ✨ Package Details

### 🕸️ CLI — One Command for Everything

```bash
npx @weave_protocol/cli init        # detect framework, scaffold middleware
npx @weave_protocol/cli audit       # supply chain scan (Tollere)
npx @weave_protocol/cli dashboard   # launch monitoring UI
npx @weave_protocol/cli doctor      # environment health check
```

| Framework | Generated middleware |
|-----------|---------------------|
| **LangChain.js** | `WeaveSecurityCallback` ready to drop into any chain |
| **MCP Server** | `secureToolHandler()` wrapper for input/output scanning |
| **OpenAI / Anthropic SDK** | `secureChatCompletion()` / `secureMessages()` wrappers |
| **Vercel AI SDK** | OpenAI-style wrapper |
| **Generic** | Just installs packages and writes `.weaverc` |

📄 **Skill:** [`weave-cli`](./cli/SKILL.md)

---

### 🛡️ Ward — The Policy Standard

WARD.md files declare what an agent is allowed to do, version-controlled alongside `AGENTS.md` and `SKILL.md`.

```
my-agent-project/
├── AGENTS.md          # what the agent does
├── SKILL.md           # how the agent does it
└── WARD.md            # what the agent can't do
```

| Section | Controls |
|---------|----------|
| **Filesystem** | Read/write/execute/delete/list rules with glob patterns |
| **Network** | Outbound HTTP allowlist with optional method restrictions |
| **Capabilities** | Tools the agent may invoke (with optional approval gating) |
| **Data Boundaries** | Egress classifications (PII, PHI, credentials...) and redaction |
| **Behavioral Limits** | Iterations, runtime, cost, tokens, tool calls |
| **Multi-Agent** | Trust chain, isolation level, semantic drift threshold |
| **Compliance** | SOC2 / HIPAA / GDPR / CCPA / ISO27001 / PCI-DSS |
| **Verification** | Attestation backend (Dōmere), blockchain, frequency |
| **Threat Model** | In-scope / out-of-scope threats |
| **Incident Response** | Actions on violation (log / alert / terminate / attest) |

Enforced at runtime by:
- **Hundredmen** (MCP layer) — gates tool calls routed through MCP servers
- **adapter-claudecode** (Claude Code) — gates Claude Code's PreToolUse hooks

📄 **Skill:** [`ward`](./ward/SKILL.md) · 📋 **Spec:** [WARD.md SPEC →](./ward/SPEC.md)

---

### 🛡️ adapter-claudecode — Claude Code enforcement

First cross-platform harness adapter. Installs into Claude Code's hook system and enforces your WARD.md on every tool call.

```bash
weave-claude-code init               # install the hook
weave-claude-code status             # show config + active policy
weave-claude-code test Bash --input='{"command":"rm -rf ~/.ssh"}'
weave-claude-code disable            # remove
```

WARD resolution order: `$WEAVE_WARD_PATH` → `<cwd>/WARD.md` → `<cwd>/.weave/WARD.md` → `~/.claude/WARD.md` (user-global).

Tool mapping covers Bash, Edit/MultiEdit/Write, Read, Grep, LS, Glob, WebFetch, WebSearch, Task, NotebookEdit. Use either Claude tool names (`Bash`, `Read`) or generic capabilities (`shell_exec`, `file_read`) in WARD.md — explicit rules beat default decisions.

📄 **Skill:** [`adapter-claudecode`](./adapter-claudecode/SKILL.md)

---

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

Real-time MCP security proxy that intercepts, scans, and gates AI agent tool calls. **v1.1.0 enforces WARD.md policies.**

| Category | Features |
|----------|----------|
| **WARD enforcement** | Reads `WARD.md`, gates calls at the MCP layer |
| **Interception** | Proxy all MCP tool calls in real-time |
| **Drift Detection** | "Said X, doing Y" — catch unauthorized actions |
| **Reputation** | Server trust scores, community reports |
| **Manual Gates** | Require approval for high-risk operations |

Decision flow: **WARD policy → critical scan issues → reputation → intent/drift → manual approval queue.** WARD wins.

📄 **Skill:** [`security-inspection`](./hundredmen/SKILL.md)

---

### 🛂 Tollere — The Customs Inspector

Supply chain security for AI-generated code. Catches malicious packages, Docker images, and IDE extensions **before** they reach `node_modules/`, your container, or your editor.

| Surface | Coverage |
|---------|----------|
| **Packages** | npm, PyPI, Cargo, Go, Maven (typosquats, CVEs, maintainer reputation) |
| **Sandwich Pattern** | Malicious code hidden between a clean "filling" version (Checkmarx attack pattern) |
| **Docker Images** | Tag overwrite detection, phantom tags (Docker Hub) |
| **IDE Extensions** | VS Code (Cursor, Windsurf), Open VSX (VSCodium, Gitpod), JetBrains |

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
┌──────────────────────────────────────────────────────────────────────┐
│                         🕸️  weave init / audit                       │
│                       (front door — @weave_protocol/cli)             │
└────────────────────────────────┬─────────────────────────────────────┘
                                 │
            ┌────────────────────┴────────────────────┐
            │     🛡️  WARD.md  (policy standard)      │
            │     declares what the agent can't do    │
            └────────────────────┬────────────────────┘
                                 │
                  enforced at runtime by:
                                 │
       ┌─────────────────────────┼─────────────────────────┐
       ▼                         ▼                         ▼
┌──────────────┐         ┌──────────────┐          ┌──────────────────┐
│🔍 Hundredmen │         │ adapter-     │          │ adapter-         │
│   (MCP)      │         │ claudecode   │          │ antigravity/...  │
│              │         │ (Claude Code)│          │ (coming Q3)      │
└──────────────┘         └──────────────┘          └──────────────────┘
                                 │
┌────────────────────────────────┴─────────────────────────────────────┐
│                          AI Agent System                             │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐             │
│  │  🛡️ Mund │  │ 🏛️ Hord  │  │ ⚖️ Domere│  │ 👥 Witan │             │
│  │ Guardian │  │  Vault   │  │  Judge   │  │ Council  │             │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘             │
│       │             │             │             │                    │
│  Security      Encryption    Compliance     Consensus               │
│       │             │             │             │                    │
│       └─────────────┴─────────────┴─────────────┘                    │
│                           │                                          │
│  ┌──────────────┐  ┌──────┴──────┐  ┌──────────────┐                │
│  │🔍 Hundredmen │  │ 🛂 Tollere  │  │  🔌 API      │                │
│  │  Watchers    │  │   Customs   │  │  REST + UI   │                │
│  └──────────────┘  └─────────────┘  └──────────────┘                │
│        │                  │                  │                       │
│  Runtime Calls    Supply Chain        Universal Access               │
│        │                  │                  │                       │
│        └──────────────────┴──────────────────┘                       │
│                           │                                          │
│                    ┌──────┴───────┐                                  │
│                    │ 🔗 Langchain │                                  │
│                    │   Bridge     │                                  │
│                    └──────────────┘                                  │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 🔐 Security Model

Defense-in-depth across the entire AI agent lifecycle:

1. **🛡️ Ward** declares what the agent can and can't do (policy-as-code)
2. **🛡️ adapter-claudecode** enforces WARD inside Claude Code (PreToolUse hook)
3. **🛂 Tollere** inspects every dependency, image, and extension before it enters your project
4. **🛡️ Mund** scans all inputs for threats before processing
5. **🏛️ Hord** encrypts sensitive data at rest and in transit
6. **⚖️ Domere** logs all actions with tamper-evident checksums
7. **👥 Witan** requires consensus for high-risk operations
8. **🔍 Hundredmen** intercepts and gates tool calls in real-time — enforcing WARD policy at the MCP layer
9. **🔗 Langchain** secures LangChain.js chains and agents

### CORS Model Integration

| CORS Layer | Weave Package | Function |
|------------|---------------|----------|
| **Policy** | 🛡️ Ward | Declares allowed/denied actions, behavioral limits, attestation requirements |
| **Policy Enforcement (harness)** | 🛡️ adapter-claudecode | Reads WARD, gates Claude Code tool calls via hooks |
| **Policy Enforcement (MCP)** | 🔍 Hundredmen | Reads WARD, gates tool calls at the MCP layer |
| **Supply Chain** | 🛂 Tollere | Vets dependencies, images, extensions before install |
| **Origin Validation** | 🛡️ Mund | Validates input sources, detects injection |
| **Context Integrity** | 🏛️ Hord | Protects data integrity through encryption |
| **Deterministic Enforcement** | ⚖️ Domere | Ensures consistent policy application |

---

## 🛠️ Development

```bash
git clone https://github.com/Tyox-all/Weave_Protocol.git
cd Weave_Protocol

# Build each package
for pkg in mund hord domere witan hundredmen tollere langchain api cli ward adapter-claudecode; do
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
- [x] Bundle package + CLI (`weave init`) — adoption funnel
- [x] WARD.md agent security policy standard
- [x] Hundredmen ↔ WARD enforcement integration (v1.1.0)
- [x] **Claude Code harness adapter** (first cross-platform adapter)

### H2 2026 Q3 — Adoption Quarter
- [ ] Google Antigravity adapter (`@weave_protocol/adapter-antigravity`)
- [ ] Microsoft MDASH adapter (`@weave_protocol/adapter-mdash`)
- [ ] Browser agent security (`@weave_protocol/browser`)
- [ ] Dashboard v2 with orchestration visualization
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
