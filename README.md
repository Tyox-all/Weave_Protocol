# Weave Protocol Security Suite

![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)
![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen)
[![GitHub stars](https://img.shields.io/github/stars/Tyox-all/Weave)](https://github.com/Tyox-all/Weave-Protocol/stargazers)
[![npm mund](https://img.shields.io/npm/v/@weave_protocol/mund)](https://www.npmjs.com/package/@weave_protocol/mund)
[![npm hord](https://img.shields.io/npm/v/@weave_protocol/hord)](https://www.npmjs.com/package/@weave_protocol/hord)
[![npm domere](https://img.shields.io/npm/v/@weave_protocol/domere)](https://www.npmjs.com/package/@weave_protocol/domere)


**Vendor-Neutral Security for AI Agents**

## The Gap

Protocols like MCP, A2A, and UCP standardize how AI agents communicate. They solve for interoperability—how agents talk to each other.

They don't solve for trust—how we verify what agents actually did.

When Agent A calls Agent B calls Agent C, who confirms the original intent was preserved? Who proves what happened at each step?

Weave Protocol enforces identity, intent, and proof at execution time—not just at the handshake.

## The Suite

```
┌─────────────────────────────────────────────────────────────────────┐
│                     WEAVE SECURITY SUITE                            │
│                                                                     │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐              │
│  │    MUND     │   │    HORD     │   │   DŌMERE    │              │
│  │  Guardian   │   │    Vault    │   │    Judge    │              │
│  │             │   │             │   │             │              │
│  │ • Secrets   │   │ • Vaults    │   │ • Threads   │              │
│  │ • Injection │   │ • Redaction │   │ • Drift     │              │
│  │ • PII       │   │ • Sandbox   │   │ • Anchoring │              │
│  │ • Exfil     │   │ • Attest    │   │ • Proof     │              │
│  └─────────────┘   └─────────────┘   └─────────────┘              │
│                                                                     │
│  11 MCP Tools       25 MCP Tools       12 MCP Tools                │
└─────────────────────────────────────────────────────────────────────┘
```

### Mund (Guardian Protocol)
Pattern detection and threat scanning. Finds secrets, injection attempts, PII, and exfiltration patterns before they cause harm.

### Hord (Vault Protocol)  
Cryptographic containment. Secure vaults, capability-based access, content redaction, sandboxed execution, and attestation.

### Dōmere (Judge Protocol)
Thread identity and verification. Tracks intent through agent chains, detects drift, and anchors proof to blockchain.

## Quick Start

```bash
# Clone
git clone https://github.com/Tyox-all/Weave-Protocol.git
cd Weave

# Install and run Mund
cd mund && npm install && npm run build && npm start

# Install and run Hord
cd ../hord && npm install && npm run build && npm start

# Install and run Dōmere
cd ../domere && npm install && npm run build && npm start
```

## Claude Desktop Configuration

```json
{
  "mcpServers": {
    "mund": {
      "command": "node",
      "args": ["/path/to/Weave/mund/dist/index.js"]
    },
    "hord": {
      "command": "node", 
      "args": ["/path/to/Weave/hord/dist/index.js"]
    },
    "domere": {
      "command": "node",
      "args": ["/path/to/Weave/domere/dist/index.js"]
    }
  }
}
```

## Repository Structure

```
Weave/
├── mund/               # Guardian Protocol
│   ├── src/
│   ├── rules/
│   └── package.json
├── hord/               # Vault Protocol
│   ├── src/
│   └── package.json
├── domere/             # Judge Protocol
│   ├── src/
│   └── package.json
├── contracts/          # Smart Contracts
│   ├── solana/
│   └── ethereum/
├── README.md
├── LICENSE
└── CONTRIBUTING.md
```

## Business Model

**100% Free (Apache-2.0 License):**
- All scanning and detection (Mund)
- All containment and redaction (Hord)
- All threading and drift detection (Dōmere)
- All 48 MCP tools
- Run anywhere, any cloud, any LLM

**Paid (Blockchain Anchoring Only):**
- Solana: ~$0.001 + protocol fee
- Ethereum: ~$2-10 + protocol fee
- You bring your own wallet

## Why Weave Protocol?

| Traditional | Weave Protocol |
|-------------|-------|
| Point identity (who is this?) | Thread identity (what has this done?) |
| Exchange tokens | Enforce at execution |
| Internal logs | Immutable blockchain proof |
| Vendor lock-in | Vendor neutral, open source |

## License

Apache-2.0 - Use it, fork it, build on it.

## Links

- [Mund Documentation](./mund/README.md)
- [Hord Documentation](./hord/README.md)
- [Dōmere Documentation](./domere/README.md)
