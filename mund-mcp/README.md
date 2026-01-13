# Weave Security Suite

**Vendor-Neutral Security for AI Agents**

> "Standardizing agent interoperability is a big step. The real question is how identity, intent, and proof are enforced at execution time, not just exchanged."

## The Gap

Protocols like **MCP**, **A2A**, and **UCP** standardize how AI agents communicate. They answer: *"How do agents talk?"*

They don't answer: *"How do we trust what they did?"*

**Weave Security fills this gap.**

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
# Install
npm install @weave-security/mund
npm install @weave-security/hord  
npm install @weave-security/domere

# Or run as MCP servers
npx @weave-security/mund
npx @weave-security/hord
npx @weave-security/domere
```

## Claude Desktop Configuration

```json
{
  "mcpServers": {
    "mund": {
      "command": "npx",
      "args": ["@weave-security/mund"]
    },
    "hord": {
      "command": "npx", 
      "args": ["@weave-security/hord"]
    },
    "domere": {
      "command": "npx",
      "args": ["@weave-security/domere"]
    }
  }
}
```

## Business Model

**100% Free (MIT License):**
- All scanning and detection (Mund)
- All containment and redaction (Hord)
- All threading and drift detection (Dōmere)
- All 48 MCP tools
- Run anywhere, any cloud, any LLM

**Paid (Blockchain Only):**
- Solana anchoring: ~$0.001 + 5% protocol fee
- Ethereum anchoring: ~$2-10 + 5% protocol fee
- You bring your own wallet
- Protocol fees fund continued development

## Why Weave?

| Others | Weave |
|--------|-------|
| Point identity (who is this?) | Thread identity (what has this done?) |
| Exchange identity tokens | Enforce identity at execution |
| Log what happened | Prove what happened (immutable) |
| Vendor lock-in | Vendor neutral |
| Hosted service | Self-hosted, open source |

## Repository Structure

```
weave-security/
├── README.md           # This file
├── mund/               # Guardian Protocol
│   ├── src/
│   └── package.json
├── hord/               # Vault Protocol
│   ├── src/
│   └── package.json
└── domere/             # Judge Protocol
    ├── src/
    └── package.json
```

## License

MIT - Use it, fork it, build on it.

## Links

- [Mund Documentation](./mund/README.md)
- [Hord Documentation](./hord/README.md)
- [Dōmere Documentation](./domere/README.md)
