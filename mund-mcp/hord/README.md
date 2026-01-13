# Hord - The Vault Protocol 🔐

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen)](https://nodejs.org)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-blue)](https://modelcontextprotocol.io)

> Cryptographic containment and capability management for agentic AI systems.

**Hord** (from Old English meaning "treasure, secret place, hoard") provides the missing security layer between AI agents and sensitive resources. While [Mund](../README.md) watches and alerts, Hord encrypts, isolates, and proves.

## The Problem

Current AI security tools are **reactive watchers** - they observe data streams and pattern match. But as AI agents become autonomous with persistent memory and accumulated credentials, we need:

- **Encrypted agent state** that even admins can't read
- **Fine-grained capabilities** beyond simple allow/block
- **Sandbox execution** before promoting to production
- **Cryptographic proof** of what agents actually did

## Features

- 🔐 **Encrypted Vaults** - AES-256-GCM encrypted storage for agent memories, credentials, and state
- 🎟️ **Capability Tokens** - Fine-grained, time-limited, delegatable access control
- 📦 **Sandbox Execution** - Isolated environments to test agent outputs before promotion
- 🔒 **Semantic Redaction** - Process sensitive data without exposing it
- ✅ **Cryptographic Attestation** - Non-repudiable proof of agent actions

## Quick Start

### Installation

```bash
# Using npm
npm install -g hord-mcp

# Or clone and build
git clone https://github.com/your-org/mund-mcp.git
cd mund-mcp/hord
npm install
npm run build
```

### Usage with Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "hord": {
      "command": "npx",
      "args": ["hord-mcp"],
      "env": {
        "HORD_MASTER_KEY": "your-secure-master-key"
      }
    }
  }
}
```

### Combined with Mund

```json
{
  "mcpServers": {
    "mund": {
      "command": "npx",
      "args": ["mund-mcp"]
    },
    "hord": {
      "command": "npx",
      "args": ["hord-mcp"],
      "env": {
        "HORD_MUND_URL": "http://localhost:3000"
      }
    }
  }
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           AI AGENT                                   │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
            ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
            │    MUND     │ │    HORD     │ │   FUTURE:   │
            │  (Guardian) │ │   (Vault)   │ │   DŌMERE    │
            │             │ │             │ │   (Judge)   │
            │ - Watches   │ │ - Encrypts  │ │             │
            │ - Alerts    │ │ - Isolates  │ │ - Proves    │
            │ - Patterns  │ │ - Contains  │ │ - Attests   │
            └─────────────┘ └─────────────┘ └─────────────┘
```

## MCP Tools

### Vault Tools

| Tool | Description |
|------|-------------|
| `hord_create_vault` | Create encrypted vault for agent |
| `hord_open_vault` | Open vault with attestation |
| `hord_seal_vault` | Close and re-encrypt vault |
| `hord_store_secret` | Store credential in vault |
| `hord_retrieve_secret` | Get credential |
| `hord_list_vaults` | List accessible vaults |
| `hord_store_memory` | Store agent memory |
| `hord_retrieve_memories` | Get agent memories |

### Capability Tools

| Tool | Description |
|------|-------------|
| `hord_request_capability` | Request access capability |
| `hord_verify_capability` | Check if capability is valid |
| `hord_revoke_capability` | Revoke a capability |
| `hord_delegate_capability` | Delegate to another agent |
| `hord_list_capabilities` | List active capabilities |

### Sandbox Tools

| Tool | Description |
|------|-------------|
| `hord_create_sandbox` | Create isolated environment |
| `hord_execute_in_sandbox` | Run code/command in sandbox |
| `hord_promote_sandbox_result` | Promote safe result |
| `hord_destroy_sandbox` | Clean up sandbox |
| `hord_get_sandbox_results` | Get execution results |

### Redaction Tools

| Tool | Description |
|------|-------------|
| `hord_create_redaction_policy` | Define redaction rules |
| `hord_redact_content` | Apply redaction to content |
| `hord_tokenize_pii` | Replace PII with tokens |
| `hord_detokenize` | Reverse tokenization |
| `hord_list_redaction_policies` | List policies |

### Attestation Tools

| Tool | Description |
|------|-------------|
| `hord_attest_action` | Create attestation for action |
| `hord_verify_attestation` | Verify attestation validity |
| `hord_get_attestations` | Get attestations for agent |
| `hord_get_attestation_chain` | Get attestation chain |
| `hord_export_audit_log` | Export for audit |

## Usage Examples

### Creating and Using a Vault

```javascript
// Create a vault for agent memories
const vault = await hord_create_vault({
  agent_id: "agent-123",
  name: "Agent Memory Vault",
  require_attestation: true
});

// Open the vault
await hord_open_vault({
  vault_id: vault.vault_id,
  agent_id: "agent-123",
  context: "conversation"
});

// Store a secret
await hord_store_secret({
  vault_id: vault.vault_id,
  agent_id: "agent-123",
  name: "github_token",
  value: "ghp_xxxx",
  type: "token",
  classification: "secret"
});

// Seal when done
await hord_seal_vault({
  vault_id: vault.vault_id,
  agent_id: "agent-123"
});
```

### Capability-Based Access

```javascript
// Request capability to access a vault
const cap = await hord_request_capability({
  agent_id: "agent-123",
  resource_type: "vault",
  resource_id: "vault_abc123",
  actions: ["read", "write"],
  validity_hours: 24,
  justification: "Need to store conversation history"
});

// Verify before use
const verified = await hord_verify_capability({
  token_id: cap.token_id,
  agent_id: "agent-123",
  resource_type: "vault",
  resource_id: "vault_abc123",
  action: "read"
});

// Delegate to another agent
const delegated = await hord_delegate_capability({
  token_id: cap.token_id,
  delegate_to: "agent-456",
  actions: ["read"],  // Can only give subset
  justification: "Assistant needs read access"
});
```

### Sandbox Execution

```javascript
// Create sandbox for code testing
const sandbox = await hord_create_sandbox({
  type: "code",
  isolation_level: "process",
  timeout_ms: 30000,
  memory_mb: 256,
  allow_network: false
});

// Execute agent-generated code
const result = await hord_execute_in_sandbox({
  sandbox_id: sandbox.sandbox_id,
  type: "code",
  content: agentGeneratedCode,
  language: "python",
  declared_intent: "Calculate fibonacci sequence"
});

// Check recommendation
if (result.promotion_recommendation === "safe") {
  await hord_promote_sandbox_result({
    sandbox_id: sandbox.sandbox_id,
    result_id: result.result_id
  });
}

// Clean up
await hord_destroy_sandbox({
  sandbox_id: sandbox.sandbox_id
});
```

### Semantic Redaction

```javascript
// Create redaction policy
const policy = await hord_create_redaction_policy({
  name: "customer-data",
  rules: [
    {
      field_pattern: "$.ssn",
      data_type: "ssn",
      strategy_type: "tokenize",
      reversible: true
    },
    {
      field_pattern: "$.email",
      data_type: "email",
      strategy_type: "mask",
      reversible: false
    }
  ]
});

// Redact content
const redacted = await hord_redact_content({
  content: JSON.stringify({
    name: "John Doe",
    ssn: "123-45-6789",
    email: "john@example.com"
  }),
  policy_id: policy.policy_id
});

// Result: { name: "John Doe", ssn: "TOK_SSN_abc123", email: "****@****.***" }
```

## Configuration

### Environment Variables

```bash
# Core Settings
HORD_PORT=3001              # HTTP port
HORD_HOST=127.0.0.1         # HTTP host
HORD_TRANSPORT=stdio        # stdio or http
HORD_STORAGE=memory         # memory, sqlite, postgres

# Encryption
HORD_MASTER_KEY=your-key    # Master encryption key
HORD_KEY_ROTATION_DAYS=90   # Key rotation period

# Sandbox
HORD_SANDBOX_RUNTIME=process    # process, docker, firecracker
HORD_SANDBOX_TIMEOUT_MS=30000   # Default timeout
HORD_SANDBOX_MEMORY_MB=512      # Default memory limit

# Integration
HORD_MUND_URL=http://localhost:3000  # Mund server for integration
```

## Security Considerations

### Key Management

- **Never commit master keys** - Use environment variables or key management services
- **Rotate keys regularly** - Default is 90 days
- **Use hardware keys in production** - Set `HORD_USE_HARDWARE_KEY=true`

### Vault Security

- Vaults are encrypted at rest with AES-256-GCM
- Keys are derived using PBKDF2 (Argon2id in future)
- Access policies enforce time windows, contexts, and classifications

### Sandbox Security

- Default: no network access
- Syscalls monitored for suspicious behavior
- Resource limits enforced
- Promotion requires explicit approval

## Why "Hord"?

In Old English (Anglo-Saxon), **"Hord"** (pronounced "hoard") meant:
- **Treasure** - Something precious to be protected
- **Secret place** - A hidden store
- **Hoard** - To keep safe

The word survives in modern English as "hoard" and is related to the concept of safeguarding valuables. Perfect for a protocol that protects AI agents' most sensitive data.

## Roadmap

### Phase 1 (Current)
- [x] Encrypted vault storage
- [x] Basic capability tokens
- [x] Process-based sandbox
- [x] PII tokenization
- [x] Action attestation

### Phase 2
- [ ] SQLite persistence
- [ ] Container-based sandbox
- [ ] Capability delegation chains
- [ ] Mund integration

### Phase 3
- [ ] Hardware key support (TPM)
- [ ] Format-preserving encryption
- [ ] Zero-knowledge compliance proofs
- [ ] MicroVM sandboxing

## Related Projects

- **[Mund](../README.md)** - The Guardian Protocol (pattern-based watching)
- **Dōmere** (Future) - The Judge Protocol (formal verification)

## License

MIT License - See [LICENSE](../LICENSE) file

---

Made with ❤️ for AI Safety
