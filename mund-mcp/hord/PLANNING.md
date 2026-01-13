# Hord: The Vault Protocol

## Executive Summary

**Hord** (from Old English meaning "treasure, secret place, hoard") is an open-source cryptographic containment and capability management layer for agentic AI systems. While Mund watches and alerts, Hord encrypts, isolates, and proves - providing the missing security primitive between observation and action.

## Project Vision

### The Gap in Current AI Security

Current tools like Mund, Wayfound, and similar supervisors are **reactive watchers**:
- They observe data streams
- Pattern match for known threats
- Alert or block based on signatures
- Log events post-hoc

This is necessary but insufficient as AI agents evolve from task-executors to **autonomous, persistent entities** with:
- Long-term memory across sessions
- Accumulated credentials and access
- Self-directed goal pursuit
- Complex multi-step operations

### What's Missing

| Capability | Watchers (Mund) | Vaults (Hord) |
|------------|-----------------|---------------|
| Secret detection | ✅ Pattern matching | ✅ Never sees plaintext |
| Access control | ❌ Binary allow/block | ✅ Fine-grained capabilities |
| Agent memory | ❌ Can read everything | ✅ Encrypted enclaves |
| Code execution | ❌ Run and hope | ✅ Sandbox first, promote if safe |
| Audit trail | ✅ Logs what happened | ✅ Cryptographic proof it happened |
| Data handling | ❌ Sees all data | ✅ Semantic redaction/tokenization |

### Hord's Role

Hord provides:

1. **Encrypted Agent Vaults** - Secure storage for agent state, memories, credentials
2. **Capability Tokens** - Fine-grained, time-limited, context-aware access control
3. **Sandbox Execution** - Isolated environments for testing agent outputs before promotion
4. **Semantic Redaction** - Process data without exposing sensitive content
5. **Cryptographic Attestation** - Provable records of agent actions

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
                    │               │               │
                    └───────────────┼───────────────┘
                                    ▼
            ┌─────────────────────────────────────────────────────────┐
            │                 ACTUAL RESOURCES                         │
            │         (Files, APIs, Databases, Networks)               │
            └─────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Vault Manager (Encrypted Agent Storage)

Provides encrypted storage for sensitive agent data:

```typescript
interface Vault {
  id: string;                    // Unique vault identifier
  agent_id: string;              // Owning agent
  created_at: Date;
  encryption: {
    algorithm: 'aes-256-gcm';
    key_derivation: 'argon2id';
    key_id: string;              // Reference to key in KMS
  };
  access_policy: AccessPolicy;
  contents: EncryptedBlob;       // Encrypted vault data
}

interface VaultContents {
  memories: Memory[];            // Agent's persistent memories
  credentials: Credential[];     // Stored secrets (double-encrypted)
  state: Record<string, any>;    // Agent state
  artifacts: Artifact[];         // Generated content
}
```

**Key Features:**
- Hardware-backed key storage where available (TPM, Secure Enclave)
- Key rotation without re-encryption of all data
- Granular access policies (time-based, context-based)
- Audit log of all vault access

### 2. Capability Token System

Fine-grained, cryptographically-signed access tokens:

```typescript
interface CapabilityToken {
  id: string;
  agent_id: string;
  resource: ResourceDescriptor;
  actions: Action[];
  constraints: {
    valid_from: Date;
    valid_until: Date;
    max_uses?: number;
    rate_limit?: RateLimit;
    requires_attestation?: boolean;
    allowed_contexts?: string[];
    data_classification_max: DataClassification;
  };
  delegatable: boolean;
  parent_token?: string;         // For delegation chains
  signature: string;             // Cryptographic signature
  issuer: string;                // Who issued this token
}

type Action = 'read' | 'write' | 'execute' | 'delete' | 'delegate';
type DataClassification = 'public' | 'internal' | 'confidential' | 'secret' | 'top_secret';
```

**Key Features:**
- Tokens are signed and tamper-evident
- Support for delegation with attenuation (can grant subset of own capabilities)
- Automatic expiration and revocation
- Context-aware validation (time of day, calling context, etc.)

### 3. Sandbox Executor

Isolated execution environment for agent-generated content:

```typescript
interface SandboxConfig {
  id: string;
  type: 'code' | 'command' | 'network' | 'file';
  isolation_level: 'process' | 'container' | 'vm';
  resource_limits: {
    cpu_seconds: number;
    memory_mb: number;
    disk_mb: number;
    network_bytes: number;
    max_processes: number;
  };
  allowed_syscalls?: string[];
  network_policy: NetworkPolicy;
  filesystem_policy: FilesystemPolicy;
}

interface SandboxResult {
  id: string;
  status: 'success' | 'failure' | 'timeout' | 'violation';
  exit_code?: number;
  stdout: string;
  stderr: string;
  resource_usage: ResourceUsage;
  syscalls: SyscallTrace[];
  network_activity: NetworkActivity[];
  filesystem_changes: FilesystemChange[];
  security_events: SecurityEvent[];
  promotion_recommendation: 'safe' | 'review' | 'block';
}
```

**Key Features:**
- Multiple isolation levels (process, container, microVM)
- Syscall tracing and filtering
- Network interception and analysis
- Filesystem change tracking
- Behavioral comparison against declared intent

### 4. Semantic Redaction Engine

Process sensitive data without full exposure:

```typescript
interface RedactionPolicy {
  id: string;
  name: string;
  rules: RedactionRule[];
}

interface RedactionRule {
  field_pattern: string;         // JSONPath or regex
  data_type: DataType;
  strategy: RedactionStrategy;
  reversible: boolean;           // Can be de-redacted with token
}

type RedactionStrategy = 
  | { type: 'mask'; char: string; preserve_length: boolean }
  | { type: 'hash'; algorithm: string; salt: boolean }
  | { type: 'tokenize'; format_preserving: boolean }
  | { type: 'generalize'; level: number }
  | { type: 'encrypt'; key_id: string }
  | { type: 'synthetic'; generator: string };

interface RedactedData {
  data: any;                     // Redacted version
  redaction_map: RedactionMap;   // For reversal (encrypted)
  policy_id: string;
  timestamp: Date;
}
```

**Key Features:**
- Format-preserving tokenization (SSN looks like SSN but isn't real)
- Reversible redaction with proper authorization
- Differential privacy options
- Data type-aware strategies

### 5. Attestation Service

Cryptographic proof of agent behavior:

```typescript
interface Attestation {
  id: string;
  timestamp: Date;
  agent_id: string;
  action: AttestableAction;
  inputs_hash: string;           // Hash of inputs
  outputs_hash: string;          // Hash of outputs
  context: AttestationContext;
  signature: string;             // Signed by attestation service
  certificate_chain: string[];   // For verification
}

interface AttestableAction {
  type: string;
  description: string;
  resources_accessed: string[];
  capabilities_used: string[];
  duration_ms: number;
}

interface AttestationContext {
  environment: Record<string, string>;
  caller_chain: string[];        // Who requested this action
  policy_version: string;
  sandbox_id?: string;
}
```

**Key Features:**
- Non-repudiable action records
- Verifiable by third parties
- Chain of custody for data
- Integration with external audit systems

## MCP Tools

### Vault Tools

| Tool | Description |
|------|-------------|
| `hord_create_vault` | Create new encrypted vault for agent |
| `hord_open_vault` | Open vault with attestation |
| `hord_seal_vault` | Close and re-encrypt vault |
| `hord_store_secret` | Store credential in vault |
| `hord_retrieve_secret` | Get credential (requires capability) |
| `hord_list_vaults` | List accessible vaults |

### Capability Tools

| Tool | Description |
|------|-------------|
| `hord_request_capability` | Request access capability |
| `hord_grant_capability` | Grant capability token |
| `hord_revoke_capability` | Revoke existing capability |
| `hord_delegate_capability` | Delegate subset of capability |
| `hord_verify_capability` | Check if capability is valid |
| `hord_list_capabilities` | List active capabilities |

### Sandbox Tools

| Tool | Description |
|------|-------------|
| `hord_create_sandbox` | Create isolated execution environment |
| `hord_execute_in_sandbox` | Run code/command in sandbox |
| `hord_get_sandbox_result` | Get execution results |
| `hord_promote_from_sandbox` | Promote safe result to real execution |
| `hord_destroy_sandbox` | Clean up sandbox |

### Redaction Tools

| Tool | Description |
|------|-------------|
| `hord_redact_content` | Apply redaction policy to content |
| `hord_create_redaction_policy` | Define new redaction rules |
| `hord_de_redact` | Reverse redaction (requires capability) |
| `hord_tokenize_pii` | Replace PII with tokens |

### Attestation Tools

| Tool | Description |
|------|-------------|
| `hord_attest_action` | Create attestation for action |
| `hord_verify_attestation` | Verify attestation is valid |
| `hord_get_attestations` | Get attestations for agent/resource |
| `hord_export_audit_log` | Export attestations for audit |

## Technology Stack

### Cryptographic Primitives

| Purpose | Algorithm | Notes |
|---------|-----------|-------|
| Symmetric encryption | AES-256-GCM | Authenticated encryption |
| Key derivation | Argon2id | Memory-hard, side-channel resistant |
| Hashing | BLAKE3 | Fast, secure |
| Signatures | Ed25519 | Fast verification |
| Token signing | HMAC-SHA256 or Ed25519 | Depending on use case |

### Runtime

- **Node.js 20+** with native crypto
- **libsodium** for advanced crypto
- **Docker/containerd** for sandboxing
- **SQLite/PostgreSQL** for persistence
- **Redis** for token caching (optional)

## Directory Structure

```
hord-mcp/
├── README.md
├── LICENSE (MIT)
├── CONTRIBUTING.md
├── SECURITY.md
├── package.json
├── tsconfig.json
│
├── src/
│   ├── index.ts              # Main entry point
│   ├── server.ts             # MCP server setup
│   ├── types.ts              # TypeScript interfaces
│   ├── constants.ts          # Configuration constants
│   │
│   ├── vault/
│   │   ├── index.ts
│   │   ├── manager.ts        # Vault lifecycle
│   │   ├── encryption.ts     # Encryption operations
│   │   └── storage.ts        # Vault persistence
│   │
│   ├── capability/
│   │   ├── index.ts
│   │   ├── token.ts          # Token creation/validation
│   │   ├── policy.ts         # Access policies
│   │   └── delegation.ts     # Delegation logic
│   │
│   ├── sandbox/
│   │   ├── index.ts
│   │   ├── executor.ts       # Sandbox execution
│   │   ├── container.ts      # Container management
│   │   ├── analyzer.ts       # Behavior analysis
│   │   └── promotion.ts      # Safe promotion logic
│   │
│   ├── redaction/
│   │   ├── index.ts
│   │   ├── engine.ts         # Redaction engine
│   │   ├── strategies.ts     # Redaction strategies
│   │   └── tokenizer.ts      # PII tokenization
│   │
│   ├── attestation/
│   │   ├── index.ts
│   │   ├── service.ts        # Attestation creation
│   │   ├── verification.ts   # Attestation verification
│   │   └── export.ts         # Audit export
│   │
│   ├── tools/
│   │   ├── index.ts
│   │   ├── vault-tools.ts
│   │   ├── capability-tools.ts
│   │   ├── sandbox-tools.ts
│   │   ├── redaction-tools.ts
│   │   └── attestation-tools.ts
│   │
│   └── storage/
│       ├── index.ts
│       ├── sqlite.ts
│       └── memory.ts
│
├── policies/
│   ├── default-redaction.yaml
│   └── default-capabilities.yaml
│
└── tests/
    ├── vault/
    ├── capability/
    ├── sandbox/
    └── integration/
```

## Configuration

### Environment Variables

```bash
# Core Settings
HORD_PORT=3001
HORD_HOST=127.0.0.1
HORD_TRANSPORT=stdio
HORD_LOG_LEVEL=info
HORD_STORAGE=sqlite

# Encryption
HORD_MASTER_KEY_FILE=/path/to/master.key
HORD_KEY_ROTATION_DAYS=90
HORD_USE_HARDWARE_KEY=true

# Sandbox
HORD_SANDBOX_RUNTIME=docker
HORD_SANDBOX_IMAGE=hord/sandbox:latest
HORD_SANDBOX_TIMEOUT_MS=30000
HORD_SANDBOX_MEMORY_MB=512

# Attestation
HORD_ATTESTATION_KEY_FILE=/path/to/attestation.key
HORD_ATTESTATION_CERT_FILE=/path/to/attestation.crt

# Integration with Mund
HORD_MUND_URL=http://localhost:3000
```

## Usage Examples

### Creating and Using a Vault

```typescript
// Create vault for agent
const vault = await hord.createVault({
  agent_id: 'agent-123',
  name: 'Agent Memory Vault',
  access_policy: {
    require_attestation: true,
    allowed_contexts: ['conversation', 'task']
  }
});

// Store a secret
await hord.storeSecret(vault.id, {
  name: 'github_token',
  value: 'ghp_xxxx',  // Will be encrypted
  classification: 'secret',
  expiry: new Date('2025-12-31')
});

// Retrieve with capability
const token = await hord.requestCapability({
  resource: `vault:${vault.id}/secrets/github_token`,
  actions: ['read'],
  justification: 'Need to commit code changes'
});

const secret = await hord.retrieveSecret(vault.id, 'github_token', token);
```

### Sandbox Execution

```typescript
// Create sandbox for code execution
const sandbox = await hord.createSandbox({
  type: 'code',
  isolation_level: 'container',
  resource_limits: {
    cpu_seconds: 10,
    memory_mb: 256,
    network_bytes: 0  // No network
  }
});

// Execute agent-generated code
const result = await hord.executeInSandbox(sandbox.id, {
  language: 'python',
  code: agentGeneratedCode,
  declared_intent: 'Calculate fibonacci sequence'
});

// Check if safe to promote
if (result.promotion_recommendation === 'safe') {
  await hord.promoteFromSandbox(sandbox.id);
}
```

### Semantic Redaction

```typescript
// Define redaction policy
const policy = await hord.createRedactionPolicy({
  name: 'customer-data',
  rules: [
    {
      field_pattern: '$.ssn',
      data_type: 'ssn',
      strategy: { type: 'tokenize', format_preserving: true },
      reversible: true
    },
    {
      field_pattern: '$.email',
      data_type: 'email',
      strategy: { type: 'mask', char: '*', preserve_length: false },
      reversible: false
    }
  ]
});

// Redact customer record
const redacted = await hord.redactContent(customerData, policy.id);
// { ssn: '987-65-4321', email: '****@****.***', ... }
// (SSN is tokenized - looks real but maps to nothing)

// Agent processes redacted data safely
const analysis = await agent.analyze(redacted.data);

// De-redact if needed (requires capability)
const original = await hord.deRedact(redacted, deRedactCapability);
```

## Roadmap

### Phase 1 (Current - MVP)
- [x] Vault encryption with AES-256-GCM
- [x] Basic capability tokens
- [x] Memory storage
- [x] MCP server implementation
- [ ] SQLite persistence
- [ ] Basic sandbox (process isolation)

### Phase 2
- [ ] Container-based sandbox
- [ ] Semantic redaction engine
- [ ] Capability delegation
- [ ] Attestation service
- [ ] Integration with Mund

### Phase 3
- [ ] Hardware key support (TPM)
- [ ] MicroVM sandboxing
- [ ] Format-preserving encryption
- [ ] Zero-knowledge proofs for compliance
- [ ] SIEM integration

### Phase 4
- [ ] Homomorphic encryption research
- [ ] Secure multi-party computation
- [ ] Federated attestation
- [ ] Enterprise HSM support

## Security Considerations

### Threat Model

Hord protects against:
- **Curious agents**: Agents trying to access data beyond their authorization
- **Compromised hosts**: Attackers with access to the host system
- **Data exfiltration**: Unauthorized data leaving the system
- **Tampering**: Modification of agent actions or outputs
- **Replay attacks**: Reuse of old capabilities or attestations

Hord does NOT protect against:
- **Compromised master key**: If master key is leaked, all vaults are at risk
- **Side-channel attacks**: Timing, power analysis (mitigated but not eliminated)
- **Malicious agent code**: Sandbox isolation, but not formal verification

### Key Management

- Master key should be stored in HSM or secure enclave where available
- Key rotation supported without re-encryption of all data
- Separate keys for encryption vs signing
- Emergency key recovery procedures

## Integration with Mund

Hord and Mund are designed to work together:

```
Agent Request
     │
     ▼
┌─────────┐    ┌─────────┐
│  MUND   │───▶│  HORD   │
│ (Watch) │    │ (Vault) │
└────┬────┘    └────┬────┘
     │              │
     │   Check      │   Grant
     │   Patterns   │   Capability
     │              │
     ▼              ▼
┌─────────────────────────┐
│     Execute Action      │
│   (with attestation)    │
└─────────────────────────┘
```

1. Request comes to Mund for pattern analysis
2. If safe, Hord issues capability token
3. Action executes with token
4. Hord creates attestation
5. Mund logs the event

## License

MIT License - See LICENSE file
