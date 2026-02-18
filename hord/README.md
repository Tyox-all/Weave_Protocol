# 🏰 Hord - Vault Protocol

[![npm version](https://img.shields.io/npm/v/@weave_protocol/hord.svg)](https://www.npmjs.com/package/@weave_protocol/hord)
[![license](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**Secure containment, encryption, and sandboxing for AI agent data.**

Part of the [Weave Protocol Security Suite](https://github.com/Tyox-all/Weave_Protocol).

## ✨ Features

| Category | Features |
|----------|----------|
| **Vault** | AES-256-GCM encryption, key rotation, secure storage |
| **Yoxallismus** | Dual-mechanism obfuscation cipher (tumbler + deadbolt) |
| **Redaction** | PII/PHI masking, reversible tokenization |
| **Sandbox** | Isolated code execution, resource limits, timeout enforcement |
| **Capability** | Token-based access control, delegation chains |
| **Attestation** | Cryptographic proof of agent actions |

## 📦 Installation

```bash
npm install @weave_protocol/hord
```

## 🚀 Quick Start

```typescript
import { VaultManager, YoxallismusCipher } from '@weave_protocol/hord';

// Encrypted vault storage
const vault = new VaultManager({ encryption_key: 'your-secret-key' });
await vault.store('api-keys', { openai: 'sk-xxx' }, { encrypt: true });
const secrets = await vault.retrieve('api-keys');

// Yoxallismus obfuscation layer
const cipher = new YoxallismusCipher({ key: 'master-key', tumblers: 7 });
const locked = cipher.lock(sensitiveData);
const unlocked = cipher.unlock(locked);
```

---

## 🔐 Yoxallismus Vault Cipher

*Named after Leslie Yoxall's WWII Bletchley Park codebreaking technique*

A dual-mechanism obfuscation layer combining:
- **Tumbler**: Revolving permutation (like spinning a vault dial)
- **Deadbolt**: Position-dependent XOR masking (the manual lock)
- **Entropy**: Decoy byte injection to obscure patterns

```typescript
import { YoxallismusCipher } from '@weave_protocol/hord';

const vault = new YoxallismusCipher({
  key: 'your-master-key',
  tumblers: 7,          // 1-12 dial positions
  entropy_ratio: 0.2,   // 20% decoy bytes
  revolving: true       // Pattern changes per block
});

// Lock data (encode + obfuscate)
const locked = vault.lock(Buffer.from('sensitive data'));

// Unlock data (decode + reveal)
const unlocked = vault.unlock(locked);

// String convenience methods
const encoded = vault.encode('secret message');
const decoded = vault.decode(encoded);
```

### How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                    YOXALLISMUS VAULT                        │
├─────────────────────────────────────────────────────────────┤
│  PLAINTEXT                                                  │
│      │                                                      │
│      ▼                                                      │
│  ┌─────────────────────────────────────┐                    │
│  │  1. ENTROPY INJECTION               │                    │
│  │     Insert decoy bytes              │                    │
│  └─────────────────────────────────────┘                    │
│      │                                                      │
│      ▼                                                      │
│  ┌─────────────────────────────────────┐                    │
│  │  2. TUMBLER PERMUTATION             │                    │
│  │     Revolving shuffle (1-12 dials)  │                    │
│  └─────────────────────────────────────┘                    │
│      │                                                      │
│      ▼                                                      │
│  ┌─────────────────────────────────────┐                    │
│  │  3. DEADBOLT XOR MASK               │                    │
│  │     Position-dependent masking      │                    │
│  └─────────────────────────────────────┘                    │
│      │                                                      │
│      ▼                                                      │
│  CIPHERTEXT (YXLS header)                                   │
└─────────────────────────────────────────────────────────────┘
```

| Option | Default | Description |
|--------|---------|-------------|
| `key` | required | Master key for derivation |
| `tumblers` | 7 | Dial positions (1-12) |
| `entropy_ratio` | 0.2 | Decoy byte ratio (0.1-0.5) |
| `revolving` | true | Pattern changes per block |
| `block_size` | 64 | Processing block size |

---

## 🔒 Vault Manager

Encrypted storage with key rotation.

```typescript
import { VaultManager } from '@weave_protocol/hord';

const vault = new VaultManager({
  encryption_key: 'your-256-bit-key',
  key_rotation_days: 90
});

// Store encrypted data
await vault.store('credentials', {
  api_key: 'sk-xxx',
  database_url: 'postgres://...'
}, { 
  encrypt: true,
  ttl_ms: 3600000  // 1 hour expiry
});

// Retrieve and decrypt
const creds = await vault.retrieve('credentials');

// Rotate encryption keys
await vault.rotateKey('new-encryption-key');
```

---

## ✂️ Redaction Engine

Mask sensitive data with reversible tokenization.

```typescript
import { RedactionEngine } from '@weave_protocol/hord';

const redactor = new RedactionEngine({ signing_key: 'redaction-key' });

// Redact PII
const result = await redactor.redact(
  'Contact john@example.com or call 555-1234',
  { patterns: ['email', 'phone'] }
);
// "Contact [REDACTED:email:abc123] or call [REDACTED:phone:def456]"

// Restore original
const original = await redactor.restore(result.redacted_text, result.tokens);
```

---

## 🏖️ Sandbox Executor

Isolated code execution with resource limits.

```typescript
import { SandboxExecutor } from '@weave_protocol/hord';

const sandbox = new SandboxExecutor({
  timeout_ms: 5000,
  memory_limit_mb: 128,
  allowed_modules: ['lodash', 'moment']
});

const result = await sandbox.execute({
  code: `
    const _ = require('lodash');
    return _.sum([1, 2, 3, 4, 5]);
  `,
  context: {}
});

console.log(result.output);  // 15
```

---

## 🎫 Capability Tokens

Token-based access control with delegation.

```typescript
import { CapabilityTokenService } from '@weave_protocol/hord';

const caps = new CapabilityTokenService('signing-key');

// Issue token
const token = await caps.issue({
  subject: 'agent-1',
  capabilities: ['read:vault', 'write:logs'],
  expires_in_ms: 3600000
});

// Verify token
const verified = await caps.verify(token.token);
if (verified.valid) {
  console.log(verified.capabilities);
}

// Delegate subset
const delegated = await caps.delegate(token.token, {
  to: 'agent-2',
  capabilities: ['read:vault']
});
```

---

## ✅ Attestation Service

Cryptographic proof of agent actions.

```typescript
import { AttestationService } from '@weave_protocol/hord';

const attestation = new AttestationService('signing-key');

// Attest an action
const proof = await attestation.attest({
  agent_id: 'agent-1',
  action: 'api_call',
  resource: 'openai',
  context: { model: 'gpt-4' }
});

// Verify later
const valid = await attestation.verify(proof.attestation_id);
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        WEAVE PROTOCOL SUITE                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐           │
│  │     MUND      │  │     HORD      │  │    DŌMERE     │           │
│  │   Guardian    │  │     Vault     │  │     Judge     │           │
│  ├───────────────┤  ├───────────────┤  ├───────────────┤           │
│  │ • Watches     │  │ • Encrypts    │  │ • Verifies    │           │
│  │ • Scans       │  │ • Isolates    │  │ • Orchestrates│           │
│  │ • Alerts      │  │ • Contains    │  │ • Attests     │           │
│  │               │  │ • Yoxallismus │  │ • Compliance  │           │
│  └───────────────┘  └───────────────┘  └───────────────┘           │
│          │                  │                   │                   │
│          └──────────────────┴───────────────────┘                   │
│                             │                                       │
│              ┌──────────────▼──────────────┐                        │
│              │          WITAN              │                        │
│              │    Council Protocol         │                        │
│              │  Consensus + Governance     │                        │
│              └─────────────────────────────┘                        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 📚 API Reference

### YoxallismusCipher

| Method | Description |
|--------|-------------|
| `lock(data)` | Lock data through vault (Buffer) |
| `unlock(data)` | Unlock data from vault (Buffer) |
| `encode(string)` | Lock and base64 encode |
| `decode(string)` | Decode and unlock |
| `getInfo()` | Get cipher configuration |

### VaultManager

| Method | Description |
|--------|-------------|
| `store(key, data, options)` | Store encrypted data |
| `retrieve(key)` | Retrieve and decrypt |
| `delete(key)` | Remove from vault |
| `rotateKey(newKey)` | Rotate encryption key |
| `list()` | List stored keys |

### RedactionEngine

| Method | Description |
|--------|-------------|
| `redact(text, options)` | Redact sensitive patterns |
| `restore(text, tokens)` | Restore original text |
| `addPattern(name, regex)` | Add custom pattern |

### SandboxExecutor

| Method | Description |
|--------|-------------|
| `execute(params)` | Execute code in sandbox |
| `validateCode(code)` | Check code safety |

### CapabilityTokenService

| Method | Description |
|--------|-------------|
| `issue(params)` | Issue capability token |
| `verify(token)` | Verify token validity |
| `delegate(token, params)` | Delegate to another agent |
| `revoke(tokenId)` | Revoke a token |

---

## 🔗 Related Packages

| Package | Description |
|---------|-------------|
| [@weave_protocol/mund](https://www.npmjs.com/package/@weave_protocol/mund) | Secret & threat scanning |
| [@weave_protocol/domere](https://www.npmjs.com/package/@weave_protocol/domere) | Verification & orchestration |
| [@weave_protocol/witan](https://www.npmjs.com/package/@weave_protocol/witan) | Consensus & governance |
| [@weave_protocol/api](https://www.npmjs.com/package/@weave_protocol/api) | Universal REST API |

## 📄 License

Apache 2.0

---

**Made with ❤️ for AI Safety**
