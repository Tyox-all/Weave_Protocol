# 🏰 Hord - Vault Protocol

[![npm version](https://img.shields.io/npm/v/@weave_protocol/hord.svg)](https://www.npmjs.com/package/@weave_protocol/hord)
[![license](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**Secure containment, encryption, and sandboxing for AI agent data.**

Part of the [Weave Protocol Security Suite](https://github.com/Tyox-all/Weave_Protocol).

## ✨ Features

| Category | Features |
|----------|----------|
| **Vault** | AES-256-GCM encryption, key rotation, secure storage |
| **Yoxallismus v1** | ⚠️ Deprecated: output can't be decrypted. Use [`@weave_protocol/yoxallismus`](https://github.com/Tyox-all/Weave_Protocol/tree/main/yoxallismus) |
| **Redaction** | PII/PHI masking, reversible tokenization |
| **Sandbox** | OS-level isolation (network, filesystem, env), memory/CPU limits, process-group kill |
| **Capability** | Token-based access control, delegation chains |
| **Attestation** | Cryptographic proof of agent actions |

## 📦 Installation

```bash
npm install @weave_protocol/hord
```

## 🚀 Quick Start

```typescript
import { VaultManager } from '@weave_protocol/hord';

// Encrypted vault storage
const vault = new VaultManager({ encryption_key: 'your-secret-key' });
await vault.store('api-keys', { openai: 'sk-xxx' }, { encrypt: true });
const secrets = await vault.retrieve('api-keys');
```

---

## ⚠️ Yoxallismus Vault Cipher (v1): deprecated

`YoxallismusCipher` is **deprecated as of 0.1.8**. Its `lock()` output **cannot be decrypted**, by its own `unlock()` or by any other implementation: the XOR mask is derived from a seed that hashes the plaintext, and only part of that seed is stored. See advisory [YOXALL-2026-003](https://github.com/Tyox-all/Weave_Protocol/blob/main/yoxallismus/SECURITY_ADVISORIES.md).

Hord's vault never used this cipher, so `VaultManager` data is unaffected.

What changed in 0.1.8:
- Constructing a `YoxallismusCipher` emits a one-time `DeprecationWarning` (code `HORD_YOXALLISMUS_V1`).
- `unlock()` and `decode()` throw `YoxallismusV1UnrecoverableError` instead of silently returning the wrong bytes.
- `lock()` and `encode()` still run, so existing imports don't break, but their output is one-way.

**Use [`@weave_protocol/yoxallismus`](https://github.com/Tyox-all/Weave_Protocol/tree/main/yoxallismus) instead.** It's real authenticated, post-quantum hybrid encryption:

```typescript
import { generateHybridKeypair, publicKeyOf, seal, open } from '@weave_protocol/yoxallismus';

const key = generateHybridKeypair();
const sealed = seal(publicKeyOf(key), Buffer.from('sensitive data'));
const data = open(key, sealed);
```

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

## 🏖️ Sandbox Executor (real isolation as of 0.1.9)

Runs code or commands in an isolated child process, using what the host OS provides:

| Layer | macOS | Linux |
|-------|-------|-------|
| Network | `sandbox-exec` profile denies all network | `bwrap --unshare-net`, or `unshare -rn` |
| Filesystem | Writes only inside the sandbox workdir; no reads of `$HOME` | `bwrap`: read-only `/`, private `/tmp` and `$HOME`, workdir read-write |
| Environment | Scrubbed to `PATH`/`HOME`/`TMPDIR`/`LANG`, so the parent's API keys never leak in | same |
| Limits | `ulimit` CPU seconds, file size, file descriptors | same |
| Memory | Watchdog sums the process group's RSS, kills it over the limit, and reports the real peak | same |
| Processes | Own process group; a timeout or overrun kills every descendant | same |

Every result carries an `isolation` report saying exactly what was enforced. A missing layer (e.g. Linux without `bwrap` or user namespaces) adds an `isolation_unavailable` warning and downgrades the recommendation to REVIEW. With `enforcement: 'strict'`, Hord refuses to run instead. A memory overrun is a `violation` and recommends BLOCK; a signal-killed process reports `128 + signal` (e.g. 137), never 0.

```text
hord_create_sandbox      { "type": "code", "memory_mb": 128, "timeout_ms": 5000, "enforcement": "strict" }
hord_execute_in_sandbox  { "sandbox_id": "...", "type": "code", "language": "javascript",
                           "content": "console.log(1 + 1)", "declared_intent": "arithmetic check" }
→ { "status": "success", "stdout": "2", "promotion_recommendation": "safe",
    "isolation": { "mechanism": "sandbox-exec", "network": "blocked", "filesystem": "restricted", ... } }
```

This is process-level isolation, not a VM: kernel exploits and side channels are out of scope. For hostile code, also run Hord inside a container or VM.

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

### YoxallismusCipher (deprecated)

| Method | Description |
|--------|-------------|
| `lock(data)` / `encode(string)` | One-way: output can't be decrypted. Warns once. |
| `unlock(data)` / `decode(string)` | Throws `YoxallismusV1UnrecoverableError` |
| `getInfo()` | Get cipher configuration |

Use `seal()` / `open()` from `@weave_protocol/yoxallismus` for encryption.

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
