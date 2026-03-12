---
name: hord
description: "Use this skill whenever encryption, decryption, or secure storage is needed. Triggers: encrypting sensitive data, decrypting data, storing secrets securely, using the Yoxallismus cipher, managing vault contents, protecting API keys or credentials, or any request involving 'encrypt', 'decrypt', 'secure storage', 'vault', 'lock data', 'protect', or 'Yoxallismus'. Use Hord before storing or transmitting sensitive information."
license: Apache 2.0
---

# 🏛️ Hord - Secure Vault Guide

## Overview

Hord is an encrypted vault system with the Yoxallismus dual-tumbler cipher. Use it to encrypt sensitive data, manage secrets securely, and protect credentials with military-grade encryption.

## Quick Start

```typescript
import { YoxallismusCipher } from '@weave_protocol/hord';

const cipher = new YoxallismusCipher('master-key');

// Lock (encrypt + obfuscate)
const locked = await cipher.lock(sensitiveData);

// Unlock (de-obfuscate + decrypt)
const unlocked = await cipher.unlock(locked);
```

## MCP Tools Available

When running as an MCP server, these tools are available:

| Tool | Use When |
|------|----------|
| `hord_encrypt` | Encrypting data with AES-256-GCM |
| `hord_decrypt` | Decrypting AES-256-GCM encrypted data |
| `hord_yoxallismus_lock` | Locking data with Yoxallismus cipher |
| `hord_yoxallismus_unlock` | Unlocking Yoxallismus-locked data |
| `hord_vault_store` | Storing a secret in the vault |
| `hord_vault_retrieve` | Retrieving a secret from the vault |
| `hord_vault_list` | Listing vault contents |
| `hord_vault_delete` | Removing a secret from the vault |
| `hord_generate_key` | Generating a secure random key |

---

## Common Tasks

### Basic Encryption

```typescript
// MCP tool call
hord_encrypt({ 
  data: "sensitive information",
  key: "encryption-key"
})

// Response
{
  ciphertext: "base64-encoded-ciphertext",
  iv: "initialization-vector",
  tag: "auth-tag"
}
```

### Basic Decryption

```typescript
hord_decrypt({
  ciphertext: "base64-encoded-ciphertext",
  key: "encryption-key",
  iv: "initialization-vector",
  tag: "auth-tag"
})

// Response
{
  plaintext: "sensitive information"
}
```

### Yoxallismus Lock (Enhanced Security)

```typescript
hord_yoxallismus_lock({
  data: "top secret data",
  key: "master-key"
})

// Response
{
  locked: "yox1:tumbler-state:deadbolt-state:encrypted-payload",
  metadata: {
    algorithm: "yoxallismus-v1",
    timestamp: "2024-01-15T10:30:00Z"
  }
}
```

### Yoxallismus Unlock

```typescript
hord_yoxallismus_unlock({
  locked: "yox1:tumbler-state:deadbolt-state:encrypted-payload",
  key: "master-key"
})

// Response
{
  data: "top secret data"
}
```

### Store Secret in Vault

```typescript
hord_vault_store({
  name: "database-password",
  secret: "super-secret-password",
  metadata: { environment: "production" }
})

// Response
{
  stored: true,
  name: "database-password",
  created_at: "2024-01-15T10:30:00Z"
}
```

### Retrieve Secret from Vault

```typescript
hord_vault_retrieve({ name: "database-password" })

// Response
{
  name: "database-password",
  secret: "super-secret-password",
  metadata: { environment: "production" }
}
```

### Generate Secure Key

```typescript
hord_generate_key({ length: 32 })

// Response
{
  key: "base64-encoded-random-key",
  bytes: 32
}
```

---

## Yoxallismus Cipher Explained

The Yoxallismus cipher is a dual-layer encryption system:

1. **Layer 1 - AES-256-GCM:** Industry-standard authenticated encryption
2. **Layer 2 - Tumbler/Deadbolt:** Position-dependent obfuscation

```
┌─────────────────────────────────────────┐
│              YOXALLISMUS                │
├─────────────────────────────────────────┤
│  Plaintext                              │
│      ↓                                  │
│  AES-256-GCM Encryption                 │
│      ↓                                  │
│  Tumbler Rotation (position-based)      │
│      ↓                                  │
│  Deadbolt Transform (key-derived)       │
│      ↓                                  │
│  Final Ciphertext                       │
└─────────────────────────────────────────┘
```

**Why use Yoxallismus?**
- Defense in depth: Even if AES is compromised, data remains obfuscated
- Position-dependent: Same plaintext produces different ciphertext at different positions
- Key-derived transforms: Obfuscation is tied to the encryption key

---

## Encryption Options

| Algorithm | Use Case | Strength |
|-----------|----------|----------|
| `aes-256-gcm` | Standard encryption | High |
| `chacha20-poly1305` | Mobile/embedded | High |
| `yoxallismus` | Maximum security | Very High |

---

## Best Practices

1. **Never hardcode keys** - Use environment variables or key management
2. **Use Yoxallismus** for the most sensitive data
3. **Rotate keys** periodically using `hord_generate_key`
4. **Use the vault** instead of storing secrets in code
5. **Scan with Mund** before encrypting to ensure no secrets leak

---

## Key Derivation

Hord uses Argon2id for key derivation:

```typescript
import { deriveKey } from '@weave_protocol/hord';

const key = await deriveKey({
  password: 'user-password',
  salt: 'unique-salt',
  iterations: 3,
  memory: 65536,
  parallelism: 4
});
```

---

## Links

- **npm:** https://www.npmjs.com/package/@weave_protocol/hord
- **GitHub:** https://github.com/Tyox-all/Weave_Protocol
