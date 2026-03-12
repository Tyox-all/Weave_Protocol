---
name: encrypting-data
description: Encrypt and decrypt sensitive data using AES-256-GCM or Yoxallismus cipher. Manage secrets in a secure vault. Use when protecting credentials, storing secrets securely, or when the user mentions encrypt, decrypt, vault, or Yoxallismus.
---

# Encrypting Data with Hord

## Overview

Hord provides encryption, the Yoxallismus dual-tumbler cipher, and secure vault storage. Use it to protect sensitive data at rest and in transit.

## MCP Tools

| Tool | Purpose |
|------|---------|
| `hord_encrypt` | Encrypt with AES-256-GCM |
| `hord_decrypt` | Decrypt AES-256-GCM data |
| `hord_yoxallismus_lock` | Lock with Yoxallismus cipher (maximum security) |
| `hord_yoxallismus_unlock` | Unlock Yoxallismus data |
| `hord_vault_store` | Store secret in vault |
| `hord_vault_retrieve` | Retrieve secret from vault |
| `hord_generate_key` | Generate secure random key |

## Quick Examples

### Basic encryption
```
hord_encrypt({ data: "sensitive", key: "my-key" })
→ { ciphertext: "...", iv: "...", tag: "..." }
```

### Yoxallismus lock (enhanced security)
```
hord_yoxallismus_lock({ data: "top secret", key: "master-key" })
→ { locked: "yox1:tumbler:deadbolt:payload" }
```

### Store in vault
```
hord_vault_store({ name: "db-password", secret: "pass123" })
→ { stored: true, name: "db-password" }
```

## Yoxallismus Cipher

Dual-layer encryption: AES-256-GCM + position-dependent obfuscation. Use for maximum security when standard encryption isn't enough.

## When to Use

1. Before storing credentials or API keys
2. When transmitting sensitive data
3. For maximum security, use Yoxallismus over standard AES
4. Use vault for persistent secret storage

## Links

- npm: https://www.npmjs.com/package/@weave_protocol/hord
