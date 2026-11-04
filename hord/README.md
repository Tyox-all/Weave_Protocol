# 🏰 Hord - Vault Protocol

[![npm version](https://img.shields.io/npm/v/@weave_protocol/hord.svg)](https://www.npmjs.com/package/@weave_protocol/hord)
[![license](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**Secure containment, encryption, and sandboxing for AI agent data.**

Part of the [Weave Protocol Security Suite](https://github.com/Tyox-all/Weave_Protocol).

## 🆕 What's new

**0.3.0: vaults survive restarts.** `createStorage('sqlite')` uses Node's built-in SQLite, with no native dependency. Vault keys are stored wrapped with your master key, so a vault reopens after a restart only with the same `HORD_MASTER_KEY`. Database files are created with mode `0600`. See [Storage](#-storage).

**0.2.0: library API and a key-derivation fix.**
- Everything below is importable.
- [HORD-2026-001](https://github.com/Tyox-all/Weave_Protocol/blob/main/hord/SECURITY_ADVISORIES.md) is fixed: every non-hex master key used to derive the same key. Upgrade if you set `HORD_MASTER_KEY` to a passphrase.
- Sealed vaults can be reopened.

**0.1.9: real sandbox isolation.** See [Sandbox Executor](#️-sandbox-executor).

## ✨ Features

| Category | Features |
|----------|----------|
| **Vault** | AES-256-GCM encrypted credentials, memories, state and artifacts; SQLite or in-memory storage |
| **Yoxallismus v1** | ⚠️ Deprecated: output can't be decrypted. Use [`@weave_protocol/yoxallismus`](https://github.com/Tyox-all/Weave_Protocol/tree/main/yoxallismus) |
| **Redaction** | Policy-based masking, hashing and tokenization; reversible PII tokens |
| **Sandbox** | OS-level isolation (network, filesystem, env), memory/CPU limits, process-group kill |
| **Capability** | Scoped, expiring access tokens with attenuated delegation |
| **Attestation** | Signed, chained records of agent actions, verifiable later |

## 📦 Installation

```bash
npm install @weave_protocol/hord
```

## 🚀 Quick Start

```typescript
import { createStorage, keyStore, VaultManager } from '@weave_protocol/hord';

keyStore.initialize(process.env.HORD_MASTER_KEY!); // 64 hex chars, or a passphrase
const vaults = new VaultManager(createStorage('sqlite')); // or 'memory'

const vault = await vaults.createVault({ agent_id: 'billing-agent', name: 'api-keys', access_policy: {} });
await vaults.openVault(vault.id, 'billing-agent');
await vaults.storeCredential(vault.id, 'billing-agent', { name: 'stripe', type: 'api_key', value: 'sk_test_example' });

const key = await vaults.retrieveCredential(vault.id, 'billing-agent', 'stripe');
await vaults.sealVault(vault.id, 'billing-agent'); // wipes the vault key from memory
```

Every operation is written to an access log. As an MCP server, `hord-mcp` exposes the same functions as tools (`hord_create_vault`, `hord_store_secret`, `hord_retrieve_secret`, …).

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

## 🔑 Master key

Vault keys are wrapped with a master key. Set one of:

| Variable | Value |
|---|---|
| `HORD_MASTER_KEY` | 64 hex characters (`openssl rand -hex 32`), or a passphrase (run through PBKDF2) |
| `HORD_MASTER_KEY_FILE` | path to a file containing the key |

With neither set, Hord generates a random key for the process, so vault contents can't be read after it exits.

> **Advisory [HORD-2026-001](https://github.com/Tyox-all/Weave_Protocol/blob/main/hord/SECURITY_ADVISORIES.md):** before 0.2.0, any master key that wasn't pure hex, including the built-in default, produced the same master key on every install. Upgrade, or set a 64-hex-character key.

## 💾 Storage

By default Hord keeps everything in memory. For data that survives restarts, use SQLite (Node 22.5+, no extra dependency):

| Variable | Value |
|---|---|
| `HORD_STORAGE` | `memory` (default) or `sqlite` |
| `HORD_DATABASE_URL` | SQLite file path (default `~/.weave/hord.sqlite`, created with `0600` permissions) |

Vault keys are stored wrapped with the master key, so a persisted vault opens only with the same `HORD_MASTER_KEY`. In code: `createStorage('sqlite', { path })`. PostgreSQL is not implemented, and selecting it is an error.

## 🔒 Vault Manager

A vault belongs to an agent and holds encrypted credentials, memories, state and artifacts. It must be opened before use and sealed after; sealing wipes its key from memory.

| Method | Description |
|--------|-------------|
| `createVault({ agent_id, name, access_policy })` | Create a vault with its own encryption key |
| `openVault(vaultId, agentId)` / `sealVault(vaultId, agentId)` | Unlock or lock a vault |
| `storeCredential(vaultId, agentId, { name, type, value })` | Encrypt and store a secret |
| `retrieveCredential(vaultId, agentId, name)` | Decrypt a secret |
| `storeMemory` / `retrieveMemories` / `storeState` / `retrieveState` / `storeArtifact` | Other vault contents |
| `listVaults(agentId)` / `getVaultInfo(vaultId)` / `deleteVault(vaultId, agentId)` | Manage vaults |

---

## ✂️ Redaction Engine

Tokenize PII before text reaches a model, and restore it afterwards:

```typescript
import { createStorage, RedactionEngine } from '@weave_protocol/hord';

const redactor = new RedactionEngine(createStorage('memory'));
const { tokenized } = await redactor.tokenizePII('Email jane@example.com about the invoice');
// The email is replaced by a token; send `tokenized` to the model
const restored = await redactor.deTokenize(modelOutput);
```

For structured data, `createPolicy()` defines rules that mask, hash, tokenize, generalize or encrypt fields. `redact(data, policyId)` applies them, and `deRedact()` reverses the reversible ones.

---

## 🏖️ Sandbox Executor

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

Scoped, expiring permissions an agent can delegate in narrower form:

```typescript
import { createStorage, CapabilityManager, ActionType } from '@weave_protocol/hord';

const caps = new CapabilityManager(createStorage('memory'));
const token = await caps.createCapabilityToken({
  agent_id: 'agent-1',
  resource: { type: 'vault', id: 'api-keys' },
  actions: [ActionType.READ],
  delegatable: true,
});

await caps.verifyCapabilityToken(token.id, 'agent-1', { type: 'vault', id: 'api-keys' }, ActionType.READ);  // { valid: true }
await caps.verifyCapabilityToken(token.id, 'agent-1', { type: 'vault', id: 'api-keys' }, ActionType.WRITE); // { valid: false, reason }

await caps.delegateCapability({ parent_token_id: token.id, delegate_to_agent: 'agent-2', justification: 'read-only helper' });
```

`revokeCapability()` and `listCapabilities()` complete the set. Tokens need `keyStore.initialize()` first.

---

## ✅ Attestation Service

A signed, chained record of what an agent did:

```typescript
import { createStorage, AttestationService } from '@weave_protocol/hord';

const attest = new AttestationService(createStorage('sqlite'));
const proof = await attest.attestAction('agent-1', 'api_call', 'Charged invoice 1042', ['stripe:invoices'], { result: 'success' });

const check = await attest.verify(proof.id); // signature, timestamp and chain checks
```

`getAttestationChain()` walks the chain, and `exportForAudit()` exports a time range.

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
│  │               │  │               │  │ • Compliance  │           │
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

### Classes

Each takes a storage backend from `createStorage('sqlite' | 'memory')`.

| Class | Main methods |
|-------|--------------|
| `VaultManager` | See [Vault Manager](#-vault-manager) |
| `RedactionEngine` | `createPolicy`, `redact`, `deRedact`, `tokenizePII`, `deTokenize` |
| `SandboxManager` | `createSandbox`, `execute`, `promote`, `destroy`, `getResults` |
| `CapabilityManager` | `createCapabilityToken`, `verifyCapabilityToken`, `useCapabilityToken`, `delegateCapability`, `revokeCapability` |
| `AttestationService` | `attest`, `attestAction`, `verify`, `getAttestationChain`, `exportForAudit` |

These examples are run as tests (`tests/readme-examples.test.ts`).

---

## 🕸️ Part of Weave Protocol

One [WARD.md](https://github.com/Tyox-all/Weave_Protocol) policy for every agent you run, locally or at scale, plus the tools around it.

| Package | What it does |
|---|---|
| [Ward](https://www.npmjs.com/package/@weave_protocol/ward) | The WARD.md policy standard and the tool-call evaluator every adapter shares |
| [Mund](https://www.npmjs.com/package/@weave_protocol/mund) | Scans content for prompt injection, secrets, PII and exfiltration |
| [Hord](https://www.npmjs.com/package/@weave_protocol/hord) | Encrypted vaults, PII tokenization, sandboxes, capability tokens, attestations |
| [Dōmere](https://www.npmjs.com/package/@weave_protocol/domere) | Audit threads, compliance checkpoints, GDPR and CCPA records, anchoring |
| [Witan](https://www.npmjs.com/package/@weave_protocol/witan) | Multi-agent consensus and spending caps |
| [Hundredmen](https://www.npmjs.com/package/@weave_protocol/hundredmen) | MCP proxy that enforces WARD.md on tool calls |
| [Tollere](https://www.npmjs.com/package/@weave_protocol/tollere) | Supply-chain checks: typosquats, CVEs, suspicious version diffs |
| [Browser](https://www.npmjs.com/package/@weave_protocol/browser) | WARD.md and injection scanning for Playwright browser agents |
| Adapters | WARD.md in [Claude Code](https://www.npmjs.com/package/@weave_protocol/adapter-claudecode), [Antigravity](https://www.npmjs.com/package/@weave_protocol/adapter-antigravity), [MSAF](https://www.npmjs.com/package/@weave_protocol/adapter-msaf), [Gemini CLI](https://www.npmjs.com/package/@weave_protocol/adapter-geminicli), [Codex](https://www.npmjs.com/package/@weave_protocol/adapter-codex), [OpenCode](https://www.npmjs.com/package/@weave_protocol/adapter-opencode) and [Cursor](https://www.npmjs.com/package/@weave_protocol/adapter-cursor) |
| [Adversary](https://www.npmjs.com/package/@weave_protocol/adversary) · [AgentSecBench](https://www.npmjs.com/package/@weave_protocol/agentsecbench) | Red-team engine and locked benchmark |
| [API](https://www.npmjs.com/package/@weave_protocol/api) · [CLI](https://www.npmjs.com/package/@weave_protocol/cli) · [LangChain](https://www.npmjs.com/package/@weave_protocol/langchain) | REST API and dashboard, setup CLI, LangChain.js integration |
| [full](https://www.npmjs.com/package/@weave_protocol/full) | Every defensive package in one install |
| [Yoxallismus](https://www.npmjs.com/package/@weave_protocol/yoxallismus) | Post-quantum hybrid cipher (experimental beta) |

## 📄 License

Apache 2.0

---

**Made with ❤️ for AI Safety**
