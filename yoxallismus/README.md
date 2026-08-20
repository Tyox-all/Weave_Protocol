# 🔐 @weave_protocol/yoxallismus

> **Post-quantum cryptographic composition layer for AI agents.**
> Built on NIST-standardized primitives. Composed for multi-agent, memory-persistent, headless-tool architectures.

[![npm](https://img.shields.io/npm/v/@weave_protocol/yoxallismus?color=000&style=flat-square)](https://www.npmjs.com/package/@weave_protocol/yoxallismus)
[![License](https://img.shields.io/badge/license-Apache--2.0-000?style=flat-square)](../LICENSE)
[![Status](https://img.shields.io/badge/status-EXPERIMENTAL-red?style=flat-square)]()
[![Audit](https://img.shields.io/badge/external%20audit-none-red?style=flat-square)]()

---

## ⚠️ EXPERIMENTAL — NOT AUDITED ⚠️

**This library has NOT undergone external cryptographic audit.**

**DO NOT USE for:**
- Regulated data (HIPAA, PCI-DSS, SOC2-audited storage)
- Medical records
- Financial records
- Legal evidence
- Any system where a cryptographic failure would cause real-world harm

**DO USE for:**
- Research on post-quantum agent architectures
- Experimentation with PQ-hybrid primitives
- Development against future PQ-cryptographic patterns
- Learning post-quantum cryptography by example

**Read [THREAT_MODEL.md](THREAT_MODEL.md) and [SECURITY.md](SECURITY.md) before using this library for anything.**

The version is `0.1.0-beta.0` for a reason. The wire format may break between v0.1 and v0.2. Formal external audit is not currently planned — the library is being validated by public use, forks, community verification, and a coordinated-disclosure program. Your judgment as an adopter is your only safety net; make it well.

---

## What this is

An agent-native cryptographic composition layer built on NIST FIPS 203 (ML-KEM-768) and standard classical primitives (X25519, AES-256-GCM, HKDF-SHA-256). It doesn't invent new cryptographic primitives — it composes audited ones for the specific threat surface of long-lived, multi-agent AI systems.

The design principle: **novel architecture, standardized primitives.** The primitives (X25519, ML-KEM-768, AES-256-GCM, HKDF) are NIST-standardized or de facto industry standard. The composition (PQ-hybrid KEM, session ratcheting, agent-scoped context binding) is what's novel and what should be scrutinized.

## What this isn't

- **Not a replacement for liboqs, PQClean, or BoringSSL.** Those libraries are the primitive layer. This library composes them for agent use cases.
- **Not audited.** Signal, Cloudflare, Google, and every serious PQ-crypto deployment has been externally audited. This library has not.
- **Not production-ready.** v0.1.0-beta.0 explicitly.

## Installation

```bash
npm install @weave_protocol/yoxallismus
```

To silence the runtime beta banner:

```bash
export YOXALL_SILENCE_BETA_WARNING=1
```

## Quick start (programmatic)

```typescript
import { PQCipher } from '@weave_protocol/yoxallismus';

// Alice generates a keypair, shares her public key
const alice = PQCipher.generateKeypair();
const alicePub = PQCipher.publicKeyOf(alice);

// Bob encrypts a message to Alice
const bundle = PQCipher.encryptTo(alicePub, new TextEncoder().encode('secret'));

// Alice decrypts
const message = PQCipher.decryptFrom(alice, bundle.ciphertext, bundle.payload);
console.log(new TextDecoder().decode(message)); // "secret"
```

## Quick start (CLI)

```bash
# Generate a hybrid keypair
weave-yoxall keygen --out=./alice

# Encrypt a file to a public key
weave-yoxall encrypt --to=./alice.pub --in=./message.txt

# Decrypt with the corresponding private key
weave-yoxall decrypt --with=./alice.priv --in=./message.txt.yox

# See status, primitives, known limitations
weave-yoxall status

# Run the reproducible-claims test suite
weave-yoxall test

# Run known-attack test vectors
weave-yoxall audit-self

# Benchmarks
weave-yoxall benchmark
```

## What's inside (v0.1.0-beta.0)

| Component | Primitive | Size / Cost |
|---|---|---|
| Classical KEM | X25519 (Node crypto) | 32B pub / 32B priv |
| Post-quantum KEM | ML-KEM-768 via `@noble/post-quantum` (NIST FIPS 203) | 1184B pub / 2400B priv |
| Hybrid combination | HKDF-SHA-256 over concatenated shared secrets | 32B output |
| AEAD | AES-256-GCM (Node crypto) | 12B nonce, 16B tag |
| KDF | HKDF-SHA-256 (Node crypto) | 32B default |
| Ratchet | Symmetric ratchet (chain-key advance via HKDF) | Forward secrecy within session |
| Wire format | JSON envelopes with `_type` + `_version` discriminator | Base64url values |

## Performance (v0.1.0-beta.0)

Measured on Node.js 22, x86_64, single-threaded, warm cache:

| Operation | Time per op |
|---|---|
| AEAD encrypt (1 KB) | ~0.024 ms |
| Hybrid keypair generation | ~3.1 ms |
| Hybrid encap + decap | ~2.4 ms |
| End-to-end PQCipher (1 KB) | ~2.3 ms |

Reproduce with `weave-yoxall benchmark`.

## Reproducible claims

Every claim in this README is backed by a runnable test. To verify:

```bash
weave-yoxall test
```

This runs assertions on:
- AEAD encrypt/decrypt roundtrip
- Ciphertext bit-flip rejection
- AAD binding
- PQ-hybrid keypair sizes match NIST FIPS 203
- Encapsulate/decapsulate produce matching shared secrets
- Wrong recipient cannot decrypt
- Ratchet forward-motion and message counter
- Serialization roundtrip preserves bytes

To verify known-attack vectors are rejected:

```bash
weave-yoxall audit-self
```

## Known limitations

- **No formal external audit** performed
- **No threshold encryption** (multi-agent m-of-n) yet — planned v0.2+
- **No DH double-ratchet** — v0.1 only has symmetric ratcheting; no post-compromise recovery. Planned v0.2.
- **No zero-knowledge proofs** yet — planned v0.3+
- **No verifiable delay functions** yet — planned v0.3+
- **No FHE integration** yet — planned v0.4+
- **No Yoxallismus v1 backward-compat shim** yet — planned v0.2
- **No cascade cipher** (classical ⊕ PQ) mode — planned v0.2
- **No quantum-RNG integration** — planned v0.3+
- **Wire format not stabilized** — may change between v0.1 and v0.2 (migration tooling will accompany the break)

See `weave-yoxall status` for the machine-readable version of this list.

## Threat model

Full threat model in [THREAT_MODEL.md](THREAT_MODEL.md).

**What v0.1 defends against:**
- Passive network observation (via AEAD)
- Ciphertext tampering (via AEAD auth tag)
- Wrong-recipient decryption (via hybrid KEM correctness)
- Chosen-ciphertext attacks on the KEM (via ML-KEM's IND-CCA2 security + X25519 ephemeral keys)
- Post-quantum harvest-now-decrypt-later on ciphertexts (via hybrid KEM PQ half)
- Forward secrecy of past messages within a session (via ratcheting)

**What v0.1 does NOT defend against:**
- Post-compromise recovery (need DH ratcheting; planned v0.2)
- Multi-agent state isolation (need threshold encryption; planned v0.2+)
- Side-channel attacks (timing, cache, power)
- Compromised RNG
- Malicious dependency updates
- Runtime memory attacks (buffer inspection, coredump)
- Endpoint compromise
- Nation-state adversaries with unlimited quantum resources

## Security reports

See [SECURITY.md](SECURITY.md).

## Roadmap

The full research scope is intentionally proprietary until Q1 2027 IP position is set. The public roadmap:

- **v0.1.0-beta** (this release) — PQ-hybrid KEM + AEAD + symmetric ratchet + CLI + test suites + aggressive labels
- **v0.2.0-beta** — DH double-ratchet, cascade cipher (classical ⊕ PQ), v1 backward-compat shim, wire format stabilization
- **v0.3.0-beta** — Threshold encryption (multi-agent m-of-n), verifiable delay functions, ZK state-transition proofs (experimental), QRNG integration hook
- **v0.4.0-beta** — Homomorphic bounded arithmetic (FHE integration)
- **v1.0** — Once the community has hammered on it enough that we're confident the primitives compose correctly. No time table.

## License

Apache 2.0 — see [LICENSE](../LICENSE). No warranty. No fitness for purpose. Use at your own risk.

## Contact

- **Bug reports** → [GitHub Issues](https://github.com/Tyox-all/Weave_Protocol/issues)
- **Security reports** → see [SECURITY.md](SECURITY.md)
- **Everything else** → <TYox-all@tutamail.com>
