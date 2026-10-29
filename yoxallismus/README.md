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
- **Not production-ready.** 0.2.0-beta.0 explicitly.

## Installation

```bash
npm install @weave_protocol/yoxallismus@beta
```

The `@beta` tag is required: `latest` intentionally points at a stub until the library is audited.

To silence the runtime beta banner:

```bash
export YOXALL_SILENCE_BETA_WARNING=1
```

## 🔒 Wire format `yoxall/2` is locked

As of **0.2.0-beta.0**, everything 0.2 writes stays readable by every release through **1.0**. The format is specified byte by byte in [WIRE_FORMAT.md](WIRE_FORMAT.md), and known-answer test vectors in CI fail the build if any byte changes. Later releases may only *add* optional fields; anything else becomes `yoxall/3`. Data written by v0.1 stays readable too.

## Quick start (programmatic)

**One-shot encryption to a public key (sealed box):**

```typescript
import { generateHybridKeypair, publicKeyOf, seal, open, serializeSealed, deserializeSealed } from '@weave_protocol/yoxallismus';

const alice = generateHybridKeypair();

// Anyone with Alice's public key can seal a message to her
const msg = seal(publicKeyOf(alice), new TextEncoder().encode('secret'), {
  aad: new TextEncoder().encode('inbox:alice'), // context binding, checked on open
  mode: 'cascade',                             // optional: AES-256-GCM inside ChaCha20-Poly1305
});
const wire = serializeSealed(msg); // yoxall/2 JSON envelope

// Alice opens it, supplying the context she expects
const pt = open(alice, deserializeSealed(wire), { aad: new TextEncoder().encode('inbox:alice') });
```

**A conversation with post-compromise security (Double Ratchet):**

```typescript
import { initiateSession, acceptSession, drEncrypt, drDecrypt } from '@weave_protocol/yoxallismus';

const bob = generateHybridKeypair();

// Alice starts a session from Bob's public key and sends first
const alice = initiateSession(publicKeyOf(bob));
const m1 = drEncrypt(alice, new TextEncoder().encode('hi bob'));

// Bob creates his session from that first message: no other setup needed
const { session: bobSession, plaintext } = acceptSession(bob, m1);

// From here, either side sends; keys ratchet forward every message
const reply = drEncrypt(bobSession, new TextEncoder().encode('hi alice'));
drDecrypt(alice, reply);
```

Persist sessions with `serializeSession()` / `deserializeSession()`. Those envelopes contain secret keys, so store them encrypted.

`PQCipher` (the v0.1 API) still works and still reads v0.1 data; use `seal()` / `open()` for new code.

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

## What's inside (v0.2.0-beta.0)

| Component | Primitive | Size / Cost |
|---|---|---|
| Classical KEM | X25519 (Node crypto) | 32B pub / 32B priv |
| Post-quantum KEM | ML-KEM-768 via `@noble/post-quantum` (NIST FIPS 203) | 1184B pub / 2400B priv |
| Hybrid combination | **v2:** X-Wing-style HKDF over both secrets + X25519 ephemeral and recipient keys | 32B output |
| AEAD | AES-256-GCM (Node crypto) | 12B nonce, 16B tag |
| Cascade AEAD *(new)* | AES-256-GCM inside ChaCha20-Poly1305, independent keys | +44B |
| Sealed boxes *(new)* | Hybrid KEM → HKDF → AEAD or cascade | 1120B KEM ciphertext |
| Double Ratchet *(new)* | Signal Double Ratchet over X25519, seeded by the hybrid KEM | Forward secrecy + post-compromise security |
| Wire format | `yoxall/2` JSON envelopes, **locked through 1.0** | Base64url values |
| v1 detection *(new)* | Recognizes Hord `YoxallismusCipher` payloads (unrecoverable; YOXALL-2026-003) | — |

## Performance (measured on v0.1.0-beta.0; v0.2 adds no cost to these paths)

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
- AEAD encrypt/decrypt roundtrip, bit-flip rejection, AAD binding
- PQ-hybrid keypair sizes match NIST FIPS 203
- Encapsulate/decapsulate produce matching shared secrets
- Wrong recipient cannot decrypt
- Sealed boxes in both modes, including wrong-AAD rejection
- Double Ratchet: session start from the handshake alone, and **a stolen session copy that stops decrypting after one DH round trip** (post-compromise security)
- Serialization roundtrip preserves bytes

The full suite (`npm test`, 26 tests) also covers the `yoxall/2` known-answer vectors, out-of-order delivery across ratchet steps, replay and forgery rejection that leaves the session untouched, the skipped-message limit, and v1 payload detection.

To verify known-attack vectors are rejected:

```bash
weave-yoxall audit-self
```

## Known limitations

- **No formal external audit** performed
- **Ratchet steps are classical.** Sessions *start* post-quantum (hybrid KEM), but ongoing Double Ratchet DH steps use X25519, as in Signal's original design. A PQ ratchet is planned after v0.3.
- **No sender authentication**: sealed boxes and sessions are sender-anonymous. Authenticate peers at a higher layer.
- **Yoxallismus v1 (Hord) payloads can't be decrypted** by any implementation; v0.2 detects them and explains why (YOXALL-2026-003).
- **No threshold encryption** (multi-agent m-of-n) yet, planned v0.3
- **No zero-knowledge proofs or verifiable delay functions** yet, planned v0.3+
- **No FHE integration** yet, planned v0.4+
- **No quantum-RNG integration**, planned v0.3+

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
- Post-compromise recovery: a stolen session stops working after one DH round trip (Double Ratchet)
- Out-of-order and lost messages within a session

**What v0.2 does NOT defend against:**
- Quantum attacks on the ongoing ratchet: only the session start is post-quantum
- Sender impersonation: messages are sender-anonymous
- Multi-agent state isolation (need threshold encryption; planned v0.3)
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
