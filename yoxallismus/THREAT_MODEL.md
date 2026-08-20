# Threat Model — @weave_protocol/yoxallismus v0.1.0-beta.0

**Status:** EXPERIMENTAL. NOT AUDITED. Beta software.

**Purpose:** This document names every known attack class this library defends against, every one it does not, every assumption it makes about the runtime environment, and every known limitation of the current release. Read this before adopting.

This is the document a serious developer reads before choosing to depend on a cryptographic library. It is also the document that protects users when a vulnerability is discovered — you can point to what was and wasn't in scope.

---

## Adversary model

We assume the following adversary capabilities:

| Adversary tier | Capabilities | In scope? |
|---|---|---|
| **Passive network observer** | Reads all ciphertexts in transit | ✅ Yes |
| **Active network attacker** | Reads, modifies, replays, injects ciphertexts | ✅ Yes |
| **Malicious sender** | Sends crafted ciphertexts to try to break decryption | ✅ Yes |
| **Compromised session key holder** | Has one specific message key at time T | ✅ Yes (partial — forward secrecy) |
| **Compromised long-term key holder** | Has recipient's full private keypair | ❌ Out of scope for confidentiality (any KEM fails here) |
| **Quantum-computing adversary (harvest-now-decrypt-later)** | Records ciphertexts now, decrypts post-quantum-computer | ✅ Yes (via hybrid KEM PQ half) |
| **Nation-state with unbounded resources** | Timing, cache, power, EM side channels | ❌ Out of scope |
| **Endpoint attacker with code execution** | Reads memory, dumps process | ❌ Out of scope |
| **Supply chain attacker** | Compromises upstream dependency | ⚠️ Partial (see § Supply Chain) |
| **RNG compromise** | Predictable/controlled randomness from Node crypto | ❌ Out of scope (defer to Node) |

---

## What v0.1 defends against

### C1. Confidentiality against passive observers
**Primitive:** AES-256-GCM AEAD wrapped around every message
**Assumption:** AES-256 remains classically and quantum-resistant to Grover attacks (128-bit effective quantum strength — acceptable for beta scope)

### C2. Integrity against active tampering
**Primitive:** GCM 128-bit authentication tag on every ciphertext
**Verified:** `weave-yoxall audit-self` runs single-bit ciphertext flip, tag flip, wrong-key attacks; all rejected

### C3. Context binding via Associated Data
**Primitive:** AAD field bound into every AEAD encryption
**Use:** Prevents an attacker from replaying ciphertext across contexts (e.g. session A message swapped into session B)

### C4. Post-quantum shared-secret exchange
**Primitive:** ML-KEM-768 (NIST FIPS 203) composed with X25519 via HKDF-SHA-256
**Guarantee:** An attacker must break BOTH X25519 (via Shor) AND ML-KEM (via a novel lattice attack) to recover the shared secret
**Reference:** Signal PQXDH, Cloudflare X25519Kyber768Draft00, Google Chrome KyberHybrid

### C5. Harvest-now-decrypt-later resistance
**Assumption:** Recorded ciphertexts, decrypted after a fault-tolerant quantum computer arrives, remain confidential because the PQ half is not broken by Shor
**Caveat:** This assumes ML-KEM-768 remains secure. NIST's confidence is high but not absolute; SPHINCS+ or HQC as backup is a possible v0.2 addition

### C6. Wrong-recipient rejection
**Primitive:** ML-KEM's implicit rejection + X25519 correctness
**Behavior:** A wrong recipient trying to decapsulate produces a *different* shared secret; subsequent AEAD decryption fails with authentication error

### C7. Forward secrecy within a session
**Primitive:** Symmetric ratcheting via HKDF chain advance
**Guarantee:** Compromising the chain key at message N does not reveal messages 1..N-1
**Limitation:** Does NOT provide post-compromise recovery (see § Not defended)

### C8. Chosen-ciphertext security (IND-CCA2)
**Primitive:** ML-KEM-768 provides IND-CCA2 by construction; X25519 is used with ephemeral keys per encapsulation
**Behavior:** An attacker cannot use the recipient as a decryption oracle to extract information about other ciphertexts

---

## What v0.1 does NOT defend against

### N1. Post-compromise recovery
**Missing:** DH double-ratchet (Signal Protocol style)
**Impact:** If a chain key is compromised at message N, all *future* messages in that session become readable to the attacker until the session is torn down and re-established
**Planned:** v0.2

### N2. Multi-agent m-of-n threshold decryption
**Missing:** Threshold encryption primitive
**Impact:** Any single compromised agent that holds a private key can decrypt state that was intended to require multi-party approval
**Planned:** v0.3

### N3. Out-of-order message delivery
**Missing:** Skipped-message key retention
**Impact:** Messages must be decrypted in order. Skipping a message breaks the chain for all subsequent messages
**Planned:** v0.2

### N4. Side-channel attacks
**Missing:** Constant-time guarantees, memory-cleared secret handling, side-channel resistant primitives
**Impact:** An attacker with timing, cache, power, or EM measurement access may be able to recover keys
**Assumption:** Attackers with side-channel access have already compromised the endpoint

### N5. Compromised randomness
**Missing:** RNG verification, hardware RNG integration (QRNG)
**Impact:** If Node's `crypto.randomBytes()` returns predictable output (compromised RNG, buggy CPU, VM entropy starvation), all key generation and nonce generation is compromised
**Planned:** QRNG hook in v0.3

### N6. Malicious dependency updates
**Missing:** No lockfile verification, no reproducible builds, no dependency signing
**Impact:** A compromised `@noble/post-quantum` update could substitute broken cryptography without detection
**Mitigation:** We use `@noble/post-quantum` from Paul Miller's well-audited noble suite; the risk is low but not zero
**Planned:** SLSA/reproducible-build attestations in v0.3+

### N7. Endpoint compromise
**Missing:** Memory scrubbing after key use, TEE integration, hardware-backed key storage
**Impact:** An attacker with code execution on the endpoint can read all cryptographic material from process memory
**Assumption:** Endpoint security is out of scope for a cryptographic library

### N8. Regulated data handling
**Missing:** No FIPS 140-3 validation, no HIPAA-compliant audit trail, no PCI-DSS-approved deployment model
**Impact:** Cannot be used for regulated data storage or transmission
**Explicit non-goal for the beta series**

### N9. Formal audit
**Missing:** No external cryptographic audit by Trail of Bits, NCC Group, Cure53, or comparable
**Impact:** Any latent implementation bug is undiscovered
**By design for the beta series** — validation is via public use, forks, and responsible disclosure (see SECURITY.md)

---

## Assumptions about the runtime environment

- **Node.js ≥ 18** with functional `crypto` module (AES-256-GCM, HKDF, X25519 keygen, DER SPKI/PKCS8 encoding)
- **`@noble/post-quantum` ≥ 0.4.0** installed and unmodified
- **RNG** functioning correctly (`crypto.randomBytes()` returns cryptographically-random output)
- **Endpoint** not compromised
- **Filesystem** protects the `.priv` file with mode 600 (or equivalent)
- **Wire format** endpoints agree on `_version` field and reject unknown versions

---

## Supply chain

### Dependencies (v0.1.0-beta.0)

| Package | Version | Purpose | Risk |
|---|---|---|---|
| `@noble/post-quantum` | ^0.4.0 | ML-KEM-768 primitive | LOW — Paul Miller's audited noble suite |
| Node built-in `crypto` | ≥ 18 | X25519, AES-256-GCM, HKDF | LOW — audited by Node maintainers |

No native modules. No transitive deps beyond the standard toolchain. `npm audit` should report 0 vulnerabilities.

### Build reproducibility

- Deterministic TypeScript compilation from published source
- No preinstall/postinstall scripts
- No compiled binaries in the tarball

---

## Known unknowns

Documented so we don't pretend we've thought of everything:

1. **ML-KEM-768 novel attacks** — NIST's post-quantum competition selected ML-KEM after multiple rounds of cryptanalysis. Confidence is high but the algorithm is only ~10 years old. Any advance in lattice reduction could reduce security margins.
2. **X25519 side channels in Node** — Node's X25519 implementation relies on OpenSSL. Any side-channel vulnerability there propagates here.
3. **HKDF composition edge cases** — Our combination of X25519 secret + ML-KEM secret via HKDF follows Signal PQXDH and Cloudflare's hybrid TLS design. If those designs have a subtle flaw, this library inherits it.
4. **Ratchet edge cases** — Our symmetric ratchet is simpler than Signal Double Ratchet but has similar attack surface. Session-boundary bugs, sessionId collisions, and message-counter overflow are documented risks.
5. **JSON wire format** — Base64url-wrapped JSON is not the fastest or smallest wire format. It's chosen for debuggability during beta. It also inherits any JSON parsing vulnerabilities in the receiving environment.

---

## Version history

- **v0.1.0-beta.0** — Initial public beta. PQ-hybrid KEM, AEAD, symmetric ratcheting. Aggressive experimental labeling. Threat model established.

---

## How to report vulnerabilities

See [SECURITY.md](SECURITY.md) for the responsible-disclosure process.

Please report all cryptographic findings — even ones you're unsure of. Accepted reports are credited in [SECURITY_ADVISORIES.md](SECURITY_ADVISORIES.md) alongside the corresponding fix.
