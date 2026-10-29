# Security Advisories — @weave_protocol/yoxallismus

_This document is the public record of all security advisories issued for this library._

_Three advisories have been issued, all found during v0.2 development and fixed or documented in 0.2.0-beta.0._

---

## Format

Each entry follows this structure:

```
### YOXALL-YYYY-NNN — <title>

- **Severity:** Critical / High / Medium / Low
- **Affects:** @weave_protocol/yoxallismus X.Y.Z–X.Y.Z
- **Fixed in:** @weave_protocol/yoxallismus X.Y.Z
- **Reporter:** Name (with permission) or "anonymous"
- **CVE:** CVE-YYYY-NNNNN (if assigned)

**Description:** ...

**Impact:** ...

**Root cause:** ...

**Fix:** ...

**Mitigation for users on older versions:** ...
```

---

## Advisories

### YOXALL-2026-001: v0.1 symmetric ratchet has no interoperable session start

- **Severity:** Low (availability / misuse; no confidentiality break)
- **Affects:** @weave_protocol/yoxallismus 0.1.0-beta.0
- **Fixed in:** 0.2.0-beta.0 (replaced by the Double Ratchet)
- **Reporter:** found internally during v0.2 development

**Description:** `initRatchet(sharedSecret)` salts the chain key with a random `sessionId` generated locally, and nothing transmits it. Two parties calling it with the same shared secret derive different chain keys and cannot exchange messages. The v0.1 self-test only passed by copying the sender's `sessionId` and `chainKey` into the receiver.

**Impact:** The v0.1 ratchet couldn't be used between two real parties without an ad-hoc, unspecified state transfer. A transfer like that, done carelessly, could expose chain keys.

**Fix:** v0.2 adds `initiateSession()` / `acceptSession()` (Double Ratchet), where the session is derived from the hybrid KEM handshake carried in the first messages. `initRatchet` remains only for compatibility and is deprecated.

**Mitigation for users on older versions:** Use `initiateSession` / `acceptSession`.

### YOXALL-2026-002: v0.1 KEM combiner doesn't bind the X25519 public keys

- **Severity:** Low (defense in depth; no known practical attack)
- **Affects:** @weave_protocol/yoxallismus 0.1.0-beta.0
- **Fixed in:** 0.2.0-beta.0 (combiner v2)
- **Reporter:** found internally during v0.2 development

**Description:** The v0.1 combiner hashed the two shared secrets with the recipient public keys as salt, but not the X25519 **ephemeral** public key. Modern hybrid combiners such as X-Wing hash it, because a raw X25519 shared secret alone isn't IND-CCA.

**Impact:** The ML-KEM-768 half is IND-CCA on its own, so the combined secret stays secure while ML-KEM holds. The weakness only matters in the scenario hybrids are meant to hedge, where ML-KEM is broken and X25519 is relied on alone.

**Fix:** Combiner v2 hashes `ss_mlkem ‖ ss_x25519 ‖ eph_pub ‖ recipient_pub` under a new label (see WIRE_FORMAT.md). It's the default for all new data; the v0.1 combiner is used only to read v0.1 data.

**Mitigation for users on older versions:** Re-encrypt long-lived v0.1 data with `seal()`.

### YOXALL-2026-003: Yoxallismus v1 (Hord `YoxallismusCipher`) output cannot be decrypted

- **Severity:** High for data written with it (unrecoverable); not a confidentiality leak
- **Affects:** `YoxallismusCipher` in @weave_protocol/hord (all versions to date)
- **Fixed in:** not fixable for existing payloads. @weave_protocol/hord 0.1.8 deprecates `YoxallismusCipher` (`unlock()` now throws instead of returning wrong bytes), and @weave_protocol/yoxallismus 0.2.0-beta.0 detects v1 payloads
- **Reporter:** found internally while building the planned v1 decoder

**Description:** `lock()` derives its XOR mask from `HMAC(deadboltKey, seed)`, where `seed = SHA-256(tumblerKey ‖ SHA-256(plaintext))`. The header stores only the first 1-12 seed bytes, and stores them after they've been advanced during encryption. `unlock()` rebuilds the mask from the header bytes instead, so Hord's own `unlock()` never round-trips (we verified this for every configuration tested). No decoder holding the key can recover the remaining seed bytes, which depend on the unknown plaintext, short of brute force.

**Impact:** Anything stored only as a v1 payload is lost. Hord's vault does **not** use this cipher internally, so the exposure is limited to callers who used `YoxallismusCipher` directly. v1 was also never an AEAD: it's deterministic, unauthenticated, and built from permutation plus XOR.

**Fix:** The planned read-only v1 decoder is impossible. Instead, `inspectV1()` / `readV1()` recognize v1 payloads and raise `V1PayloadUnrecoverableError`, and `weave-yoxall decrypt` explains the situation.

**Mitigation:** Stop using `YoxallismusCipher` for anything that must be recovered. Re-encrypt from the original data with `seal()`.

---

## Reporting a new vulnerability

See [SECURITY.md](SECURITY.md) for the responsible-disclosure process.
