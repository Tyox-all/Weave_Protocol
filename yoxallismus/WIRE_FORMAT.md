# Wire Format `yoxall/2`: Locked

> **Stability promise.** Everything in this document is frozen from `@weave_protocol/yoxallismus@0.2.0-beta.0` through `1.0`. Data written by 0.2 will be readable by every later release up to and including 1.0. Changes in that window may only **add** optional envelope fields (readers ignore unknown fields) or add new envelope types. Anything else ships as `yoxall/3`.
>
> The known-answer vectors in [`test/vectors/yoxall-2.json`](test/vectors/yoxall-2.json) are part of this lock: CI fails if any byte of them changes.

## Conventions

- Envelopes are JSON objects with `_type` and `_version: "yoxall/2"`.
- Binary fields are **base64url without padding**.
- Integers are JSON numbers in `0 … 2³²−1`.
- `HKDF` = HKDF-SHA-256 (RFC 5869). `HMAC` = HMAC-SHA-256. `‖` = concatenation. `Z32` = 32 zero bytes.
- Every label below is an ASCII string used verbatim as HKDF `info`.

## Keys (unchanged since v0.1)

| Object | Layout |
|---|---|
| Hybrid public key | X25519 public (32 B) + ML-KEM-768 public (1184 B) |
| Hybrid private key | X25519 private (32 B) + ML-KEM-768 private (2400 B) |
| KEM ciphertext | X25519 ephemeral public (32 B) + ML-KEM-768 ciphertext (1088 B) |

Key envelopes `yoxall-pubkey` / `yoxall-keypair` keep their v0.1 shape and are accepted under either version string.

## Hybrid KEM combiner v2

```
ss = HKDF(ikm  = ss_mlkem ‖ ss_x25519 ‖ eph_x25519_pub ‖ recipient_x25519_pub,
          salt = Z32,
          info = "weave-yoxall/2 kem-combine",
          L    = 32)
```

Same shape as X-Wing: hashing the X25519 ephemeral and recipient public keys makes the combined secret IND-CCA even if only the X25519 half is relied on. The v0.1 combiner (`"weave-yoxall v0.1 pq-hybrid-combine"`) is kept **only** for reading v0.1 data (see YOXALL-2026-002).

## Sealed box: `yoxall-sealed`

```
ss   = KEM-v2 encapsulate(recipient)
key  = HKDF(ss, salt = Z32, info = "weave-yoxall/2 seal " ‖ mode, L = 32)
```

| `mode` | Body |
|---|---|
| `aes-256-gcm` | `nonce` = random 12 B; `ct` = AES-256-GCM(key, nonce, pt, aad) ‖ tag (16 B) |
| `cascade` | see Cascade below; `nonce` = outer ChaCha20 nonce |

```json
{ "_type": "yoxall-sealed", "_version": "yoxall/2", "mode": "aes-256-gcm",
  "x25519eph": "<32 B>", "mlkem": "<1088 B>", "nonce": "<12 B>", "ct": "<…>" }
```

The AAD is **never** stored in the envelope; the recipient supplies the expected value to `open()`.

## Cascade AEAD

```
k_aes    = HKDF(key, Z32, "weave-yoxall/2 cascade aes-256-gcm", 32)
k_chacha = HKDF(key, Z32, "weave-yoxall/2 cascade chacha20-poly1305", 32)
inner    = n1 ‖ AES-256-GCM(k_aes, n1, pt, aad) ‖ tag1
ct       = ChaCha20-Poly1305(k_chacha, n2, inner, aad) ‖ tag2
```

`n1`, `n2` are independent random 12-byte nonces; `n2` is the envelope `nonce`. Overhead is 44 bytes plus the outer nonce.

## Double Ratchet

Follows the [Signal Double Ratchet specification](https://signal.org/docs/specifications/doubleratchet/).

```
session start   (rk, ck0) = HKDF(ss_kem_v2, Z32, "weave-yoxall/2 dr-init", 64)
session AD      ad = SHA-256("weave-yoxall/2 dr-ad" ‖ kem_ct.x25519eph ‖ kem_ct.mlkem
                             ‖ responder.x25519_pub ‖ responder.mlkem_pub)
KDF_RK(rk, dh)  (rk', ck) = HKDF(ikm = dh, salt = rk, "weave-yoxall/2 dr-rk", 64)
KDF_CK(ck)      ck' = HMAC(ck, 0x02);  mk = HMAC(ck, 0x01)
message key     key ‖ nonce = HKDF(mk, Z32, "weave-yoxall/2 dr-msg", 44)   (32 B + 12 B)
header bytes    dh (32 B) ‖ pn (uint32 BE) ‖ n (uint32 BE)                  (40 B)
ciphertext      AES-256-GCM(key, nonce, pt, aad = ad ‖ header ‖ caller_aad) ‖ tag
```

- The **initiator** sends first with chain `ck0` and a fresh X25519 ratchet key. Its messages carry the KEM ciphertext as `handshake` until the first reply arrives.
- The **responder** sets `ckr = ck0`, `dhr` = the initiator's header key, generates its ratchet key, and derives its first sending chain with `KDF_RK(rk, DH(own, dhr))`.
- Skipped message keys are kept (at most 1000 per chain step, 2000 in total).

```json
{ "_type": "yoxall-dr-msg", "_version": "yoxall/2",
  "dh": "<32 B>", "pn": 0, "n": 3,
  "handshake": { "x25519eph": "<32 B>", "mlkem": "<1088 B>" },
  "ct": "<…>" }
```

### Session state: `yoxall-dr-session` (secret)

Fields: `role` (`initiator` | `responder`), `ad`, `rk`, `dhsPub`, `dhsPriv`, `dhr`, `cks`, `ckr` (32 B or `null`), `ns`, `nr`, `pn`, `skipped` (array of `["<dh b64url>:<n>", "<mk>"]`, oldest first), `pendingHandshake` (KEM ciphertext object or `null`). **Contains secret key material: store it encrypted and never log it.**

## Legacy formats

| Format | Status |
|---|---|
| `yoxall/0.1.0-beta.0` envelopes (`yoxall-kem-ct`, `yoxall-payload`, `yoxall-encrypted-file`) | **Readable**, through `PQCipher` and `weave-yoxall decrypt`. Written only by the deprecated v0.1 APIs. |
| v0.1 symmetric ratchet | Deprecated: no interoperable session start (YOXALL-2026-001). |
| Yoxallismus v1 (`YXLS` header, Hord `YoxallismusCipher`) | **Detected, not decryptable** by any implementation (YOXALL-2026-003). |
