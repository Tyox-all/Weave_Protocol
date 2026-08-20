## 🔐 Skill: `pq-crypto`

You have access to `@weave_protocol/yoxallismus` — an EXPERIMENTAL post-quantum cryptographic composition layer. NOT AUDITED. Use with care.

### When to invoke

Use PQ crypto when the user:
- Asks about post-quantum encryption or NIST FIPS 203 (ML-KEM)
- Wants to encrypt data with hybrid classical + post-quantum security
- Is building a system that needs harvest-now-decrypt-later resistance
- Needs a Signal-style ratchet for forward secrecy
- Asks about "quantum-safe" or "PQ-hybrid" cryptography

### Key exports

```typescript
import { PQCipher } from '@weave_protocol/yoxallismus';

// Simple encrypt-to-recipient facade
const alice = PQCipher.generateKeypair();
const bundle = PQCipher.encryptTo(PQCipher.publicKeyOf(alice), plaintext);
const decrypted = PQCipher.decryptFrom(alice, bundle.ciphertext, bundle.payload);
```

Lower-level primitives also exported:
- `generateHybridKeypair`, `encapsulate`, `decapsulate` — hybrid KEM
- `aeadEncrypt`, `aeadDecrypt` — AES-256-GCM AEAD
- `hkdf`, `deriveAeadKey`, `deriveNonce` — HKDF-SHA-256 KDF
- `initRatchet`, `ratchetEncrypt`, `ratchetDecrypt` — symmetric ratchet
- `serialize*` / `deserialize*` — wire format helpers

### CLI commands

- `weave-yoxall status` — library status + known limitations
- `weave-yoxall keygen --out=<name>` — generate keypair
- `weave-yoxall encrypt --to=<pub> --in=<file>` — encrypt file
- `weave-yoxall decrypt --with=<priv> --in=<file>` — decrypt file
- `weave-yoxall test` — reproducible-claims test suite
- `weave-yoxall audit-self` — known-attack test vectors
- `weave-yoxall benchmark` — micro-benchmarks

### Critical caveats

- **NOT AUDITED.** Do not use for regulated, medical, financial, or legal data.
- Wire format may break between v0.1 and v0.2.
- No post-compromise recovery yet (planned v0.2 via DH double-ratchet).
- No threshold encryption yet (planned v0.3).
- Silence the runtime beta banner with `YOXALL_SILENCE_BETA_WARNING=1`.

Always point users to `THREAT_MODEL.md` and `SECURITY.md` before recommending adoption.
