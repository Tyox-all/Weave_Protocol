/**
 * Yoxallismus v1 backward-compatibility path.
 *
 * v1 was AES-256-GCM + ChaCha20-Poly1305 with Argon2id KDF, shipped
 * embedded in @weave_protocol/hord. It was never published as a
 * standalone package with a wire format spec.
 *
 * PLANNED FOR v0.2.0-beta:
 *   - Read-only decode path for Hord v1 encrypted payloads
 *   - Migration helper: readV1(payload, oldKey) → decrypt with v1,
 *     then re-encrypt with v2 keys
 *   - Zero-loss round-trip test suite against Hord v1 test vectors
 *
 * v0.1.0-beta.0 SHIPS WITH NO V1 COMPAT.
 * If you're using Hord v1 encryption today, you can safely install
 * yoxallismus v2 side-by-side but you can't migrate data yet.
 */

export function readV1(_payload: unknown, _oldKey: unknown): never {
  throw new Error(
    '[yoxallismus] v1 backward-compat is not yet implemented in v0.1.0-beta.0. ' +
      'Planned for v0.2.0. See THREAT_MODEL.md § Migration.',
  );
}
