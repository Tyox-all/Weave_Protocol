/**
 * HKDF (HMAC-based Key Derivation Function) wrapper.
 *
 * Uses Node's built-in HKDF via crypto.hkdfSync. SHA-256 chosen for v0.1
 * because it's ubiquitous and fast; the reduced quantum strength (~128
 * bits via Grover) is adequate for the beta scope.
 *
 * DESIGN NOTES:
 *   - We use HKDF-Extract-then-Expand as a single hkdfSync call
 *   - Salt SHOULD be a random per-session value when combining independent
 *     shared secrets (as in PQ-hybrid KEM combination)
 *   - Info SHOULD be an application-context string ("weave-yoxall v0.1
 *     kem-combine", "chain-key-advance", etc.) — this domain-separates
 *     derived keys so a leak in one context doesn't cross-contaminate
 */

import { hkdfSync } from 'node:crypto';

export const HKDF_HASH = 'sha256';
export const HKDF_OUTPUT_LEN = 32;

/**
 * Derive `length` bytes of keying material from an input keying material,
 * salt, and info context string.
 */
export function hkdf(
  inputKeyMaterial: Uint8Array,
  salt: Uint8Array,
  info: string | Uint8Array,
  length: number = HKDF_OUTPUT_LEN,
): Uint8Array {
  const infoBytes = typeof info === 'string' ? new TextEncoder().encode(info) : info;
  const derived = hkdfSync(
    HKDF_HASH,
    Buffer.from(inputKeyMaterial),
    Buffer.from(salt),
    Buffer.from(infoBytes),
    length,
  );
  return new Uint8Array(derived);
}

/**
 * Derive a 32-byte AEAD key from a shared secret and a context info string.
 * Convenience wrapper — most callers want this.
 */
export function deriveAeadKey(sharedSecret: Uint8Array, info: string, salt?: Uint8Array): Uint8Array {
  return hkdf(sharedSecret, salt || new Uint8Array(32), info, 32);
}

/**
 * Derive a 12-byte AEAD nonce deterministically from a chain key + counter.
 * This is what the ratchet uses to avoid random-nonce reuse across sessions.
 */
export function deriveNonce(chainKey: Uint8Array, counter: number): Uint8Array {
  const counterBytes = new Uint8Array(8);
  const dv = new DataView(counterBytes.buffer);
  dv.setBigUint64(0, BigInt(counter), false);
  return hkdf(chainKey, counterBytes, 'weave-yoxall v0.1 nonce-derive', 12);
}
