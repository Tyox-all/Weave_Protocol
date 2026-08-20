/**
 * AEAD wrapper for @weave_protocol/yoxallismus.
 *
 * Uses Node's built-in AES-256-GCM. Chose AES-256 over ChaCha20-Poly1305
 * for v0.1 because it's hardware-accelerated on all modern CPUs and gives
 * ~128-bit quantum security via Grover's algorithm (the reduced strength
 * is still adequate for the beta scope).
 *
 * NONCE HANDLING:
 *   Each encryption generates a fresh 12-byte random nonce. Callers MUST
 *   NOT reuse nonces with the same key — this is the most common AEAD
 *   footgun. The ratchet module derives per-message nonces via HKDF to
 *   avoid this class of bug.
 *
 * KEY SIZE:
 *   AES-256 requires exactly 32 bytes. Keys shorter or longer will throw.
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import type { EncryptedPayload } from './types.js';

export const KEY_LEN = 32; // AES-256
export const NONCE_LEN = 12; // GCM standard
export const TAG_LEN = 16; // GCM auth tag

/**
 * Encrypt plaintext with AES-256-GCM. Nonce is auto-generated.
 * Associated data (AAD) is optional but recommended for context binding.
 */
export function aeadEncrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  associatedData?: Uint8Array,
): EncryptedPayload {
  if (key.length !== KEY_LEN) {
    throw new Error(`aeadEncrypt: key must be ${KEY_LEN} bytes, got ${key.length}`);
  }
  const nonce = randomBytes(NONCE_LEN);
  return aeadEncryptWithNonce(key, plaintext, nonce, associatedData);
}

/**
 * Encrypt with a caller-provided nonce. Used by the ratchet where
 * nonces are deterministically derived from chain state (never random).
 *
 * WARNING: never call this with a nonce you have previously used with
 * the same key. Doing so catastrophically breaks GCM confidentiality
 * AND integrity.
 */
export function aeadEncryptWithNonce(
  key: Uint8Array,
  plaintext: Uint8Array,
  nonce: Uint8Array,
  associatedData?: Uint8Array,
): EncryptedPayload {
  if (key.length !== KEY_LEN) {
    throw new Error(`aeadEncryptWithNonce: key must be ${KEY_LEN} bytes, got ${key.length}`);
  }
  if (nonce.length !== NONCE_LEN) {
    throw new Error(`aeadEncryptWithNonce: nonce must be ${NONCE_LEN} bytes, got ${nonce.length}`);
  }
  const cipher = createCipheriv('aes-256-gcm', Buffer.from(key), Buffer.from(nonce));
  if (associatedData && associatedData.length > 0) {
    cipher.setAAD(Buffer.from(associatedData));
  }
  const enc = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  const tag = cipher.getAuthTag();
  const ciphertext = new Uint8Array(enc.length + tag.length);
  ciphertext.set(enc, 0);
  ciphertext.set(tag, enc.length);
  return {
    nonce,
    ciphertext,
    ...(associatedData ? { associatedData } : {}),
  };
}

/**
 * Decrypt an EncryptedPayload. Throws on:
 *   - key length mismatch
 *   - nonce length mismatch
 *   - GCM auth tag verification failure (ciphertext tamper, wrong key,
 *     wrong nonce, wrong AAD)
 */
export function aeadDecrypt(key: Uint8Array, payload: EncryptedPayload): Uint8Array {
  if (key.length !== KEY_LEN) {
    throw new Error(`aeadDecrypt: key must be ${KEY_LEN} bytes, got ${key.length}`);
  }
  if (payload.nonce.length !== NONCE_LEN) {
    throw new Error(`aeadDecrypt: nonce must be ${NONCE_LEN} bytes, got ${payload.nonce.length}`);
  }
  if (payload.ciphertext.length < TAG_LEN) {
    throw new Error(`aeadDecrypt: ciphertext too short (min ${TAG_LEN} bytes for GCM tag)`);
  }
  const ctBody = payload.ciphertext.slice(0, payload.ciphertext.length - TAG_LEN);
  const tag = payload.ciphertext.slice(payload.ciphertext.length - TAG_LEN);
  const decipher = createDecipheriv('aes-256-gcm', Buffer.from(key), Buffer.from(payload.nonce));
  if (payload.associatedData && payload.associatedData.length > 0) {
    decipher.setAAD(Buffer.from(payload.associatedData));
  }
  decipher.setAuthTag(Buffer.from(tag));
  // Node throws with an obscure error on tag mismatch; wrap for clarity
  try {
    const dec = Buffer.concat([decipher.update(Buffer.from(ctBody)), decipher.final()]);
    return new Uint8Array(dec);
  } catch (err) {
    throw new Error('aeadDecrypt: authentication failed (ciphertext tampered, wrong key, wrong nonce, or wrong AAD)');
  }
}
