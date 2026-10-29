/**
 * Cascade AEAD: AES-256-GCM inside ChaCha20-Poly1305.
 *
 * Two independent ciphers, two independent keys (derived from one 32-byte
 * key with HKDF under distinct labels), two independent random nonces:
 *
 *   inner = AES-256-GCM(k_aes, n1, plaintext, aad)          ‖ tag1
 *   outer = ChaCha20-Poly1305(k_chacha, n2, n1 ‖ inner, aad) ‖ tag2
 *
 * Confidentiality holds if EITHER cipher holds; forgery requires breaking
 * the outer AEAD and then the inner one. This is a defense-in-depth hedge
 * against a break in one primitive, not a performance feature: it costs
 * two passes and 44 extra bytes.
 *
 * Why not XOR the two keystreams? XOR composition drops both ciphers'
 * authentication and makes key/nonce misuse in either one fatal for the
 * whole construction. Layering keeps every AEAD guarantee of both.
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { hkdf } from './kdf.js';

const NONCE = 12;
const TAG = 16;
const K_AES = 'weave-yoxall/2 cascade aes-256-gcm';
const K_CHACHA = 'weave-yoxall/2 cascade chacha20-poly1305';

export interface CascadePayload {
  /** ChaCha20-Poly1305 nonce (outer layer). The AES nonce is inside the ciphertext. */
  nonce: Uint8Array;
  /** n1 ‖ AES-GCM ciphertext ‖ tag1, encrypted by ChaCha20-Poly1305 ‖ tag2 */
  ciphertext: Uint8Array;
}

function keys(key: Uint8Array): { aes: Buffer; chacha: Buffer } {
  if (key.length !== 32) throw new Error(`cascade: key must be 32 bytes, got ${key.length}`);
  const salt = new Uint8Array(32);
  return { aes: Buffer.from(hkdf(key, salt, K_AES, 32)), chacha: Buffer.from(hkdf(key, salt, K_CHACHA, 32)) };
}

function seal(algo: 'aes-256-gcm' | 'chacha20-poly1305', key: Buffer, nonce: Buffer, pt: Uint8Array, aad?: Uint8Array): Buffer {
  const c = createCipheriv(algo as 'aes-256-gcm', key, nonce, { authTagLength: TAG });
  if (aad && aad.length) c.setAAD(Buffer.from(aad), { plaintextLength: pt.length });
  return Buffer.concat([c.update(Buffer.from(pt)), c.final(), c.getAuthTag()]);
}

function unseal(algo: 'aes-256-gcm' | 'chacha20-poly1305', key: Buffer, nonce: Buffer, ct: Uint8Array, aad?: Uint8Array): Buffer {
  if (ct.length < TAG) throw new Error('cascade: authentication failed');
  const body = Buffer.from(ct.subarray(0, ct.length - TAG));
  const d = createDecipheriv(algo as 'aes-256-gcm', key, nonce, { authTagLength: TAG });
  if (aad && aad.length) d.setAAD(Buffer.from(aad), { plaintextLength: body.length });
  d.setAuthTag(Buffer.from(ct.subarray(ct.length - TAG)));
  try {
    return Buffer.concat([d.update(body), d.final()]);
  } catch {
    throw new Error('cascade: authentication failed (tampered, wrong key, or wrong AAD)');
  }
}

export function cascadeEncrypt(key: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): CascadePayload {
  return cascadeEncryptWith(key, plaintext, aad, randomBytes(NONCE), randomBytes(NONCE));
}

/** Fixed-nonce variant for known-answer test vectors only. Never reuse nonces in real use. */
export function cascadeEncryptWith(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array | undefined, n1: Uint8Array, n2: Uint8Array): CascadePayload {
  if (n1.length !== NONCE || n2.length !== NONCE) throw new Error(`cascade: nonces must be ${NONCE} bytes`);
  const k = keys(key);
  const inner = Buffer.concat([Buffer.from(n1), seal('aes-256-gcm', k.aes, Buffer.from(n1), plaintext, aad)]);
  return { nonce: new Uint8Array(n2), ciphertext: new Uint8Array(seal('chacha20-poly1305', k.chacha, Buffer.from(n2), inner, aad)) };
}

export function cascadeDecrypt(key: Uint8Array, payload: CascadePayload, aad?: Uint8Array): Uint8Array {
  if (payload.nonce.length !== NONCE) throw new Error(`cascade: nonce must be ${NONCE} bytes`);
  const k = keys(key);
  const inner = unseal('chacha20-poly1305', k.chacha, Buffer.from(payload.nonce), payload.ciphertext, aad);
  if (inner.length < NONCE + TAG) throw new Error('cascade: authentication failed');
  return new Uint8Array(unseal('aes-256-gcm', k.aes, inner.subarray(0, NONCE), inner.subarray(NONCE), aad));
}

/** Bytes added by cascade mode on top of the plaintext (n1 + 2 tags; outer nonce stored separately). */
export const CASCADE_OVERHEAD = NONCE + 2 * TAG;
