/**
 * Sealed boxes (wire format yoxall/2): encrypt to a recipient's hybrid
 * public key, sender-anonymous, one shot.
 *
 *   ss  = hybrid KEM (v2 combiner) to the recipient
 *   key = HKDF(ss, salt = 32 zero bytes, info = "weave-yoxall/2 seal <mode>")
 *   body = AES-256-GCM(key, random nonce, pt, aad)          mode "aes-256-gcm"
 *        | cascadeEncrypt(key, pt, aad)                     mode "cascade"
 *
 * The caller passes the expected AAD to open(): it is never carried in
 * the message, so a recipient can't be tricked into accepting a message
 * bound to some other context.
 */

import type { HybridCiphertext, HybridKeypair, HybridPublicKey } from './types.js';
import { encapsulate, decapsulate } from './kem.js';
import { hkdf } from './kdf.js';
import { aeadEncrypt, aeadDecrypt } from './aead.js';
import { cascadeEncrypt, cascadeDecrypt } from './cascade.js';

export type SealMode = 'aes-256-gcm' | 'cascade';

export interface SealedMessage {
  version: 2;
  mode: SealMode;
  kem: HybridCiphertext;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

export interface SealOptions {
  /** Associated data bound to the message; must be passed identically to open(). */
  aad?: Uint8Array;
  /** "cascade" layers AES-256-GCM inside ChaCha20-Poly1305. Default "aes-256-gcm". */
  mode?: SealMode;
}

const keyFor = (ss: Uint8Array, mode: SealMode) => hkdf(ss, new Uint8Array(32), `weave-yoxall/2 seal ${mode}`, 32);

export function seal(recipient: HybridPublicKey, plaintext: Uint8Array, opts: SealOptions = {}): SealedMessage {
  const mode = opts.mode ?? 'aes-256-gcm';
  if (mode !== 'aes-256-gcm' && mode !== 'cascade') throw new Error(`seal: unknown mode "${mode}"`);
  const kem = encapsulate(recipient, 2);
  const key = keyFor(kem.sharedSecret, mode);
  const body = mode === 'cascade' ? cascadeEncrypt(key, plaintext, opts.aad) : aeadEncrypt(key, plaintext, opts.aad);
  return { version: 2, mode, kem: kem.ciphertext, nonce: body.nonce, ciphertext: body.ciphertext };
}

export function open(recipient: HybridKeypair, msg: SealedMessage, opts: { aad?: Uint8Array } = {}): Uint8Array {
  if (msg.version !== 2) throw new Error(`open: unsupported sealed-message version ${msg.version}`);
  const ss = decapsulate(recipient, msg.kem, 2);
  const key = keyFor(ss, msg.mode);
  if (msg.mode === 'cascade') return cascadeDecrypt(key, { nonce: msg.nonce, ciphertext: msg.ciphertext }, opts.aad);
  if (msg.mode === 'aes-256-gcm') {
    return aeadDecrypt(key, { nonce: msg.nonce, ciphertext: msg.ciphertext, ...(opts.aad ? { associatedData: opts.aad } : {}) });
  }
  throw new Error(`open: unknown mode "${(msg as SealedMessage).mode}"`);
}
