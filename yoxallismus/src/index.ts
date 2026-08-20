/**
 * @weave_protocol/yoxallismus — EXPERIMENTAL post-quantum
 * cryptographic composition layer for AI agents.
 *
 * ⚠️  NOT AUDITED. Beta software. See THREAT_MODEL.md and SECURITY.md
 *     before use. Do not use for regulated, medical, financial, or
 *     legal data.
 */

import { showBetaBanner, STATUS } from './labels.js';

// Show the beta warning banner on first import (silenceable via env var)
showBetaBanner();

// ─── Public API ─────────────────────────────────────────────────

// Labels & status metadata
export { STATUS } from './labels.js';

// KEM
export {
  generateHybridKeypair,
  encapsulate,
  decapsulate,
  publicKeyOf,
} from './kem.js';

// AEAD
export {
  aeadEncrypt,
  aeadDecrypt,
  aeadEncryptWithNonce,
  KEY_LEN,
  NONCE_LEN,
  TAG_LEN,
} from './aead.js';

// KDF
export {
  hkdf,
  deriveAeadKey,
  deriveNonce,
  HKDF_HASH,
} from './kdf.js';

// Ratchet
export {
  initRatchet,
  ratchetEncrypt,
  ratchetDecrypt,
} from './ratchet.js';

// Serialization
export {
  serializePublicKey,
  deserializePublicKey,
  serializeKeypair,
  deserializeKeypair,
  serializeCiphertext,
  deserializeCiphertext,
  serializePayload,
  deserializePayload,
} from './serialize.js';

// v1 compat (throws — not implemented in v0.1.0-beta.0)
export { readV1 } from './v1-compat.js';

// Types
export type {
  HybridKeypair,
  HybridPublicKey,
  EncapsulationResult,
  HybridCiphertext,
  EncryptedPayload,
  RatchetSession,
} from './types.js';

// ─── High-level facade ──────────────────────────────────────────

import {
  generateHybridKeypair,
  encapsulate,
  decapsulate,
  publicKeyOf,
} from './kem.js';
import { aeadEncrypt, aeadDecrypt } from './aead.js';
import { deriveAeadKey } from './kdf.js';
import {
  serializeKeypair, deserializeKeypair,
  serializePublicKey, deserializePublicKey,
  serializePayload, deserializePayload,
  serializeCiphertext, deserializeCiphertext,
} from './serialize.js';
import type { HybridKeypair, HybridPublicKey, EncryptedPayload, HybridCiphertext } from './types.js';

/**
 * The high-level "just encrypt this for that person" facade.
 * Under the hood: hybrid KEM → HKDF → AES-256-GCM.
 */
export class PQCipher {
  /** Generate a fresh hybrid keypair. */
  static generateKeypair(): HybridKeypair {
    return generateHybridKeypair();
  }

  /** Get the public half of a keypair for sharing. */
  static publicKeyOf(kp: HybridKeypair): HybridPublicKey {
    return publicKeyOf(kp);
  }

  /**
   * Encrypt a message to a recipient's public key.
   * Returns a bundle: { ciphertext (KEM), payload (AEAD) }.
   * Sender does not need their own keypair for this (KEM is sender-anonymous).
   */
  static encryptTo(
    recipientPub: HybridPublicKey,
    plaintext: Uint8Array,
    associatedData?: Uint8Array,
  ): { ciphertext: HybridCiphertext; payload: EncryptedPayload } {
    const kem = encapsulate(recipientPub);
    const aeadKey = deriveAeadKey(kem.sharedSecret, 'weave-yoxall v0.1 pqcipher-encrypt');
    const payload = aeadEncrypt(aeadKey, plaintext, associatedData);
    return { ciphertext: kem.ciphertext, payload };
  }

  /** Decrypt a message received from a sender. */
  static decryptFrom(
    recipientPriv: HybridKeypair,
    ciphertext: HybridCiphertext,
    payload: EncryptedPayload,
  ): Uint8Array {
    const sharedSecret = decapsulate(recipientPriv, ciphertext);
    const aeadKey = deriveAeadKey(sharedSecret, 'weave-yoxall v0.1 pqcipher-encrypt');
    return aeadDecrypt(aeadKey, payload);
  }

  /** All serialization helpers exposed as static methods. */
  static serializeKeypair = serializeKeypair;
  static deserializeKeypair = deserializeKeypair;
  static serializePublicKey = serializePublicKey;
  static deserializePublicKey = deserializePublicKey;
  static serializePayload = serializePayload;
  static deserializePayload = deserializePayload;
  static serializeCiphertext = serializeCiphertext;
  static deserializeCiphertext = deserializeCiphertext;
}
