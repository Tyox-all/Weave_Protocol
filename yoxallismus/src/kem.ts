/**
 * PQ-hybrid Key Encapsulation Mechanism.
 *
 * Combines X25519 (classical elliptic-curve KEM) with ML-KEM-768
 * (post-quantum lattice KEM, NIST FIPS 203) via HKDF-SHA-256.
 *
 * The security guarantee: an attacker must break BOTH primitives to
 * recover the shared secret. If Shor's algorithm arrives and breaks
 * X25519, the ML-KEM component keeps the secret confidential. If a
 * classical or quantum attack on ML-KEM emerges, X25519 keeps the
 * secret confidential.
 *
 * This is the same construction Signal ships as PQXDH and Cloudflare
 * ships as X25519Kyber768Draft00 in TLS 1.3. The design pattern is
 * well-established; the primitives are NIST-standardized.
 *
 * WIRE FORMAT (v0.1.0-beta.0, subject to change before v0.2):
 *   Public key:  [X25519 32B][ML-KEM-768 pub 1184B] = 1216 bytes
 *   Private key: [X25519 32B][ML-KEM-768 priv 2400B] = 2432 bytes
 *   Ciphertext:  [X25519 eph pub 32B][ML-KEM-768 ct 1088B] = 1120 bytes
 *   Shared sec:  32 bytes (HKDF-combined)
 */

import { generateKeyPairSync, createPrivateKey, createPublicKey, diffieHellman, randomBytes } from 'node:crypto';
import { ml_kem768 } from '@noble/post-quantum/ml-kem';
import type { HybridKeypair, HybridPublicKey, EncapsulationResult, HybridCiphertext } from './types.js';
import { hkdf } from './kdf.js';

const HYBRID_COMBINE_INFO = 'weave-yoxall v0.1 pq-hybrid-combine';

// ─── Key generation ─────────────────────────────────────────────

/**
 * Generate a fresh hybrid keypair. Both halves are generated with
 * independent randomness from Node's crypto RNG.
 */
export function generateHybridKeypair(): HybridKeypair {
  // X25519 half via Node crypto — request DER SPKI/PKCS8 export
  const x = generateKeyPairSync('x25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  // Extract raw 32-byte keys from DER (Node returns wrapped SPKI/PKCS8)
  const x25519PublicKey = extractX25519RawFromSpki(x.publicKey as unknown as Buffer);
  const x25519PrivateKey = extractX25519RawFromPkcs8(x.privateKey as unknown as Buffer);

  // ML-KEM-768 half via noble
  const mlkemSeed = randomBytes(64);
  const mlkemKeys = ml_kem768.keygen(mlkemSeed);

  return {
    x25519PublicKey,
    x25519PrivateKey,
    mlkemPublicKey: mlkemKeys.publicKey,
    mlkemPrivateKey: mlkemKeys.secretKey,
  };
}

// ─── Encapsulation (sender side) ────────────────────────────────

/**
 * Encapsulate a shared secret to the recipient's hybrid public key.
 *
 * Returns:
 *   - sharedSecret: 32 bytes that both parties will hold
 *   - ciphertext: the hybrid KEM output that recipient decapsulates
 */
export function encapsulate(recipientPub: HybridPublicKey): EncapsulationResult {
  // X25519: generate ephemeral, compute shared secret
  const ephemeral = generateKeyPairSync('x25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  const ephemeralPubRaw = extractX25519RawFromSpki(ephemeral.publicKey as unknown as Buffer);
  const ephemeralPrivObj = createPrivateKey({
    key: ephemeral.privateKey as unknown as Buffer,
    format: 'der',
    type: 'pkcs8',
  });

  const recipientX25519PubObj = createPublicKey({
    key: wrapX25519RawAsSpki(recipientPub.x25519PublicKey),
    format: 'der',
    type: 'spki',
  });

  const x25519SharedSecret = new Uint8Array(diffieHellman({
    privateKey: ephemeralPrivObj,
    publicKey: recipientX25519PubObj,
  }));

  // ML-KEM: encapsulate to recipient's ML-KEM public key
  const mlkemResult = ml_kem768.encapsulate(recipientPub.mlkemPublicKey);
  const mlkemSharedSecret = mlkemResult.sharedSecret;
  const mlkemCiphertext = mlkemResult.cipherText;

  // Combine via HKDF: salt = both public parts, ikm = concatenated secrets
  const salt = concatBytes(recipientPub.x25519PublicKey, recipientPub.mlkemPublicKey);
  const ikm = concatBytes(x25519SharedSecret, mlkemSharedSecret);
  const sharedSecret = hkdf(ikm, salt, HYBRID_COMBINE_INFO, 32);

  return {
    sharedSecret,
    ciphertext: {
      x25519EphemeralPublicKey: ephemeralPubRaw,
      mlkemCiphertext,
    },
  };
}

// ─── Decapsulation (recipient side) ─────────────────────────────

/**
 * Decapsulate a shared secret from a ciphertext using the recipient's
 * private key. Both halves must succeed; either failure means the
 * derived shared secret will not match the sender's.
 *
 * ML-KEM has "implicit rejection" — a malformed ML-KEM ciphertext
 * doesn't throw, it silently returns garbage. That's a feature (it
 * prevents timing attacks) but means the caller MUST verify the
 * shared secret was correct out-of-band (typically via AEAD auth-tag
 * verification on subsequent messages).
 */
export function decapsulate(recipientPriv: HybridKeypair, ct: HybridCiphertext): Uint8Array {
  // X25519: compute shared secret with ephemeral public + own private
  const recipientPrivObj = createPrivateKey({
    key: wrapX25519RawAsPkcs8(recipientPriv.x25519PrivateKey),
    format: 'der',
    type: 'pkcs8',
  });
  const ephemeralPubObj = createPublicKey({
    key: wrapX25519RawAsSpki(ct.x25519EphemeralPublicKey),
    format: 'der',
    type: 'spki',
  });

  const x25519SharedSecret = new Uint8Array(diffieHellman({
    privateKey: recipientPrivObj,
    publicKey: ephemeralPubObj,
  }));

  // ML-KEM: decapsulate
  const mlkemSharedSecret = ml_kem768.decapsulate(ct.mlkemCiphertext, recipientPriv.mlkemPrivateKey);

  // Combine — same salt/info as encapsulate
  const salt = concatBytes(recipientPriv.x25519PublicKey, recipientPriv.mlkemPublicKey);
  const ikm = concatBytes(x25519SharedSecret, mlkemSharedSecret);
  return hkdf(ikm, salt, HYBRID_COMBINE_INFO, 32);
}

// ─── Public-key extraction ──────────────────────────────────────

export function publicKeyOf(kp: HybridKeypair): HybridPublicKey {
  return {
    x25519PublicKey: kp.x25519PublicKey,
    mlkemPublicKey: kp.mlkemPublicKey,
  };
}

// ─── Helpers ────────────────────────────────────────────────────

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

// X25519 SPKI DER header (12 bytes) + 32-byte raw key
const X25519_SPKI_HEADER = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
]);

// X25519 PKCS8 DER header (16 bytes) + 32-byte raw key
const X25519_PKCS8_HEADER = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

function extractX25519RawFromSpki(der: Buffer): Uint8Array {
  // DER format: [header 12 bytes][raw 32 bytes]
  return new Uint8Array(der.slice(der.length - 32));
}

function extractX25519RawFromPkcs8(der: Buffer): Uint8Array {
  // DER format: [header 16 bytes][raw 32 bytes]
  return new Uint8Array(der.slice(der.length - 32));
}

function wrapX25519RawAsSpki(raw: Uint8Array): Buffer {
  return Buffer.concat([Buffer.from(X25519_SPKI_HEADER), Buffer.from(raw)]);
}

function wrapX25519RawAsPkcs8(raw: Uint8Array): Buffer {
  return Buffer.concat([Buffer.from(X25519_PKCS8_HEADER), Buffer.from(raw)]);
}
