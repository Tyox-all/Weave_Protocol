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
 * COMBINERS
 *   v2 (default, wire format yoxall/2):
 *     ss = HKDF-SHA-256(ikm = ss_mlkem || ss_x25519 || eph_x25519_pub || recip_x25519_pub,
 *                       salt = 32 zero bytes, info = "weave-yoxall/2 kem-combine")
 *     Same shape as X-Wing: binding the X25519 ephemeral and recipient
 *     public keys means the combined secret is IND-CCA even if only the
 *     X25519 half is relied on. ML-KEM is already IND-CCA, so its
 *     ciphertext doesn't need to be hashed in.
 *   v1 (legacy, v0.1.0-beta.0): HKDF over ss_x25519 || ss_mlkem, salted
 *     with the recipient public keys, without the ephemeral key. Kept
 *     only so data from v0.1 can still be decrypted (YOXALL-2026-002).
 *
 * WIRE FORMAT (byte sizes, unchanged since v0.1):
 *   Public key:  [X25519 32B][ML-KEM-768 pub 1184B] = 1216 bytes
 *   Private key: [X25519 32B][ML-KEM-768 priv 2400B] = 2432 bytes
 *   Ciphertext:  [X25519 eph pub 32B][ML-KEM-768 ct 1088B] = 1120 bytes
 *   Shared sec:  32 bytes (HKDF-combined)
 */

import { generateKeyPairSync, createPrivateKey, createPublicKey, diffieHellman, randomBytes } from 'node:crypto';
import { ml_kem768 } from '@noble/post-quantum/ml-kem';
import type { HybridKeypair, HybridPublicKey, EncapsulationResult, HybridCiphertext } from './types.js';
import { hkdf } from './kdf.js';

const HYBRID_COMBINE_INFO_V1 = 'weave-yoxall v0.1 pq-hybrid-combine';
const HYBRID_COMBINE_INFO_V2 = 'weave-yoxall/2 kem-combine';

/** KEM combiner version: 2 (default) or 1 (legacy v0.1 data only). */
export type CombinerVersion = 1 | 2;

function combine(
  version: CombinerVersion,
  x25519Shared: Uint8Array,
  mlkemShared: Uint8Array,
  ephemeralPub: Uint8Array,
  recipient: HybridPublicKey,
): Uint8Array {
  if (version === 1) {
    const salt = concatBytes(recipient.x25519PublicKey, recipient.mlkemPublicKey);
    return hkdf(concatBytes(x25519Shared, mlkemShared), salt, HYBRID_COMBINE_INFO_V1, 32);
  }
  const ikm = concatAll(mlkemShared, x25519Shared, ephemeralPub, recipient.x25519PublicKey);
  return hkdf(ikm, new Uint8Array(32), HYBRID_COMBINE_INFO_V2, 32);
}

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
export function encapsulate(recipientPub: HybridPublicKey, version: CombinerVersion = 2): EncapsulationResult {
  return encapsulateWith(recipientPub, version, randomBytes(32), randomBytes(32));
}

/**
 * Deterministic encapsulation from caller-supplied randomness. Used for
 * known-answer test vectors only — NEVER call with non-random inputs in
 * real use. Not exported from the package index.
 */
export function encapsulateWith(
  recipientPub: HybridPublicKey,
  version: CombinerVersion,
  x25519EphemeralPrivate: Uint8Array,
  mlkemRandomness: Uint8Array,
): EncapsulationResult {
  // X25519: ephemeral keypair from the supplied private scalar
  const ephemeralPrivObj = createPrivateKey({
    key: wrapX25519RawAsPkcs8(x25519EphemeralPrivate),
    format: 'der',
    type: 'pkcs8',
  });
  const ephemeralPubRaw = extractX25519RawFromSpki(
    createPublicKey(ephemeralPrivObj).export({ type: 'spki', format: 'der' }) as Buffer,
  );

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
  const mlkemResult = ml_kem768.encapsulate(recipientPub.mlkemPublicKey, mlkemRandomness);
  const mlkemSharedSecret = mlkemResult.sharedSecret;
  const mlkemCiphertext = mlkemResult.cipherText;

  const sharedSecret = combine(version, x25519SharedSecret, mlkemSharedSecret, ephemeralPubRaw, recipientPub);

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
export function decapsulate(recipientPriv: HybridKeypair, ct: HybridCiphertext, version: CombinerVersion = 2): Uint8Array {
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

  return combine(version, x25519SharedSecret, mlkemSharedSecret, ct.x25519EphemeralPublicKey, recipientPriv);
}

// ─── Public-key extraction ──────────────────────────────────────

export function publicKeyOf(kp: HybridKeypair): HybridPublicKey {
  return {
    x25519PublicKey: kp.x25519PublicKey,
    mlkemPublicKey: kp.mlkemPublicKey,
  };
}

// ─── Helpers ────────────────────────────────────────────────────

/** Deterministic keypair from seeds — known-answer test vectors only. */
export function keypairFromSeeds(x25519Private: Uint8Array, mlkemSeed: Uint8Array): HybridKeypair {
  const priv = createPrivateKey({ key: wrapX25519RawAsPkcs8(x25519Private), format: 'der', type: 'pkcs8' });
  const x25519PublicKey = extractX25519RawFromSpki(createPublicKey(priv).export({ type: 'spki', format: 'der' }) as Buffer);
  const ml = ml_kem768.keygen(mlkemSeed);
  return { x25519PublicKey, x25519PrivateKey: new Uint8Array(x25519Private), mlkemPublicKey: ml.publicKey, mlkemPrivateKey: ml.secretKey };
}

/** Raw X25519 Diffie-Hellman on 32-byte keys (used by the double ratchet). */
export function x25519(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return new Uint8Array(diffieHellman({
    privateKey: createPrivateKey({ key: wrapX25519RawAsPkcs8(privateKey), format: 'der', type: 'pkcs8' }),
    publicKey: createPublicKey({ key: wrapX25519RawAsSpki(publicKey), format: 'der', type: 'spki' }),
  }));
}

/** Fresh raw X25519 keypair (used by the double ratchet). */
export function generateX25519(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const k = generateKeyPairSync('x25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  return {
    publicKey: extractX25519RawFromSpki(k.publicKey as unknown as Buffer),
    privateKey: extractX25519RawFromPkcs8(k.privateKey as unknown as Buffer),
  };
}

function concatAll(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

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
