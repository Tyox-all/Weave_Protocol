/**
 * Wire format for @weave_protocol/yoxallismus v0.1.0-beta.0.
 *
 * SUBJECT TO CHANGE. This is beta. The wire format may break between
 * v0.1 and v0.2 as we integrate DH ratcheting and other v0.2 pieces.
 * Migration tooling will be provided when the format stabilizes.
 *
 * Current format: base64url-encoded JSON envelopes with explicit
 * versioning. Simple, debuggable, forward-compatible via version tag.
 */

import type { HybridKeypair, HybridPublicKey, HybridCiphertext, EncryptedPayload, RatchetSession } from './types.js';

const WIRE_VERSION = 'yoxall/0.1.0-beta.0';

function b64(u8: Uint8Array): string {
  return Buffer.from(u8).toString('base64url');
}
function u8(b64s: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64s, 'base64url'));
}

// ─── Public keys ────────────────────────────────────────────────

export function serializePublicKey(pub: HybridPublicKey): string {
  return JSON.stringify({
    _type: 'yoxall-pubkey',
    _version: WIRE_VERSION,
    x25519: b64(pub.x25519PublicKey),
    mlkem: b64(pub.mlkemPublicKey),
  });
}

export function deserializePublicKey(s: string): HybridPublicKey {
  const j = JSON.parse(s);
  if (j._type !== 'yoxall-pubkey') throw new Error(`not a public key envelope: ${j._type}`);
  return {
    x25519PublicKey: u8(j.x25519),
    mlkemPublicKey: u8(j.mlkem),
  };
}

// ─── Private keypair (WARNING: contains secret material) ────────

export function serializeKeypair(kp: HybridKeypair): string {
  return JSON.stringify({
    _type: 'yoxall-keypair',
    _version: WIRE_VERSION,
    _warning: 'CONTAINS PRIVATE KEY MATERIAL — protect this file',
    x25519pub: b64(kp.x25519PublicKey),
    x25519priv: b64(kp.x25519PrivateKey),
    mlkempub: b64(kp.mlkemPublicKey),
    mlkempriv: b64(kp.mlkemPrivateKey),
  }, null, 2);
}

export function deserializeKeypair(s: string): HybridKeypair {
  const j = JSON.parse(s);
  if (j._type !== 'yoxall-keypair') throw new Error(`not a keypair envelope: ${j._type}`);
  return {
    x25519PublicKey: u8(j.x25519pub),
    x25519PrivateKey: u8(j.x25519priv),
    mlkemPublicKey: u8(j.mlkempub),
    mlkemPrivateKey: u8(j.mlkempriv),
  };
}

// ─── Ciphertext ─────────────────────────────────────────────────

export function serializeCiphertext(ct: HybridCiphertext): string {
  return JSON.stringify({
    _type: 'yoxall-kem-ct',
    _version: WIRE_VERSION,
    x25519eph: b64(ct.x25519EphemeralPublicKey),
    mlkem: b64(ct.mlkemCiphertext),
  });
}

export function deserializeCiphertext(s: string): HybridCiphertext {
  const j = JSON.parse(s);
  if (j._type !== 'yoxall-kem-ct') throw new Error(`not a KEM ciphertext envelope: ${j._type}`);
  return {
    x25519EphemeralPublicKey: u8(j.x25519eph),
    mlkemCiphertext: u8(j.mlkem),
  };
}

// ─── Encrypted payload ──────────────────────────────────────────

export function serializePayload(p: EncryptedPayload): string {
  return JSON.stringify({
    _type: 'yoxall-payload',
    _version: WIRE_VERSION,
    nonce: b64(p.nonce),
    ct: b64(p.ciphertext),
    ...(p.associatedData ? { aad: b64(p.associatedData) } : {}),
  });
}

export function deserializePayload(s: string): EncryptedPayload {
  const j = JSON.parse(s);
  if (j._type !== 'yoxall-payload') throw new Error(`not a payload envelope: ${j._type}`);
  return {
    nonce: u8(j.nonce),
    ciphertext: u8(j.ct),
    ...(j.aad ? { associatedData: u8(j.aad) } : {}),
  };
}
