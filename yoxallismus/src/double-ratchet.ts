/**
 * Double Ratchet (wire format yoxall/2).
 *
 * Follows the Signal Double Ratchet specification
 * (https://signal.org/docs/specifications/doubleratchet/):
 *
 *   KDF_RK(rk, dh_out) = HKDF-SHA-256(ikm = dh_out, salt = rk,
 *                                     info = "weave-yoxall/2 dr-rk", 64) → (rk', ck)
 *   KDF_CK(ck)         = (HMAC-SHA-256(ck, 0x02) → ck', HMAC-SHA-256(ck, 0x01) → mk)
 *   ENCRYPT(mk, pt, ad) = AES-256-GCM with key ‖ nonce = HKDF(mk, "weave-yoxall/2 dr-msg", 44)
 *
 * PROPERTIES
 *   - Forward secrecy: message keys are deleted after use and chain keys
 *     only move forward.
 *   - Post-compromise security: each round trip performs a fresh X25519
 *     exchange, so an attacker who stole session state stops being able
 *     to read messages once both parties have sent again.
 *   - Post-quantum session start: the initial root key comes from the
 *     hybrid X25519 + ML-KEM-768 KEM, so the first messages are
 *     protected against harvest-now-decrypt-later. (The ongoing DH
 *     ratchet is classical X25519, as in Signal; see THREAT_MODEL.md.)
 *   - Out-of-order delivery: keys for skipped messages are kept, bounded
 *     by MAX_SKIP per chain and MAX_SKIPPED_TOTAL overall.
 *   - Transactional decrypt: a forged, replayed or corrupted message
 *     throws and leaves the session unchanged.
 *
 * SESSION START
 *   The initiator encapsulates to the responder's hybrid public key and
 *   sends first. Until the responder replies, every initiator message
 *   carries the KEM ciphertext (the "handshake"), so losing the first
 *   message doesn't strand the session. The responder creates its
 *   session from any of those messages with acceptSession().
 */

import { createHash, createHmac } from 'node:crypto';
import type { HybridCiphertext, HybridKeypair, HybridPublicKey } from './types.js';
import { encapsulate, decapsulate, generateX25519, x25519 } from './kem.js';
import { hkdf } from './kdf.js';
import { aeadEncryptWithNonce, aeadDecrypt } from './aead.js';

export const MAX_SKIP = 1000;
export const MAX_SKIPPED_TOTAL = 2000;

export interface RatchetHeader {
  /** Sender's current ratchet public key (32 bytes) */
  dh: Uint8Array;
  /** Number of messages in the sender's previous sending chain */
  pn: number;
  /** Message number in the current sending chain */
  n: number;
}

export interface RatchetMessage {
  version: 2;
  header: RatchetHeader;
  /** Present on initiator messages until the responder has replied */
  handshake?: HybridCiphertext;
  ciphertext: Uint8Array;
}

export interface DoubleRatchetSession {
  version: 2;
  role: 'initiator' | 'responder';
  /** Session associated data: binds every message to this handshake */
  ad: Uint8Array;
  rk: Uint8Array;
  dhs: { publicKey: Uint8Array; privateKey: Uint8Array };
  dhr: Uint8Array | null;
  cks: Uint8Array | null;
  ckr: Uint8Array | null;
  ns: number;
  nr: number;
  pn: number;
  /** "<dh b64url>:<n>" → message key, in insertion order (oldest first) */
  skipped: Map<string, Uint8Array>;
  pendingHandshake: HybridCiphertext | null;
}

const ZERO32 = new Uint8Array(32);

function kdfRk(rk: Uint8Array, dhOut: Uint8Array): [Uint8Array, Uint8Array] {
  const okm = hkdf(dhOut, rk, 'weave-yoxall/2 dr-rk', 64);
  return [okm.slice(0, 32), okm.slice(32)];
}

function kdfCk(ck: Uint8Array): [Uint8Array, Uint8Array] {
  const next = new Uint8Array(createHmac('sha256', ck).update(Uint8Array.of(0x02)).digest());
  const mk = new Uint8Array(createHmac('sha256', ck).update(Uint8Array.of(0x01)).digest());
  return [next, mk];
}

function messageKeyMaterial(mk: Uint8Array): { key: Uint8Array; nonce: Uint8Array } {
  const okm = hkdf(mk, ZERO32, 'weave-yoxall/2 dr-msg', 44);
  return { key: okm.slice(0, 32), nonce: okm.slice(32) };
}

export function encodeHeader(h: RatchetHeader): Uint8Array {
  if (h.dh.length !== 32) throw new Error('ratchet header: dh must be 32 bytes');
  const out = new Uint8Array(40);
  out.set(h.dh, 0);
  const dv = new DataView(out.buffer);
  dv.setUint32(32, h.pn, false);
  dv.setUint32(36, h.n, false);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Session AD = SHA-256(label ‖ KEM ciphertext ‖ responder public key). */
function sessionAd(handshake: HybridCiphertext, responder: HybridPublicKey): Uint8Array {
  return new Uint8Array(
    createHash('sha256')
      .update('weave-yoxall/2 dr-ad')
      .update(handshake.x25519EphemeralPublicKey)
      .update(handshake.mlkemCiphertext)
      .update(responder.x25519PublicKey)
      .update(responder.mlkemPublicKey)
      .digest(),
  );
}

function rootFromSecret(ss: Uint8Array): [Uint8Array, Uint8Array] {
  const okm = hkdf(ss, ZERO32, 'weave-yoxall/2 dr-init', 64);
  return [okm.slice(0, 32), okm.slice(32)];
}

const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64url');
const eq = (a: Uint8Array | null, b: Uint8Array) => !!a && a.length === b.length && Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;

/** Start a session as the initiator. Send first with ratchetEncrypt(). */
export function initiateSession(responder: HybridPublicKey): DoubleRatchetSession {
  const kem = encapsulate(responder, 2);
  const [rk, ck0] = rootFromSecret(kem.sharedSecret);
  return {
    version: 2,
    role: 'initiator',
    ad: sessionAd(kem.ciphertext, responder),
    rk,
    dhs: generateX25519(),
    dhr: null,
    cks: ck0,
    ckr: null,
    ns: 0,
    nr: 0,
    pn: 0,
    skipped: new Map(),
    pendingHandshake: kem.ciphertext,
  };
}

/**
 * Create the responder's session from an initiator message that carries
 * the handshake, and decrypt that message.
 */
export function acceptSession(
  responder: HybridKeypair,
  first: RatchetMessage,
  associatedData?: Uint8Array,
): { session: DoubleRatchetSession; plaintext: Uint8Array } {
  if (!first.handshake) throw new Error('acceptSession: message carries no handshake (not an initiator message)');
  const ss = decapsulate(responder, first.handshake, 2);
  const [rk0, ck0] = rootFromSecret(ss);
  const dhs = generateX25519();
  const [rk, cks] = kdfRk(rk0, x25519(dhs.privateKey, first.header.dh));
  const session: DoubleRatchetSession = {
    version: 2,
    role: 'responder',
    ad: sessionAd(first.handshake, responder),
    rk,
    dhs,
    dhr: new Uint8Array(first.header.dh),
    cks,
    ckr: ck0,
    ns: 0,
    nr: 0,
    pn: 0,
    skipped: new Map(),
    pendingHandshake: null,
  };
  const plaintext = ratchetDecrypt(session, first, associatedData);
  return { session, plaintext };
}

/** Encrypt the next message. Mutates the session. */
export function ratchetEncrypt(
  session: DoubleRatchetSession,
  plaintext: Uint8Array,
  associatedData?: Uint8Array,
): RatchetMessage {
  if (!session.cks) throw new Error('ratchetEncrypt: session has no sending chain');
  const [cks, mk] = kdfCk(session.cks);
  const header: RatchetHeader = { dh: new Uint8Array(session.dhs.publicKey), pn: session.pn, n: session.ns };
  const { key, nonce } = messageKeyMaterial(mk);
  const aad = concat(session.ad, encodeHeader(header), associatedData ?? new Uint8Array(0));
  const { ciphertext } = aeadEncryptWithNonce(key, plaintext, nonce, aad);
  session.cks = cks;
  session.ns += 1;
  return {
    version: 2,
    header,
    ...(session.pendingHandshake ? { handshake: session.pendingHandshake } : {}),
    ciphertext,
  };
}

/**
 * Decrypt a message. Throws on forgery, replay, too many skipped
 * messages or wrong associated data, and in that case the session is
 * left exactly as it was.
 */
export function ratchetDecrypt(
  session: DoubleRatchetSession,
  msg: RatchetMessage,
  associatedData?: Uint8Array,
): Uint8Array {
  if (msg.version !== 2) throw new Error(`ratchetDecrypt: unsupported message version ${msg.version}`);
  const s = cloneSession(session);
  const plaintext = decryptInto(s, msg, associatedData);
  if (s.role === 'initiator') s.pendingHandshake = null; // the responder has a session now
  Object.assign(session, s);
  return plaintext;
}

function decryptInto(s: DoubleRatchetSession, msg: RatchetMessage, associatedData?: Uint8Array): Uint8Array {
  const h = msg.header;
  const aad = concat(s.ad, encodeHeader(h), associatedData ?? new Uint8Array(0));

  const skippedId = `${b64(h.dh)}:${h.n}`;
  const skippedMk = s.skipped.get(skippedId);
  if (skippedMk) {
    s.skipped.delete(skippedId);
    return open(skippedMk, msg.ciphertext, aad);
  }

  if (!eq(s.dhr, h.dh)) {
    skipMessageKeys(s, h.pn);
    // DH ratchet step
    s.pn = s.ns;
    s.ns = 0;
    s.nr = 0;
    s.dhr = new Uint8Array(h.dh);
    [s.rk, s.ckr] = kdfRk(s.rk, x25519(s.dhs.privateKey, s.dhr));
    s.dhs = generateX25519();
    [s.rk, s.cks] = kdfRk(s.rk, x25519(s.dhs.privateKey, s.dhr));
  }

  skipMessageKeys(s, h.n);
  if (!s.ckr) throw new Error('ratchetDecrypt: no receiving chain');
  const [ckr, mk] = kdfCk(s.ckr);
  s.ckr = ckr;
  s.nr += 1;
  return open(mk, msg.ciphertext, aad);
}

function skipMessageKeys(s: DoubleRatchetSession, until: number): void {
  if (!s.ckr || !s.dhr) return;
  if (until - s.nr > MAX_SKIP) throw new Error(`ratchetDecrypt: more than ${MAX_SKIP} skipped messages`);
  while (s.nr < until) {
    const [ckr, mk] = kdfCk(s.ckr);
    s.ckr = ckr;
    s.skipped.set(`${b64(s.dhr)}:${s.nr}`, mk);
    s.nr += 1;
    while (s.skipped.size > MAX_SKIPPED_TOTAL) {
      s.skipped.delete(s.skipped.keys().next().value as string);
    }
  }
}

function open(mk: Uint8Array, ciphertext: Uint8Array, aad: Uint8Array): Uint8Array {
  const { key, nonce } = messageKeyMaterial(mk);
  try {
    return aeadDecrypt(key, { nonce, ciphertext, associatedData: aad });
  } catch {
    throw new Error('ratchetDecrypt: authentication failed (forged, replayed, out of window, or wrong AAD)');
  }
}

function cloneSession(s: DoubleRatchetSession): DoubleRatchetSession {
  const c = (u: Uint8Array | null) => (u ? new Uint8Array(u) : null);
  return {
    ...s,
    ad: new Uint8Array(s.ad),
    rk: new Uint8Array(s.rk),
    dhs: { publicKey: new Uint8Array(s.dhs.publicKey), privateKey: new Uint8Array(s.dhs.privateKey) },
    dhr: c(s.dhr),
    cks: c(s.cks),
    ckr: c(s.ckr),
    skipped: new Map([...s.skipped].map(([k, v]) => [k, new Uint8Array(v)])),
  };
}

/** Internal KDFs, exposed for known-answer test vectors only (not exported from the package index). */
export const __kdf = { kdfRk, kdfCk, messageKeyMaterial, rootFromSecret };
