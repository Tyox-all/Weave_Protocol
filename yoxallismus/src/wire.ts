/**
 * Wire format yoxall/2: LOCKED. Stable from 0.2.0-beta.0 through 1.0.
 *
 * Every envelope is JSON with `_type` and `_version: "yoxall/2"`; binary
 * fields are base64url without padding. Full spec and known-answer test
 * vectors: WIRE_FORMAT.md and test/vectors/. Readers ignore unknown
 * extra fields so later versions can add, never change, fields.
 *
 * v0.1 envelopes (`_version: "yoxall/0.1.0-beta.0"`) are still readable
 * through serialize.ts and PQCipher.
 */

import type { HybridCiphertext } from './types.js';
import type { SealedMessage, SealMode } from './sealed.js';
import type { DoubleRatchetSession, RatchetMessage } from './double-ratchet.js';

export const WIRE_VERSION_2 = 'yoxall/2';

const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64url');
function u8(s: unknown, field: string, len?: number): Uint8Array {
  if (typeof s !== 'string') throw new Error(`yoxall/2: missing field "${field}"`);
  const out = new Uint8Array(Buffer.from(s, 'base64url'));
  if (len !== undefined && out.length !== len) throw new Error(`yoxall/2: "${field}" must be ${len} bytes, got ${out.length}`);
  return out;
}
function uint(v: unknown, field: string): number {
  if (!Number.isInteger(v) || (v as number) < 0 || (v as number) > 0xffffffff) throw new Error(`yoxall/2: "${field}" must be a uint32`);
  return v as number;
}
function parse(s: string, type: string): Record<string, unknown> {
  const j = JSON.parse(s);
  if (j?._type !== type) throw new Error(`yoxall/2: expected ${type}, got ${j?._type}`);
  if (j._version !== WIRE_VERSION_2) throw new Error(`yoxall/2: unsupported version ${j._version}`);
  return j;
}

const kemOut = (k: HybridCiphertext) => ({ x25519eph: b64(k.x25519EphemeralPublicKey), mlkem: b64(k.mlkemCiphertext) });
const kemIn = (j: Record<string, unknown>): HybridCiphertext => ({
  x25519EphemeralPublicKey: u8(j.x25519eph, 'x25519eph', 32),
  mlkemCiphertext: u8(j.mlkem, 'mlkem', 1088),
});

// ─── Sealed message ─────────────────────────────────────────────

export function serializeSealed(m: SealedMessage): string {
  return JSON.stringify({ _type: 'yoxall-sealed', _version: WIRE_VERSION_2, mode: m.mode, ...kemOut(m.kem), nonce: b64(m.nonce), ct: b64(m.ciphertext) });
}

export function deserializeSealed(s: string): SealedMessage {
  const j = parse(s, 'yoxall-sealed');
  if (j.mode !== 'aes-256-gcm' && j.mode !== 'cascade') throw new Error(`yoxall/2: unknown seal mode ${j.mode}`);
  return { version: 2, mode: j.mode as SealMode, kem: kemIn(j), nonce: u8(j.nonce, 'nonce', 12), ciphertext: u8(j.ct, 'ct') };
}

// ─── Double-ratchet message ─────────────────────────────────────

export function serializeRatchetMessage(m: RatchetMessage): string {
  return JSON.stringify({
    _type: 'yoxall-dr-msg',
    _version: WIRE_VERSION_2,
    dh: b64(m.header.dh),
    pn: m.header.pn,
    n: m.header.n,
    ...(m.handshake ? { handshake: kemOut(m.handshake) } : {}),
    ct: b64(m.ciphertext),
  });
}

export function deserializeRatchetMessage(s: string): RatchetMessage {
  const j = parse(s, 'yoxall-dr-msg');
  return {
    version: 2,
    header: { dh: u8(j.dh, 'dh', 32), pn: uint(j.pn, 'pn'), n: uint(j.n, 'n') },
    ...(j.handshake ? { handshake: kemIn(j.handshake as Record<string, unknown>) } : {}),
    ciphertext: u8(j.ct, 'ct'),
  };
}

// ─── Double-ratchet session state (CONTAINS SECRETS) ───────────

export function serializeSession(s: DoubleRatchetSession): string {
  const opt = (u: Uint8Array | null) => (u ? b64(u) : null);
  return JSON.stringify({
    _type: 'yoxall-dr-session',
    _version: WIRE_VERSION_2,
    _warning: 'CONTAINS SECRET KEY MATERIAL — store encrypted, never log',
    role: s.role,
    ad: b64(s.ad),
    rk: b64(s.rk),
    dhsPub: b64(s.dhs.publicKey),
    dhsPriv: b64(s.dhs.privateKey),
    dhr: opt(s.dhr),
    cks: opt(s.cks),
    ckr: opt(s.ckr),
    ns: s.ns,
    nr: s.nr,
    pn: s.pn,
    skipped: [...s.skipped].map(([k, v]) => [k, b64(v)]),
    pendingHandshake: s.pendingHandshake ? kemOut(s.pendingHandshake) : null,
  });
}

export function deserializeSession(str: string): DoubleRatchetSession {
  const j = parse(str, 'yoxall-dr-session');
  if (j.role !== 'initiator' && j.role !== 'responder') throw new Error('yoxall/2: bad session role');
  const opt = (v: unknown, f: string) => (v === null || v === undefined ? null : u8(v, f, 32));
  return {
    version: 2,
    role: j.role,
    ad: u8(j.ad, 'ad', 32),
    rk: u8(j.rk, 'rk', 32),
    dhs: { publicKey: u8(j.dhsPub, 'dhsPub', 32), privateKey: u8(j.dhsPriv, 'dhsPriv', 32) },
    dhr: opt(j.dhr, 'dhr'),
    cks: opt(j.cks, 'cks'),
    ckr: opt(j.ckr, 'ckr'),
    ns: uint(j.ns, 'ns'),
    nr: uint(j.nr, 'nr'),
    pn: uint(j.pn, 'pn'),
    skipped: new Map(((j.skipped as Array<[string, string]>) ?? []).map(([k, v]) => [k, u8(v, 'skipped', 32)])),
    pendingHandshake: j.pendingHandshake ? kemIn(j.pendingHandshake as Record<string, unknown>) : null,
  };
}
