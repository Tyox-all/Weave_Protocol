/**
 * Symmetric ratchet for @weave_protocol/yoxallismus v0.1.0-beta.0.
 *
 * Each message advances the chain key via HKDF, providing forward
 * secrecy within a session: if the current chain key is compromised
 * at message N, messages 1..N-1 remain confidential (their per-message
 * keys were derived from earlier chain state that is now unrecoverable).
 *
 * WHAT THIS DOESN'T DO (yet — planned for v0.2):
 *   - DH ratcheting (Signal Double Ratchet) — required for post-compromise
 *     recovery. Without it, if the chain key IS compromised at message N,
 *     all future messages 1..∞ from that session are readable to the
 *     attacker.
 *   - Out-of-order delivery handling — messages must be decrypted in
 *     order; skipped messages break the chain.
 *   - Skipped-message key retention — no support for holding decryption
 *     keys for future out-of-order arrivals.
 *
 * These are all real Signal Protocol features; v0.1 is deliberately
 * simpler while the wire format stabilizes.
 */

import { randomBytes } from 'node:crypto';
import type { RatchetSession, EncryptedPayload } from './types.js';
import { aeadEncryptWithNonce, aeadDecrypt } from './aead.js';
import { hkdf, deriveNonce } from './kdf.js';

const CHAIN_ADVANCE_INFO = 'weave-yoxall v0.1 chain-advance';
const MESSAGE_KEY_INFO = 'weave-yoxall v0.1 message-key';

/**
 * Initialize a ratchet session from an initial 32-byte shared secret
 * (typically the output of a hybrid KEM decapsulation).
 */
export function initRatchet(sharedSecret: Uint8Array): RatchetSession {
  if (sharedSecret.length !== 32) {
    throw new Error(`initRatchet: sharedSecret must be 32 bytes, got ${sharedSecret.length}`);
  }
  const sessionId = new Uint8Array(randomBytes(16));
  // Derive initial chain key from the shared secret, salted with sessionId
  const chainKey = hkdf(sharedSecret, sessionId, 'weave-yoxall v0.1 ratchet-init', 32);
  return {
    chainKey,
    messageNumber: 0,
    sessionId,
  };
}

/**
 * Encrypt a message, advancing the ratchet by one step.
 * Mutates the session in place.
 */
export function ratchetEncrypt(
  session: RatchetSession,
  plaintext: Uint8Array,
  associatedData?: Uint8Array,
): EncryptedPayload {
  const messageKey = hkdf(session.chainKey, session.sessionId, MESSAGE_KEY_INFO, 32);
  const nonce = deriveNonce(session.chainKey, session.messageNumber);

  // Combine caller AAD with session ID + message number for context binding
  const contextAAD = buildContextAAD(session.sessionId, session.messageNumber, associatedData);

  const payload = aeadEncryptWithNonce(messageKey, plaintext, nonce, contextAAD);

  // Advance chain — chainKey_new = HKDF(chainKey_old)
  session.chainKey = hkdf(session.chainKey, session.sessionId, CHAIN_ADVANCE_INFO, 32);
  session.messageNumber += 1;

  return payload;
}

/**
 * Decrypt a message, advancing the ratchet by one step.
 * Both sides must process messages in the same order for chain keys to match.
 */
export function ratchetDecrypt(
  session: RatchetSession,
  payload: EncryptedPayload,
  associatedData?: Uint8Array,
): Uint8Array {
  const messageKey = hkdf(session.chainKey, session.sessionId, MESSAGE_KEY_INFO, 32);

  // Rebuild the same AAD the sender bound
  const contextAAD = buildContextAAD(session.sessionId, session.messageNumber, associatedData);

  const plaintext = aeadDecrypt(messageKey, {
    ...payload,
    associatedData: contextAAD,
  });

  // Advance chain
  session.chainKey = hkdf(session.chainKey, session.sessionId, CHAIN_ADVANCE_INFO, 32);
  session.messageNumber += 1;

  return plaintext;
}

function buildContextAAD(sessionId: Uint8Array, msgNum: number, userAAD?: Uint8Array): Uint8Array {
  const msgNumBytes = new Uint8Array(8);
  new DataView(msgNumBytes.buffer).setBigUint64(0, BigInt(msgNum), false);
  const parts = [sessionId, msgNumBytes];
  if (userAAD) parts.push(userAAD);
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}
