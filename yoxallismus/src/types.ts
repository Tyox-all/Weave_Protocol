/**
 * Public types for @weave_protocol/yoxallismus v0.1.0-beta.0.
 * See THREAT_MODEL.md for the security model these types operate within.
 */

// ─── PQ-hybrid KEM ──────────────────────────────────────────────

/**
 * A hybrid keypair combining X25519 (classical) and ML-KEM-768 (post-quantum).
 *
 * SIZES (v0.1.0-beta.0):
 *   x25519PublicKey:  32 bytes
 *   x25519PrivateKey: 32 bytes
 *   mlkemPublicKey:   1184 bytes (ML-KEM-768)
 *   mlkemPrivateKey:  2400 bytes (ML-KEM-768)
 */
export interface HybridKeypair {
  x25519PublicKey: Uint8Array;
  x25519PrivateKey: Uint8Array;
  mlkemPublicKey: Uint8Array;
  mlkemPrivateKey: Uint8Array;
}

/**
 * Public-key half of a hybrid keypair — the shareable identity.
 */
export interface HybridPublicKey {
  x25519PublicKey: Uint8Array;
  mlkemPublicKey: Uint8Array;
}

/**
 * The output of a hybrid KEM encapsulation.
 *
 * `sharedSecret` is a 32-byte value derived via HKDF-SHA-256 from
 * BOTH the X25519 shared secret AND the ML-KEM shared secret. If
 * either primitive is broken, the combined secret remains secure
 * (this is the core PQ-hybrid guarantee).
 *
 * `ciphertext` is the encapsulated key material that the recipient
 * uses to derive the same shared secret via decapsulation.
 */
export interface EncapsulationResult {
  sharedSecret: Uint8Array; // 32 bytes
  ciphertext: HybridCiphertext;
}

export interface HybridCiphertext {
  x25519EphemeralPublicKey: Uint8Array; // 32 bytes (ephemeral X25519 pub)
  mlkemCiphertext: Uint8Array; // 1088 bytes (ML-KEM-768 encapsulation)
}

// ─── AEAD ───────────────────────────────────────────────────────

/**
 * An AES-256-GCM encrypted payload.
 */
export interface EncryptedPayload {
  nonce: Uint8Array; // 12 bytes
  ciphertext: Uint8Array; // any length; includes 16-byte GCM auth tag
  associatedData?: Uint8Array; // optional AAD; must be provided identically on decrypt
}

// ─── Ratchet ────────────────────────────────────────────────────

/**
 * Symmetric ratchet session state.
 *
 * v0.1.0-beta.0 implements only a SYMMETRIC ratchet — each message
 * advances a chain key via HKDF. This provides forward secrecy but
 * NOT post-compromise recovery (which requires DH ratcheting, planned
 * for v0.2).
 */
export interface RatchetSession {
  chainKey: Uint8Array; // 32 bytes; advanced with each message
  messageNumber: number; // monotonic counter
  sessionId: Uint8Array; // 16 bytes; unique per session for uniqueness domain
}
