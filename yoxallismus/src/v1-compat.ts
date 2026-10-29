/**
 * Yoxallismus v1 (Hord's YoxallismusCipher): detection only.
 *
 * Planned as a read-only decoder, but v1 payloads cannot be decrypted:
 *
 *   - lock() derives its XOR mask from HMAC(deadboltKey, seed), where
 *     seed = SHA-256(tumblerKey ‖ SHA-256(plaintext)). The seed depends on
 *     the plaintext and only its first 1-12 bytes reach the header (as
 *     tumbler positions, already advanced during encryption).
 *   - unlock() rebuilds the mask from the header bytes instead, so Hord's
 *     own unlock() never round-trips, and no decoder with the key can
 *     recover the remaining 20+ seed bytes short of brute force.
 *
 * See SECURITY_ADVISORIES.md YOXALL-2026-003. v1 was also never an
 * encryption scheme: no authentication, deterministic, and permutation
 * plus XOR rather than a cipher. Re-encrypt from the original plaintext
 * with seal() instead.
 */

export interface V1HeaderInfo {
  version: 1;
  tumblers: number;
  entropyRatio: number;
  revolving: boolean;
  payloadBytes: number;
}

export class V1PayloadUnrecoverableError extends Error {
  constructor(public readonly info: V1HeaderInfo) {
    super(
      `[yoxallismus] This is a Yoxallismus v1 (Hord YoxallismusCipher) payload ` +
        `(${info.tumblers} tumblers, ${Math.round(info.entropyRatio * 100)}% entropy, ` +
        `${info.payloadBytes} bytes). v1 payloads cannot be decrypted by any implementation: ` +
        `the masking key depends on plaintext bytes that are not stored. See ` +
        `SECURITY_ADVISORIES.md YOXALL-2026-003; re-encrypt from the original data with seal().`,
    );
    this.name = 'V1PayloadUnrecoverableError';
  }
}

/** Parse a v1 header, or return null if the bytes aren't a v1 payload. */
export function inspectV1(payload: Uint8Array): V1HeaderInfo | null {
  if (payload.length < 8 || Buffer.from(payload.subarray(0, 4)).toString('latin1') !== 'YXLS' || payload[4] !== 1) return null;
  const tumblers = payload[5];
  const headerSize = 8 + tumblers + 8;
  if (tumblers < 1 || tumblers > 12 || payload.length < headerSize) return null;
  return {
    version: 1,
    tumblers,
    entropyRatio: payload[6] / 100,
    revolving: payload[7] === 1,
    payloadBytes: payload.length - headerSize,
  };
}

/**
 * Kept for API compatibility. Identifies v1 payloads and always throws:
 * V1PayloadUnrecoverableError for genuine v1 data, Error otherwise.
 */
export function readV1(payload: Uint8Array | string, _oldKey?: unknown): never {
  const bytes = typeof payload === 'string' ? new Uint8Array(Buffer.from(payload, 'base64')) : payload;
  const info = inspectV1(bytes);
  if (info) throw new V1PayloadUnrecoverableError(info);
  throw new Error('[yoxallismus] not a Yoxallismus v1 payload (no YXLS v1 header)');
}
