// Regenerates test/vectors/*.json. The committed vectors LOCK wire format
// yoxall/2: only rerun this for a deliberate, versioned format change.
import { writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
process.env.YOXALL_SILENCE_BETA_WARNING = '1';
const { keypairFromSeeds, encapsulateWith } = await import('../dist/kem.js');
const { cascadeEncryptWith } = await import('../dist/cascade.js');
const { __kdf, encodeHeader } = await import('../dist/double-ratchet.js');
const { hkdf } = await import('../dist/kdf.js');

const hex = (u) => Buffer.from(u).toString('hex');
const fill = (n, b) => new Uint8Array(n).fill(b);
const sha = (u) => createHash('sha256').update(u).digest('hex');

const recipient = keypairFromSeeds(fill(32, 0x11), fill(64, 0x22));
const v2 = encapsulateWith(recipient, 2, fill(32, 0x33), fill(32, 0x44));
const v1 = encapsulateWith(recipient, 1, fill(32, 0x33), fill(32, 0x44));

const kem = {
  description: 'Hybrid KEM, deterministic inputs. Byte fields are hex; large fields as SHA-256.',
  inputs: { recipientX25519Private: hex(fill(32, 0x11)), recipientMlkemSeed: hex(fill(64, 0x22)), ephemeralX25519Private: hex(fill(32, 0x33)), mlkemRandomness: hex(fill(32, 0x44)) },
  recipientX25519Public: hex(recipient.x25519PublicKey),
  recipientMlkemPublicSha256: sha(recipient.mlkemPublicKey),
  ephemeralX25519Public: hex(v2.ciphertext.x25519EphemeralPublicKey),
  mlkemCiphertextSha256: sha(v2.ciphertext.mlkemCiphertext),
  sharedSecretV2: hex(v2.sharedSecret),
  sharedSecretV1Legacy: hex(v1.sharedSecret),
};

const key = fill(32, 0x55);
const casc = cascadeEncryptWith(key, new TextEncoder().encode('yoxall/2 cascade vector'), new TextEncoder().encode('aad'), fill(12, 0x66), fill(12, 0x77));
const cascade = { key: hex(key), plaintext: 'yoxall/2 cascade vector', aad: 'aad', n1: hex(fill(12, 0x66)), n2: hex(fill(12, 0x77)), nonce: hex(casc.nonce), ciphertext: hex(casc.ciphertext) };

const [rk0, ck0] = __kdf.rootFromSecret(fill(32, 0x88));
const [rk1, ck1] = __kdf.kdfRk(rk0, fill(32, 0x99));
const [ckNext, mk] = __kdf.kdfCk(ck0);
const mkm = __kdf.messageKeyMaterial(mk);
const ratchet = {
  sharedSecret: hex(fill(32, 0x88)), rootKey0: hex(rk0), chainKey0: hex(ck0),
  dhOut: hex(fill(32, 0x99)), rootKey1: hex(rk1), chainKey1: hex(ck1),
  chainKey0Next: hex(ckNext), messageKey0: hex(mk), aesKey: hex(mkm.key), aesNonce: hex(mkm.nonce),
  header: { dh: hex(fill(32, 0xaa)), pn: 3, n: 7, encoded: hex(encodeHeader({ dh: fill(32, 0xaa), pn: 3, n: 7 })) },
};
const seal = {
  sharedSecret: hex(fill(32, 0xbb)),
  keyAesGcm: hex(hkdf(fill(32, 0xbb), new Uint8Array(32), 'weave-yoxall/2 seal aes-256-gcm', 32)),
  keyCascade: hex(hkdf(fill(32, 0xbb), new Uint8Array(32), 'weave-yoxall/2 seal cascade', 32)),
};
writeFileSync(new URL('./vectors/yoxall-2.json', import.meta.url), JSON.stringify({ format: 'yoxall/2', kem, cascade, ratchet, seal }, null, 2) + '\n');
console.log('wrote test/vectors/yoxall-2.json');
