// @weave_protocol/yoxallismus 0.2: tests run against dist/.
process.env.YOXALL_SILENCE_BETA_WARNING = '1';
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createDecipheriv } from 'node:crypto';
const Y = await import('../dist/index.js');
const { keypairFromSeeds, encapsulateWith } = await import('../dist/kem.js');
const { cascadeEncryptWith } = await import('../dist/cascade.js');
const { __kdf } = await import('../dist/double-ratchet.js');
const { hkdf } = await import('../dist/kdf.js');

const te = new TextEncoder();
const td = new TextDecoder();
const vectors = JSON.parse(readFileSync(new URL('./vectors/yoxall-2.json', import.meta.url), 'utf8'));
const hex = (u) => Buffer.from(u).toString('hex');
const fill = (n, b) => new Uint8Array(n).fill(b);
const sha = (u) => createHash('sha256').update(u).digest('hex');
const snapshot = (s) => Y.serializeSession(s);
const clone = (s) => Y.deserializeSession(Y.serializeSession(s));

describe('known-answer vectors (lock wire format yoxall/2)', () => {
  test('hybrid KEM, v2 and legacy combiners', () => {
    const v = vectors.kem;
    const kp = keypairFromSeeds(fill(32, 0x11), fill(64, 0x22));
    assert.equal(hex(kp.x25519PublicKey), v.recipientX25519Public);
    assert.equal(sha(kp.mlkemPublicKey), v.recipientMlkemPublicSha256);
    const e = encapsulateWith(kp, 2, fill(32, 0x33), fill(32, 0x44));
    assert.equal(hex(e.ciphertext.x25519EphemeralPublicKey), v.ephemeralX25519Public);
    assert.equal(sha(e.ciphertext.mlkemCiphertext), v.mlkemCiphertextSha256);
    assert.equal(hex(e.sharedSecret), v.sharedSecretV2);
    assert.equal(hex(Y.decapsulate(kp, e.ciphertext, 2)), v.sharedSecretV2);
    assert.equal(hex(encapsulateWith(kp, 1, fill(32, 0x33), fill(32, 0x44)).sharedSecret), v.sharedSecretV1Legacy);
  });

  test('cascade AEAD', () => {
    const v = vectors.cascade;
    const out = cascadeEncryptWith(Buffer.from(v.key, 'hex'), te.encode(v.plaintext), te.encode(v.aad), Buffer.from(v.n1, 'hex'), Buffer.from(v.n2, 'hex'));
    assert.equal(hex(out.nonce), v.nonce);
    assert.equal(hex(out.ciphertext), v.ciphertext);
    assert.equal(td.decode(Y.cascadeDecrypt(Buffer.from(v.key, 'hex'), out, te.encode(v.aad))), v.plaintext);
  });

  test('double-ratchet KDFs and header encoding', () => {
    const v = vectors.ratchet;
    const [rk0, ck0] = __kdf.rootFromSecret(fill(32, 0x88));
    const [rk1, ck1] = __kdf.kdfRk(rk0, fill(32, 0x99));
    const [ckNext, mk] = __kdf.kdfCk(ck0);
    const m = __kdf.messageKeyMaterial(mk);
    assert.deepEqual(
      [hex(rk0), hex(ck0), hex(rk1), hex(ck1), hex(ckNext), hex(mk), hex(m.key), hex(m.nonce)],
      [v.rootKey0, v.chainKey0, v.rootKey1, v.chainKey1, v.chainKey0Next, v.messageKey0, v.aesKey, v.aesNonce],
    );
    assert.equal(hex(Y.encodeHeader({ dh: fill(32, 0xaa), pn: 3, n: 7 })), v.header.encoded);
  });

  test('sealed-box key schedule', () => {
    const ss = fill(32, 0xbb);
    assert.equal(hex(hkdf(ss, new Uint8Array(32), 'weave-yoxall/2 seal aes-256-gcm', 32)), vectors.seal.keyAesGcm);
    assert.equal(hex(hkdf(ss, new Uint8Array(32), 'weave-yoxall/2 seal cascade', 32)), vectors.seal.keyCascade);
  });
});

describe('hybrid KEM', () => {
  test('v2 is the default and round-trips; v1 and v2 secrets differ', () => {
    const kp = Y.generateHybridKeypair();
    const e = Y.encapsulate(Y.publicKeyOf(kp));
    assert.deepEqual(Y.decapsulate(kp, e.ciphertext), e.sharedSecret);
    assert.notDeepEqual(Y.decapsulate(kp, e.ciphertext, 1), e.sharedSecret);
  });

  test('v2 binds the X25519 ephemeral key: swapping it changes the secret', () => {
    const kp = Y.generateHybridKeypair();
    const e = Y.encapsulate(Y.publicKeyOf(kp));
    const other = Y.encapsulate(Y.publicKeyOf(kp));
    const swapped = { ...e.ciphertext, x25519EphemeralPublicKey: other.ciphertext.x25519EphemeralPublicKey };
    assert.notDeepEqual(Y.decapsulate(kp, swapped), e.sharedSecret);
  });

  test('legacy PQCipher (v0.1 API) still round-trips', () => {
    const kp = Y.PQCipher.generateKeypair();
    const b = Y.PQCipher.encryptTo(Y.PQCipher.publicKeyOf(kp), te.encode('legacy'));
    assert.equal(td.decode(Y.PQCipher.decryptFrom(kp, b.ciphertext, b.payload)), 'legacy');
  });
});

describe('cascade AEAD', () => {
  const key = fill(32, 7);
  test('round-trips with AAD and adds 44 bytes', () => {
    const pt = te.encode('defense in depth');
    const c = Y.cascadeEncrypt(key, pt, te.encode('ctx'));
    assert.equal(Y.CASCADE_OVERHEAD, 44);
    assert.equal(c.ciphertext.length, pt.length + Y.CASCADE_OVERHEAD);
    assert.equal(td.decode(Y.cascadeDecrypt(key, c, te.encode('ctx'))), 'defense in depth');
  });

  test('outer layer decrypts to the inner AES-GCM layer, not the plaintext', () => {
    const pt = te.encode('two independent layers');
    const c = Y.cascadeEncrypt(key, pt);
    const kChacha = hkdf(key, new Uint8Array(32), 'weave-yoxall/2 cascade chacha20-poly1305', 32);
    const d = createDecipheriv('chacha20-poly1305', kChacha, c.nonce, { authTagLength: 16 });
    d.setAuthTag(c.ciphertext.subarray(c.ciphertext.length - 16));
    const inner = Buffer.concat([d.update(c.ciphertext.subarray(0, c.ciphertext.length - 16)), d.final()]);
    assert.equal(inner.length, 12 + pt.length + 16);
    assert.ok(!inner.includes(Buffer.from(pt)), 'inner layer must still be encrypted');
  });

  test('rejects tampering, wrong key and wrong AAD', () => {
    const c = Y.cascadeEncrypt(key, te.encode('x'), te.encode('a'));
    const bad = { ...c, ciphertext: new Uint8Array(c.ciphertext) };
    bad.ciphertext[3] ^= 1;
    assert.throws(() => Y.cascadeDecrypt(key, bad, te.encode('a')), /authentication failed/);
    assert.throws(() => Y.cascadeDecrypt(fill(32, 8), c, te.encode('a')), /authentication failed/);
    assert.throws(() => Y.cascadeDecrypt(key, c, te.encode('b')), /authentication failed/);
  });
});

describe('sealed boxes', () => {
  const bob = Y.generateHybridKeypair();
  const bobPub = Y.publicKeyOf(bob);
  for (const mode of ['aes-256-gcm', 'cascade']) {
    test(`${mode}: seal/open, wire round-trip, AAD enforced`, () => {
      const m = Y.seal(bobPub, te.encode('for bob'), { mode, aad: te.encode('inbox:bob') });
      const wire = Y.deserializeSealed(Y.serializeSealed(m));
      assert.equal(td.decode(Y.open(bob, wire, { aad: te.encode('inbox:bob') })), 'for bob');
      assert.throws(() => Y.open(bob, wire, { aad: te.encode('inbox:eve') }));
      assert.throws(() => Y.open(bob, wire));
    });
  }

  test('wrong recipient and tampered KEM ciphertext fail', () => {
    const m = Y.seal(bobPub, te.encode('x'));
    assert.throws(() => Y.open(Y.generateHybridKeypair(), m));
    const t = { ...m, kem: { ...m.kem, mlkemCiphertext: new Uint8Array(m.kem.mlkemCiphertext) } };
    t.kem.mlkemCiphertext[0] ^= 1;
    assert.throws(() => Y.open(bob, t));
  });

  test('envelope validation rejects wrong version, type and sizes', () => {
    const j = JSON.parse(Y.serializeSealed(Y.seal(bobPub, te.encode('x'))));
    assert.throws(() => Y.deserializeSealed(JSON.stringify({ ...j, _version: 'yoxall/0.1.0-beta.0' })), /unsupported version/);
    assert.throws(() => Y.deserializeSealed(JSON.stringify({ ...j, _type: 'yoxall-payload' })), /expected yoxall-sealed/);
    assert.throws(() => Y.deserializeSealed(JSON.stringify({ ...j, nonce: 'AAAA' })), /must be 12 bytes/);
    assert.throws(() => Y.deserializeSealed(JSON.stringify({ ...j, mode: 'xor' })), /unknown seal mode/);
  });
});

describe('double ratchet', () => {
  function pair() {
    const bob = Y.generateHybridKeypair();
    const alice = Y.initiateSession(Y.publicKeyOf(bob));
    return { bob, alice };
  }
  const send = (s, text, ad) => Y.drEncrypt(s, te.encode(text), ad);
  const recv = (s, m, ad) => td.decode(Y.drDecrypt(s, m, ad));

  test('two parties establish a session without sharing state out of band', () => {
    const { bob: bobKp, alice } = pair();
    const a1 = send(alice, 'hi bob');
    assert.ok(a1.handshake, 'initiator messages carry the handshake');
    const { session: bob, plaintext } = Y.acceptSession(bobKp, Y.deserializeRatchetMessage(Y.serializeRatchetMessage(a1)));
    assert.equal(td.decode(plaintext), 'hi bob');
    assert.equal(recv(alice, send(bob, 'hi alice')), 'hi alice');
    assert.equal(send(alice, 'after reply').handshake, undefined, 'handshake dropped once the responder has replied');
  });

  test('first message lost: responder accepts from a later one, then the lost one still decrypts', () => {
    const { bob: bobKp, alice } = pair();
    const a1 = send(alice, 'one');
    const a2 = send(alice, 'two');
    const { session: bob, plaintext } = Y.acceptSession(bobKp, a2);
    assert.equal(td.decode(plaintext), 'two');
    assert.equal(recv(bob, a1), 'one');
  });

  test('long random conversation stays in sync', () => {
    const { bob: bobKp, alice } = pair();
    const { session: bob } = Y.acceptSession(bobKp, send(alice, 'start'));
    let seed = 7;
    for (let i = 0; i < 200; i++) {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      const [from, to] = seed % 2 ? [alice, bob] : [bob, alice];
      assert.equal(recv(to, send(from, `m${i}`)), `m${i}`);
    }
  });

  test('out-of-order delivery across DH ratchet steps', () => {
    const { bob: bobKp, alice } = pair();
    const a = ['a0', 'a1', 'a2', 'a3'].map((t) => send(alice, t));
    const { session: bob } = Y.acceptSession(bobKp, a[3]);
    assert.equal(recv(alice, send(bob, 'b0')), 'b0'); // Alice ratchets to a new DH key
    const a4 = send(alice, 'a4');
    assert.equal(recv(bob, a4), 'a4'); // Bob ratchets
    assert.deepEqual([a[1], a[0], a[2]].map((m) => recv(bob, m)), ['a1', 'a0', 'a2']); // old chain via skipped keys
  });

  test('replay and tampering are rejected and leave the session unchanged', () => {
    const { bob: bobKp, alice } = pair();
    const a1 = send(alice, 'once');
    const { session: bob } = Y.acceptSession(bobKp, a1);
    const before = snapshot(bob);
    assert.throws(() => Y.drDecrypt(bob, a1), /authentication failed/);
    const a2 = send(alice, 'two');
    const forged = { ...a2, ciphertext: new Uint8Array(a2.ciphertext) };
    forged.ciphertext[0] ^= 1;
    assert.throws(() => Y.drDecrypt(bob, forged), /authentication failed/);
    const badHeader = { ...a2, header: { ...a2.header, pn: a2.header.pn + 1 } };
    assert.throws(() => Y.drDecrypt(bob, badHeader));
    assert.equal(snapshot(bob), before);
    assert.equal(recv(bob, a2), 'two');
  });

  test('associated data must match', () => {
    const { bob: bobKp, alice } = pair();
    const { session: bob } = Y.acceptSession(bobKp, send(alice, 'x', te.encode('ctx')), te.encode('ctx'));
    assert.throws(() => Y.drDecrypt(bob, send(alice, 'y', te.encode('ctx')), te.encode('other')));
  });

  test(`refuses more than ${'MAX_SKIP'} skipped messages`, () => {
    const { bob: bobKp, alice } = pair();
    const { session: bob } = Y.acceptSession(bobKp, send(alice, 'x'));
    let last;
    for (let i = 0; i <= Y.MAX_SKIP + 1; i++) last = send(alice, `m${i}`);
    assert.throws(() => Y.drDecrypt(bob, last), /skipped messages/);
  });

  test('post-compromise security: stolen state stops working after a DH round trip', () => {
    const { bob: bobKp, alice } = pair();
    const { session: bob } = Y.acceptSession(bobKp, send(alice, 'a1'));
    recv(alice, send(bob, 'b1'));
    recv(bob, send(alice, 'a2'));

    const eve = clone(bob); // attacker copies Bob's full session state
    recv(alice, send(bob, 'b2'));
    const a3 = send(alice, 'a3');
    assert.equal(recv(clone(eve), a3), 'a3', 'compromise window: stolen state reads the next message');
    recv(eve, a3);
    assert.equal(recv(bob, a3), 'a3');

    recv(alice, send(bob, 'b3')); // Bob's fresh DH key, unknown to Eve
    const a4 = send(alice, 'a4');
    assert.throws(() => Y.drDecrypt(eve, a4), 'healed: stolen state can no longer decrypt');
    assert.equal(recv(bob, a4), 'a4');
  });

  test('sessions survive serialization mid-conversation', () => {
    const { bob: bobKp, alice: a0 } = pair();
    let alice = a0;
    const a = [send(alice, 'one'), send(alice, 'two')];
    let { session: bob } = Y.acceptSession(bobKp, a[1]);
    alice = clone(alice);
    bob = clone(bob); // includes a skipped key for 'one'
    assert.equal(recv(bob, a[0]), 'one');
    assert.equal(recv(alice, send(bob, 'back')), 'back');
  });
});

describe('Yoxallismus v1 (Hord) payloads', () => {
  const fixture = JSON.parse(readFileSync(new URL('./vectors/hord-v1.json', import.meta.url), 'utf8'));
  test('inspectV1 parses a real Hord v1 header', () => {
    const info = Y.inspectV1(new Uint8Array(Buffer.from(fixture.base64, 'base64')));
    assert.deepEqual({ ...info, payloadBytes: undefined }, { version: 1, tumblers: 7, entropyRatio: 0.2, revolving: true, payloadBytes: undefined });
    assert.ok(info.payloadBytes > 0);
  });
  test('readV1 explains that v1 data is unrecoverable', () => {
    assert.throws(() => Y.readV1(fixture.base64, 'fixture-key'), (e) => e instanceof Y.V1PayloadUnrecoverableError && /YOXALL-2026-003/.test(e.message));
  });
  test('non-v1 input is rejected plainly', () => {
    assert.equal(Y.inspectV1(te.encode('not v1 at all')), null);
    assert.throws(() => Y.readV1(te.encode('nope')), /not a Yoxallismus v1 payload/);
  });
});
