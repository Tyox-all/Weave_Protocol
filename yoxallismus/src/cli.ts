#!/usr/bin/env node
/**
 * weave-yoxall — CLI for @weave_protocol/yoxallismus v0.1.0-beta.0.
 *
 * Subcommands:
 *   status         Print library status, primitives, known limitations
 *   keygen         Generate a hybrid keypair, write to files
 *   encrypt        Encrypt a file to a recipient's public key
 *   decrypt        Decrypt a file with a private key
 *   test           Run all self-tests (reproducible-claims suite)
 *   benchmark      Micro-benchmarks vs baseline
 *   audit-self     Run known-attack test vectors
 *   help           Show this message
 */

import { readFileSync, writeFileSync, chmodSync } from 'node:fs';
import {
  STATUS,
  PQCipher,
  generateHybridKeypair,
  encapsulate,
  decapsulate,
  aeadEncrypt,
  aeadDecrypt,
  initRatchet,
  ratchetEncrypt,
  ratchetDecrypt,
  serializeKeypair, deserializeKeypair,
  serializePublicKey, deserializePublicKey,
  serializeCiphertext, deserializeCiphertext,
  serializePayload, deserializePayload,
} from './index.js';

const args = process.argv.slice(2);
const cmd = args[0];

// ─── Aggressive red callout ─────────────────────────────────────
function redCallout(title: string, lines: string[]): void {
  const RED = '\x1b[41m\x1b[1;37m';
  const RESET = '\x1b[0m';
  const width = Math.max(title.length + 4, ...lines.map((l) => l.length + 4), 60);
  const top = '┌─ ' + title + ' ' + '─'.repeat(Math.max(0, width - title.length - 4)) + '┐';
  const bot = '└' + '─'.repeat(width) + '┘';
  const pad = (s: string) => '│ ' + s + ' '.repeat(Math.max(0, width - s.length - 2)) + '│';
  console.log('');
  console.log(RED + ' ' + top + ' ' + RESET);
  console.log(RED + ' ' + pad('') + ' ' + RESET);
  for (const l of lines) console.log(RED + ' ' + pad(l) + ' ' + RESET);
  console.log(RED + ' ' + pad('') + ' ' + RESET);
  console.log(RED + ' ' + bot + ' ' + RESET);
  console.log('');
}

function banner(): void {
  console.log('');
  console.log('  🔐 \x1b[1mweave-yoxall\x1b[0m — post-quantum cipher composition');
  console.log('  @weave_protocol/yoxallismus \x1b[2mv' + STATUS.version + '\x1b[0m');
  console.log('');
}

function showHelp(): void {
  banner();
  console.log('  Usage:  weave-yoxall <command> [options]');
  console.log('');
  console.log('  Commands:');
  console.log('    status                              Print library status + known limitations');
  console.log('    keygen --out=<basename>             Generate hybrid keypair → <basename>.pub, <basename>.priv');
  console.log('    encrypt --to=<pub> --in=<file>      Encrypt file to recipient\'s public key');
  console.log('    decrypt --with=<priv> --in=<file>   Decrypt file with private key');
  console.log('    test                                Run all self-tests (reproducible-claims suite)');
  console.log('    benchmark                           Micro-benchmarks');
  console.log('    audit-self                          Run known-attack test vectors');
  console.log('    help                                This message');
  console.log('');
  console.log('  See THREAT_MODEL.md before use.');
  console.log('  See SECURITY.md for the bug bounty program.');
  console.log('');
}

function parseFlags(argv: string[]): Record<string, string | boolean> {
  const flags: Record<string, string | boolean> = {};
  for (const a of argv) {
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq > 0) flags[a.slice(2, eq)] = a.slice(eq + 1);
      else flags[a.slice(2)] = true;
    }
  }
  return flags;
}

// ─── status ─────────────────────────────────────────────────────

function cmdStatus(): void {
  banner();
  redCallout('EXPERIMENTAL — NOT AUDITED', [
    'This library has NOT undergone external cryptographic audit.',
    '',
    'Do NOT use for:',
    '  - Regulated data (HIPAA, PCI-DSS, SOC2)',
    '  - Medical records',
    '  - Financial records',
    '  - Legal evidence',
    '',
    'See THREAT_MODEL.md and SECURITY.md before adopting.',
  ]);
  console.log('  \x1b[1mVersion:\x1b[0m         ' + STATUS.version);
  console.log('  \x1b[1mStatus:\x1b[0m          ' + STATUS.status);
  console.log('  \x1b[1mAudited:\x1b[0m         ' + STATUS.audited);
  console.log('  \x1b[1mAudit planned:\x1b[0m   ' + STATUS.auditPlanned);
  console.log('  \x1b[1mProd-ready:\x1b[0m      ' + STATUS.productionReady);
  console.log('');
  console.log('  \x1b[1mPrimitives:\x1b[0m');
  console.log('    KEM:      ' + STATUS.primitivesUsed.kem.join(' + '));
  console.log('    AEAD:     ' + STATUS.primitivesUsed.aead.join(', '));
  console.log('    KDF:      ' + STATUS.primitivesUsed.kdf.join(', '));
  console.log('    Ratchet:  ' + STATUS.primitivesUsed.ratchet.join(', '));
  console.log('');
  console.log('  \x1b[1mScope for use:\x1b[0m');
  for (const s of STATUS.scopeForUse) console.log('    ✅ ' + s);
  console.log('');
  console.log('  \x1b[1mNOT for use with:\x1b[0m');
  for (const s of STATUS.scopeForNonUse) console.log('    ❌ ' + s);
  console.log('');
  console.log('  \x1b[1mKnown limitations (v0.1.0-beta.0):\x1b[0m');
  for (const s of STATUS.knownLimitations) console.log('    ⚠️  ' + s);
  console.log('');
}

// ─── keygen ─────────────────────────────────────────────────────

function cmdKeygen(): void {
  banner();
  const flags = parseFlags(args.slice(1));
  const out = flags.out as string | undefined;
  if (!out) {
    redCallout('Missing --out flag', [
      'weave-yoxall keygen --out=<basename>',
      '',
      'Example:',
      '',
      '  weave-yoxall keygen --out=./alice',
      '',
      'Produces ./alice.pub and ./alice.priv',
    ]);
    process.exit(1);
  }
  console.log(`  Generating hybrid keypair (X25519 + ML-KEM-768)...`);
  const kp = generateHybridKeypair();
  const pubPath = `${out}.pub`;
  const privPath = `${out}.priv`;
  writeFileSync(pubPath, serializePublicKey({ x25519PublicKey: kp.x25519PublicKey, mlkemPublicKey: kp.mlkemPublicKey }));
  writeFileSync(privPath, serializeKeypair(kp));
  chmodSync(privPath, 0o600);
  console.log(`  ✅ ${pubPath}   (${kp.x25519PublicKey.length + kp.mlkemPublicKey.length}-byte hybrid public key, JSON-wrapped)`);
  console.log(`  ✅ ${privPath}  (${kp.x25519PrivateKey.length + kp.mlkemPrivateKey.length}-byte hybrid private key, mode 600)`);
  console.log('');
  console.log('  \x1b[33m⚠  Keep the .priv file secret. Share only the .pub file.\x1b[0m');
  console.log('');
}

// ─── encrypt ────────────────────────────────────────────────────

function cmdEncrypt(): void {
  banner();
  const flags = parseFlags(args.slice(1));
  const toPath = flags.to as string | undefined;
  const inPath = flags.in as string | undefined;
  const outPath = (flags.out as string) || (inPath ? `${inPath}.yox` : undefined);
  if (!toPath || !inPath) {
    redCallout('Missing flags', [
      'weave-yoxall encrypt --to=<pub-file> --in=<plaintext-file> [--out=<ciphertext-file>]',
      '',
      'Example:',
      '',
      '  weave-yoxall encrypt --to=./bob.pub --in=./message.txt',
      '',
      'Default output is <input>.yox',
    ]);
    process.exit(1);
  }
  const recipientPub = deserializePublicKey(readFileSync(toPath, 'utf8'));
  const plaintext = readFileSync(inPath);
  const { ciphertext, payload } = PQCipher.encryptTo(recipientPub, new Uint8Array(plaintext));
  const envelope = JSON.stringify({
    _type: 'yoxall-encrypted-file',
    _version: 'yoxall/0.1.0-beta.0',
    kem: JSON.parse(serializeCiphertext(ciphertext)),
    payload: JSON.parse(serializePayload(payload)),
  }, null, 2);
  writeFileSync(outPath!, envelope);
  console.log(`  ✅ encrypted ${inPath} (${plaintext.length} bytes) → ${outPath}`);
  console.log(`     hybrid KEM (X25519+ML-KEM-768) + AES-256-GCM`);
}

// ─── decrypt ────────────────────────────────────────────────────

function cmdDecrypt(): void {
  banner();
  const flags = parseFlags(args.slice(1));
  const withPath = flags.with as string | undefined;
  const inPath = flags.in as string | undefined;
  const outPath = (flags.out as string) || (inPath ? inPath.replace(/\.yox$/, '') + '.decrypted' : undefined);
  if (!withPath || !inPath) {
    redCallout('Missing flags', [
      'weave-yoxall decrypt --with=<priv-file> --in=<ciphertext-file> [--out=<plaintext-file>]',
      '',
      'Example:',
      '',
      '  weave-yoxall decrypt --with=./bob.priv --in=./message.txt.yox',
    ]);
    process.exit(1);
  }
  const kp = deserializeKeypair(readFileSync(withPath, 'utf8'));
  const env = JSON.parse(readFileSync(inPath, 'utf8'));
  if (env._type !== 'yoxall-encrypted-file') {
    redCallout('Wrong file type', [`Expected yoxall-encrypted-file, got ${env._type}`]);
    process.exit(1);
  }
  const ct = deserializeCiphertext(JSON.stringify(env.kem));
  const payload = deserializePayload(JSON.stringify(env.payload));
  try {
    const plaintext = PQCipher.decryptFrom(kp, ct, payload);
    writeFileSync(outPath!, Buffer.from(plaintext));
    console.log(`  ✅ decrypted ${inPath} → ${outPath} (${plaintext.length} bytes)`);
  } catch (err) {
    redCallout('Decryption failed', [
      (err as Error).message,
      '',
      'Common causes:',
      '  - Wrong private key for this ciphertext',
      '  - Ciphertext tampered with',
      '  - File corruption',
    ]);
    process.exit(2);
  }
}

// ─── test ───────────────────────────────────────────────────────

function cmdTest(): void {
  banner();
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  let passed = 0, failed = 0;
  function ok(desc: string, cond: boolean): void {
    if (cond) { console.log(`  ✅ ${desc}`); passed++; }
    else { console.log(`  ❌ ${desc}`); failed++; }
  }

  console.log('  \x1b[1mReproducible-claims test suite\x1b[0m');
  console.log('  Every claim in the README is verified below.');
  console.log('');

  console.log('  1. AEAD (AES-256-GCM)');
  const key = new Uint8Array(32).fill(0x42);
  const pt = enc.encode('hello');
  const p = aeadEncrypt(key, pt);
  ok('encrypt/decrypt roundtrip', dec.decode(aeadDecrypt(key, p)) === 'hello');
  const tampered = { ...p, ciphertext: new Uint8Array(p.ciphertext) };
  tampered.ciphertext[0] ^= 1;
  let ct = false; try { aeadDecrypt(key, tampered); } catch { ct = true; }
  ok('rejects ciphertext bit-flip', ct);
  console.log('');

  console.log('  2. PQ-hybrid KEM (X25519 + ML-KEM-768)');
  const kp = generateHybridKeypair();
  ok('X25519 pub == 32 B (NIST FIPS 203)', kp.x25519PublicKey.length === 32);
  ok('ML-KEM pub == 1184 B (NIST FIPS 203)', kp.mlkemPublicKey.length === 1184);
  ok('ML-KEM priv == 2400 B (NIST FIPS 203)', kp.mlkemPrivateKey.length === 2400);
  const r = encapsulate({ x25519PublicKey: kp.x25519PublicKey, mlkemPublicKey: kp.mlkemPublicKey });
  ok('encap shared secret == 32 B', r.sharedSecret.length === 32);
  const d = decapsulate(kp, r.ciphertext);
  ok('decap shared secret matches encap', Buffer.compare(r.sharedSecret, d) === 0);
  console.log('');

  console.log('  3. End-to-end PQCipher facade');
  const alice = PQCipher.generateKeypair();
  const bob = PQCipher.generateKeypair();
  const msg = enc.encode('the quick brown fox');
  const bundle = PQCipher.encryptTo(PQCipher.publicKeyOf(bob), msg);
  ok('Alice→Bob roundtrip', dec.decode(PQCipher.decryptFrom(bob, bundle.ciphertext, bundle.payload)) === 'the quick brown fox');
  let wrongDec = false;
  try { const wrong = PQCipher.decryptFrom(alice, bundle.ciphertext, bundle.payload); wrongDec = dec.decode(wrong) !== 'the quick brown fox'; } catch { wrongDec = true; }
  ok('Wrong recipient cannot decrypt', wrongDec);
  console.log('');

  console.log('  4. Symmetric ratchet (forward secrecy within session)');
  const secret = new Uint8Array(32).fill(0x11);
  const sSend = initRatchet(secret);
  const sRecv = initRatchet(new Uint8Array(secret));
  sRecv.sessionId = new Uint8Array(sSend.sessionId);
  sRecv.chainKey = new Uint8Array(sSend.chainKey);
  const m1 = ratchetEncrypt(sSend, enc.encode('one'));
  const m2 = ratchetEncrypt(sSend, enc.encode('two'));
  ok('msg counter advances', sSend.messageNumber === 2);
  ok('recv msg 1', dec.decode(ratchetDecrypt(sRecv, m1)) === 'one');
  ok('recv msg 2', dec.decode(ratchetDecrypt(sRecv, m2)) === 'two');
  console.log('');

  console.log('  5. Serialization roundtrip');
  const kp3 = generateHybridKeypair();
  const j = serializePublicKey({ x25519PublicKey: kp3.x25519PublicKey, mlkemPublicKey: kp3.mlkemPublicKey });
  const r3 = deserializePublicKey(j);
  ok('public key JSON roundtrip preserves bytes',
    Buffer.compare(kp3.x25519PublicKey, r3.x25519PublicKey) === 0 &&
    Buffer.compare(kp3.mlkemPublicKey, r3.mlkemPublicKey) === 0);
  console.log('');

  console.log('  ═══ Results ═══');
  console.log(`  ${passed} passed · ${failed} failed`);
  console.log('');
  if (failed > 0) process.exit(1);
}

// ─── benchmark ──────────────────────────────────────────────────

function cmdBench(): void {
  banner();
  console.log('  \x1b[1mMicro-benchmarks\x1b[0m — 100 iters each, warm cache');
  console.log('');

  const iters = 100;
  const key = new Uint8Array(32).fill(0x7);
  const data1kb = new Uint8Array(1024).fill(0xa);

  // Convert BigInt ns to floating-point ms with proper precision
  const nsToMs = (ns: bigint, n: number): number => Number(ns) / 1_000_000 / n;

  // AEAD 1KB
  let t = process.hrtime.bigint();
  for (let i = 0; i < iters; i++) aeadEncrypt(key, data1kb);
  const aead_ms = nsToMs(process.hrtime.bigint() - t, iters);
  console.log(`  AEAD encrypt (1KB):              ${aead_ms.toFixed(4)} ms/op`);

  // Hybrid keygen
  t = process.hrtime.bigint();
  for (let i = 0; i < 20; i++) generateHybridKeypair();
  const keygen_ms = nsToMs(process.hrtime.bigint() - t, 20);
  console.log(`  Hybrid keygen:                   ${keygen_ms.toFixed(4)} ms/op`);

  // Encap + decap
  const kp = generateHybridKeypair();
  const pub = { x25519PublicKey: kp.x25519PublicKey, mlkemPublicKey: kp.mlkemPublicKey };
  t = process.hrtime.bigint();
  for (let i = 0; i < iters; i++) {
    const r = encapsulate(pub);
    decapsulate(kp, r.ciphertext);
  }
  const enc_dec_ms = nsToMs(process.hrtime.bigint() - t, iters);
  console.log(`  Hybrid encap + decap:            ${enc_dec_ms.toFixed(4)} ms/op`);

  // End-to-end PQCipher 1KB
  t = process.hrtime.bigint();
  for (let i = 0; i < iters; i++) {
    const b = PQCipher.encryptTo(pub, data1kb);
    PQCipher.decryptFrom(kp, b.ciphertext, b.payload);
  }
  const e2e_ms = nsToMs(process.hrtime.bigint() - t, iters);
  console.log(`  PQCipher e2e (1KB, encap+aead):  ${e2e_ms.toFixed(4)} ms/op`);
  console.log('');
}

// ─── audit-self ────────────────────────────────────────────────

function cmdAuditSelf(): void {
  banner();
  console.log('  \x1b[1mKnown-attack test vectors\x1b[0m');
  console.log('  These are attacks the primitives MUST reject.');
  console.log('');
  let passed = 0, failed = 0;
  function ok(desc: string, cond: boolean): void {
    if (cond) { console.log(`  ✅ ${desc}`); passed++; }
    else { console.log(`  ❌ ${desc}`); failed++; }
  }

  const enc = new TextEncoder();
  const key = new Uint8Array(32).fill(0xab);
  const pt = enc.encode('sensitive data');

  // Attack 1: single-bit ciphertext flip
  const p1 = aeadEncrypt(key, pt);
  const flipped = { ...p1, ciphertext: new Uint8Array(p1.ciphertext) };
  flipped.ciphertext[0] ^= 1;
  let a1 = false; try { aeadDecrypt(key, flipped); } catch { a1 = true; }
  ok('rejects single-bit ciphertext flip', a1);

  // Attack 2: auth tag flip
  const p2 = aeadEncrypt(key, pt);
  const tagFlip = { ...p2, ciphertext: new Uint8Array(p2.ciphertext) };
  tagFlip.ciphertext[tagFlip.ciphertext.length - 1] ^= 1;
  let a2 = false; try { aeadDecrypt(key, tagFlip); } catch { a2 = true; }
  ok('rejects auth-tag bit flip', a2);

  // Attack 3: wrong key
  const wrongKey = new Uint8Array(32).fill(0xcd);
  let a3 = false; try { aeadDecrypt(wrongKey, p1); } catch { a3 = true; }
  ok('rejects wrong key', a3);

  // Attack 4: truncated nonce
  const truncNonce = { ...p1, nonce: p1.nonce.slice(0, 8) };
  let a4 = false; try { aeadDecrypt(key, truncNonce as any); } catch { a4 = true; }
  ok('rejects truncated nonce', a4);

  // Attack 5: KEM implicit rejection - malformed ct with wrong recipient
  const kp = generateHybridKeypair();
  const other = generateHybridKeypair();
  const r = encapsulate({ x25519PublicKey: kp.x25519PublicKey, mlkemPublicKey: kp.mlkemPublicKey });
  const wrongDec = decapsulate(other, r.ciphertext);
  ok('ML-KEM implicit rejection (wrong ct + wrong key produces non-matching secret)',
    Buffer.compare(r.sharedSecret, wrongDec) !== 0);

  console.log('');
  console.log('  ═══ Results ═══');
  console.log(`  ${passed} passed · ${failed} failed`);
  console.log('');
  if (failed > 0) process.exit(1);
}

// ─── main ───────────────────────────────────────────────────────

(async () => {
  try {
    if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') { showHelp(); return; }
    if (cmd === 'status') return cmdStatus();
    if (cmd === 'keygen') return cmdKeygen();
    if (cmd === 'encrypt') return cmdEncrypt();
    if (cmd === 'decrypt') return cmdDecrypt();
    if (cmd === 'test') return cmdTest();
    if (cmd === 'benchmark') return cmdBench();
    if (cmd === 'audit-self') return cmdAuditSelf();
    console.error(`Unknown command: ${cmd}`);
    showHelp();
    process.exit(1);
  } catch (err) {
    console.error('Error:', (err as Error).stack || err);
    process.exit(1);
  }
})();
