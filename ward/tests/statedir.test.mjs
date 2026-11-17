// Ward 0.3.13: when ~/.weave can't be written (a harness sandbox, a read-only
// home), Ward keeps its state in the temp folder, and a ledger it can't use
// never turns into "allow".
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, chmodSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const DIST = resolve('dist');
const asRoot = process.getuid?.() === 0 && 'root ignores permissions';
const uid = process.getuid?.() ?? 'user';

// A workspace and policy: secrets/ denied, everything else readable, optional limits
function setup({ limits = true, receipts = true } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'ward-state-'));
  const home = join(root, 'home'), tmp = join(root, 'tmp'), ws = join(root, 'ws');
  for (const d of [home, tmp, join(ws, 'secrets')]) mkdirSync(d, { recursive: true });
  const ward = `---\nward: "1.0"\nagent: state-test\n---\n\n## Filesystem\n\nallow:\n  - read: ${ws}/**\ndeny:\n  - read: ${ws}/secrets/**\ndefault: deny\n\n## Capabilities\n\ndefault: allow\n`
    + (limits ? '\n## Behavioral Limits\n\nmaxToolCalls: 50\n' : '')
    + (receipts ? '\n## Verification\n\nrequired: true\n' : '');
  return { root, home, tmp, ws, ward };
}

// Decide one Read in a child process with the given HOME and TMPDIR (and no WEAVE_* settings)
function decide({ home, tmp, ws, ward }, file, extraEnv = {}, wrap = []) {
  const script = `
    import { parseWard } from ${JSON.stringify(join(DIST, 'index.js'))};
    import { evaluateWithLedger, ledgerDir } from ${JSON.stringify(join(DIST, 'ledger/index.js'))};
    import { receiptDir, receiptKeyPath } from ${JSON.stringify(join(DIST, 'receipts/index.js'))};
    const r = evaluateWithLedger(parseWard(${JSON.stringify(ward)}), 'Read', { file_path: ${JSON.stringify(join(ws, file))} },
      { mappings: { Read: { capability: 'file_read', pathField: 'file_path', fsOp: 'read' } }, cwd: ${JSON.stringify(ws)}, session: 's' });
    process.stdout.write(JSON.stringify({ decision: r.decision, reasons: r.reasons, receipts: receiptDir(), ledger: ledgerDir(), key: receiptKeyPath() }));`;
  const env = { PATH: process.env.PATH, HOME: home, TMPDIR: tmp, ...extraEnv };
  const r = spawnSync(wrap[0] ?? process.execPath, [...wrap.slice(1), ...(wrap.length ? [process.execPath] : []), '--input-type=module', '-e', script], { env, encoding: 'utf8', timeout: 10000 });
  assert.equal(r.signal, null, 'must not hang');
  assert.ok(r.stdout, `no output: ${r.stderr}`);
  return JSON.parse(r.stdout);
}

describe('where Ward keeps its state', () => {
  test('a writable home keeps everything in ~/.weave', () => {
    const s = setup();
    const out = decide(s, 'secrets/key');
    assert.equal(out.decision, 'deny');
    assert.equal(out.ledger, join(s.home, '.weave', 'ledger'));
    assert.equal(out.receipts, join(s.home, '.weave', 'receipts'));
    assert.ok(existsSync(join(s.home, '.weave', 'receipts', 'state-test.jsonl')));
  });

  test('a read-only home moves state to the temp folder, and limits still count', { skip: asRoot }, () => {
    const s = setup();
    chmodSync(s.home, 0o500);
    try {
      const temp = join(s.tmp, `weave-${uid}`);
      assert.equal(decide(s, 'secrets/key').decision, 'deny');
      const ok = decide(s, 'a.txt');
      assert.equal(ok.decision, 'allow');
      assert.equal(ok.ledger, join(temp, 'ledger'));
      assert.equal(ok.receipts, join(temp, 'receipts'));
      assert.equal(ok.key, join(temp, 'keys', 'ward-receipts.pem'));
      assert.ok(existsSync(join(temp, 'ledger')) && existsSync(join(temp, 'receipts', 'state-test.jsonl')));
      assert.ok(!existsSync(join(s.home, '.weave')), 'nothing written under the read-only home');
    } finally { chmodSync(s.home, 0o700); }
  });

  test('an existing receipt key in a read-only ~/.weave is still used', { skip: asRoot }, () => {
    const s = setup();
    decide(s, 'a.txt'); // creates ~/.weave/keys/ward-receipts.pem, receipts/ and ledger/
    const locked = ['receipts', 'ledger', 'keys', ''].map((d) => join(s.home, '.weave', d));
    for (const d of locked) chmodSync(d, 0o500);
    try {
      const out = decide(s, 'a.txt');
      assert.equal(out.decision, 'allow');
      assert.equal(out.key, join(s.home, '.weave', 'keys', 'ward-receipts.pem'));
      assert.equal(out.receipts, join(s.tmp, `weave-${uid}`, 'receipts'));
      assert.equal(out.ledger, join(s.tmp, `weave-${uid}`, 'ledger'));
    } finally { for (const d of locked) chmodSync(d, 0o700); }
  });

  test('WEAVE_* settings are used as given', () => {
    const s = setup();
    const mine = join(s.root, 'mine');
    const out = decide(s, 'a.txt', { WEAVE_LEDGER_DIR: join(mine, 'l'), WEAVE_RECEIPT_DIR: join(mine, 'r'), WEAVE_RECEIPT_KEY_FILE: join(mine, 'k.pem') });
    assert.deepEqual([out.ledger, out.receipts, out.key], [join(mine, 'l'), join(mine, 'r'), join(mine, 'k.pem')]);
  });
});

describe('a ledger Ward cannot use', () => {
  test('never turns into allow: the rules\' deny stands, and other calls are denied with the reason', { skip: asRoot }, () => {
    const s = setup({ receipts: false });
    chmodSync(s.home, 0o500);
    chmodSync(s.tmp, 0o500);
    try {
      const secret = decide(s, 'secrets/key');
      assert.equal(secret.decision, 'deny');
      assert.match(secret.reasons[0], /Denied by filesystem rule/);
      const other = decide(s, 'a.txt');
      assert.equal(other.decision, 'deny');
      assert.match(other.reasons[0], /can't record calls to check them.*WEAVE_LEDGER_DIR/);
    } finally { chmodSync(s.home, 0o700); chmodSync(s.tmp, 0o700); }
  });

  test('a policy without limits is unaffected', { skip: asRoot }, () => {
    const s = setup({ limits: false, receipts: false });
    chmodSync(s.home, 0o500);
    chmodSync(s.tmp, 0o500);
    try {
      assert.equal(decide(s, 'a.txt').decision, 'allow');
      assert.equal(decide(s, 'secrets/key').decision, 'deny');
    } finally { chmodSync(s.home, 0o700); chmodSync(s.tmp, 0o700); }
  });
});

// The shape of Gemini CLI's and Qwen Code's default macOS profiles
// (permissive-open): read anything, write only the project and temp folders.
// Both CLIs re-launch themselves, hooks included, under such a profile.
describe('under macOS Seatbelt, like Gemini CLI and Qwen Code', { skip: process.platform !== 'darwin' && 'macOS only' }, () => {
  test('limits and receipts work from temp, and denies hold', () => {
    const s = setup();
    const profile = join(s.root, 'profile.sb');
    writeFileSync(profile, `(version 1)
(allow default)
(deny file-write*)
(allow file-write* (subpath (param "TARGET_DIR")) (subpath (param "TMP_DIR")) (literal "/dev/null"))
`);
    const real = (p) => spawnSync('realpath', [p], { encoding: 'utf8' }).stdout.trim();
    const wrap = ['sandbox-exec', '-f', profile, '-D', `TARGET_DIR=${real(s.ws)}`, '-D', `TMP_DIR=${real(s.tmp)}`];
    const secret = decide(s, 'secrets/key', {}, wrap);
    assert.equal(secret.decision, 'deny');
    assert.match(secret.reasons[0], /Denied by filesystem rule/);
    const ok = decide(s, 'a.txt', {}, wrap);
    assert.equal(ok.decision, 'allow', ok.reasons.join('; '));
    assert.ok(existsSync(join(s.tmp, `weave-${uid}`, 'receipts', 'state-test.jsonl')));
    assert.ok(!existsSync(join(s.home, '.weave')));
  });
});
