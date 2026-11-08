// Ward 0.3.8: signed WARD.md policies.
import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { parseWard } from '../dist/index.js';
import { evaluateWithLedger } from '../dist/ledger/index.js';
import { signPolicySource, checkPolicySignature, loadPolicySigningKey, readSignature, signedContent } from '../dist/signing/index.js';

const WARD = `---
ward: "1.0"
agent: signed-test
---

## Filesystem

allow:
  - read: /repo/**
default: deny

## Capabilities

default: allow

## Verification

required: false
`;

let dir, key, other;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'ward-signing-'));
  process.env.WEAVE_POLICY_TRUSTED_KEYS_FILE = join(dir, 'trusted');
  delete process.env.WEAVE_POLICY_TRUSTED_KEYS;
  process.env.WEAVE_RECEIPTS = '0';
  key = loadPolicySigningKey(join(dir, 'team.pem'));
  other = loadPolicySigningKey(join(dir, 'other.pem'));
});

const run = (source) => evaluateWithLedger(parseWard(source), 'Read', { file_path: '/repo/a.ts' }, {
  mappings: { Read: { capability: 'file_read', pathField: 'file_path', fsOp: 'read' } },
});

describe('signatures', () => {
  test('a signed policy verifies, and parses exactly like the unsigned one', () => {
    const signed = signPolicySource(WARD, key);
    assert.match(signed, /<!-- ward-signature v1 keyId=\w{16} publicKey=\S+ signedAt=\S+ sig=\S+ -->\n$/);
    assert.equal(checkPolicySignature(signed, []).status, 'valid');
    assert.deepEqual(JSON.parse(JSON.stringify(parseWard(signed))), JSON.parse(JSON.stringify(parseWard(WARD))));
  });

  test('re-signing replaces the old signature; line endings do not matter', () => {
    const twice = signPolicySource(signPolicySource(WARD, other), key);
    assert.equal((twice.match(/ward-signature/g) ?? []).length, 1);
    assert.equal(readSignature(twice).keyId, key.keyId);
    assert.equal(checkPolicySignature(twice.replace(/\n/g, '\r\n'), [key.publicKeyB64]).status, 'valid');
    assert.equal(signedContent(WARD), signedContent(WARD.replace(/\n/g, '\r\n') + '   \n'));
  });

  test('any change after signing is caught', () => {
    const signed = signPolicySource(WARD, key);
    for (const edit of [(s) => s.replace('default: deny', 'default: allow'), (s) => s.replace('/repo/**', '/**'), (s) => s.replace('## Filesystem', '## Filesystem\n\nallow:\n  - write: /**')]) {
      const r = checkPolicySignature(edit(signed), []);
      assert.equal(r.status, 'tampered');
      assert.equal(r.ok, false);
    }
  });

  test('a forged signature line is caught', () => {
    const signed = signPolicySource(WARD, key);
    const swapped = signed.replace(/publicKey=\S+/, `publicKey=${other.publicKeyB64}`);
    assert.equal(checkPolicySignature(swapped, []).ok, false);
  });
});

describe('enforcement in evaluateWithLedger', () => {
  test('no trust list: unsigned and validly signed policies work; a tampered one denies everything', () => {
    assert.equal(run(WARD).decision, 'allow');
    const signed = signPolicySource(WARD, key);
    assert.equal(run(signed).decision, 'allow');
    const r = run(signed.replace('default: deny', 'default: allow'));
    assert.equal(r.decision, 'deny');
    assert.match(r.reasons[0], /changed after it was signed/);
  });

  test('with a trust list: only policies signed by a trusted key are enforced', () => {
    writeFileSync(process.env.WEAVE_POLICY_TRUSTED_KEYS_FILE, `# security team\n${key.publicKeyB64}\n`);
    assert.match(run(WARD).reasons[0], /not signed/);
    assert.equal(run(WARD).decision, 'deny');
    assert.equal(run(signPolicySource(WARD, key)).decision, 'allow');
    const byOther = run(signPolicySource(WARD, other));
    assert.equal(byOther.decision, 'deny');
    assert.match(byOther.reasons[0], /doesn't trust/);
  });

  test('WEAVE_POLICY_TRUSTED_KEYS works too', () => {
    process.env.WEAVE_POLICY_TRUSTED_KEYS = `${other.publicKeyB64}, ${key.publicKeyB64}`;
    assert.equal(run(signPolicySource(WARD, key)).decision, 'allow');
    assert.equal(run(WARD).decision, 'deny');
  });
});

test('CLI: sign writes the signature; verify passes, then fails after an edit', () => {
  const cli = resolve('dist/cli.js');
  const file = join(dir, 'WARD.md');
  writeFileSync(file, WARD);
  const env = { ...process.env, WEAVE_POLICY_KEY_FILE: join(dir, 'cli.pem') };
  const signed = spawnSync(process.execPath, [cli, 'sign', file], { env, encoding: 'utf8' });
  assert.equal(signed.status, 0, signed.stderr);
  const pub = signed.stdout.trim().split('\n').at(-1).trim();
  assert.equal(spawnSync(process.execPath, [cli, 'verify', file, `--key=${pub}`], { env }).status, 0);
  writeFileSync(file, readFileSync(file, 'utf8').replace('default: deny', 'default: allow'));
  const bad = spawnSync(process.execPath, [cli, 'verify', file], { env, encoding: 'utf8' });
  assert.equal(bad.status, 1);
  assert.match(bad.stdout, /changed after it was signed/);
  writeFileSync(file, '# not a policy');
  assert.equal(spawnSync(process.execPath, [cli, 'sign', file], { env }).status, 1, 'refuses to sign an invalid policy');
});
