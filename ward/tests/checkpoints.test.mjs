// Ward 0.3.9: signed checkpoints of receipt-log heads, so a log that was cut
// short or rewritten fails verification against a checkpoint kept elsewhere.
import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { parseWard } from '../dist/index.js';
import { evaluateWithLedger } from '../dist/ledger/index.js';
import { verifyReceiptLog, receiptLogPath, createCheckpoint, verifyCheckpoint, readCheckpoints, loadReceiptKeys } from '../dist/receipts/index.js';

const policy = parseWard(`---
ward: "1.0"
agent: checkpoint-test
---

## Capabilities

default: allow

## Verification

required: true
`);

let dir;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'ward-checkpoints-'));
  process.env.WEAVE_RECEIPT_DIR = join(dir, 'receipts');
  process.env.WEAVE_RECEIPT_KEY_FILE = join(dir, 'keys', 'ward-receipts.pem');
  process.env.WEAVE_LEDGER_DIR = join(dir, 'ledger');
  delete process.env.WEAVE_RECEIPTS;
});

const log = () => receiptLogPath('checkpoint-test');
const lines = () => readFileSync(log(), 'utf8').trim().split('\n');
const calls = (n) => { for (let i = 0; i < n; i++) evaluateWithLedger(policy, 'Tool', { i }, { session: 's' }); };

describe('checkpoints', () => {
  test('a checkpoint is signed, names the head, and matches the log', () => {
    calls(3);
    const cp = createCheckpoint(log());
    assert.equal(cp.agent, 'checkpoint-test');
    assert.equal(cp.seq, 3);
    assert.equal(cp.head, verifyReceiptLog(log()).head);
    assert.equal(verifyCheckpoint(cp), true);
    for (const edit of [{ seq: 2 }, { head: 'sha256:' + '1'.repeat(64) }, { agent: 'other' }]) assert.equal(verifyCheckpoint({ ...cp, ...edit }), false);
    calls(2);
    const r = verifyReceiptLog(log(), { checkpoints: [cp] });
    assert.equal(r.ok, true, JSON.stringify(r.problems));
    assert.equal(r.checkpoints, 1);
    assert.equal(r.checkpointedSeq, 3);
  });

  test('cutting off the newest receipts passes alone, but fails against a checkpoint', () => {
    calls(4);
    const cp = createCheckpoint(log());
    const l = lines(); l.splice(-2, 2); writeFileSync(log(), l.join('\n') + '\n');
    assert.equal(verifyReceiptLog(log()).ok, true, 'a shorter chain is still a chain');
    const r = verifyReceiptLog(log(), { checkpoints: [cp] });
    assert.equal(r.ok, false);
    assert.match(r.problems[0].problem, /receipts after #2 were removed/);
  });

  test('regenerating the log with the same key fails against an older checkpoint', () => {
    calls(3);
    const cp = createCheckpoint(log());
    rmSync(log());
    calls(3); // same key, same count, different receipts
    const r = verifyReceiptLog(log(), { checkpoints: [cp] });
    assert.equal(r.ok, false);
    assert.match(r.problems[0].problem, /receipt #3 doesn't match .* rewritten/);
  });

  test('a checkpoint from a key that never signed the log fails', () => {
    calls(2);
    const cp = createCheckpoint(log());
    rmSync(log());
    process.env.WEAVE_RECEIPT_KEY_FILE = join(dir, 'keys', 'forger.pem');
    calls(2);
    const r = verifyReceiptLog(log(), { checkpoints: [cp] });
    assert.equal(r.ok, false);
    assert.match(r.problems[0].problem, /never signed this log/);
  });

  test('checkpoints for other agents are ignored; a broken log cannot be checkpointed', () => {
    calls(2);
    const cp = createCheckpoint(log());
    assert.equal(verifyReceiptLog(log(), { checkpoints: [{ ...cp, agent: 'someone-else' }] }).checkpoints, 0);
    const l = lines(); const x = JSON.parse(l[1]); x.decision = 'deny'; l[1] = JSON.stringify(x); writeFileSync(log(), l.join('\n') + '\n');
    assert.throws(() => createCheckpoint(log()), /doesn't verify/);
  });

  test('readCheckpoints takes JSON lines, an array, or a Dōmere bundle', () => {
    calls(1);
    const cp = createCheckpoint(log());
    assert.equal(readCheckpoints(`${JSON.stringify(cp)}\n${JSON.stringify(cp)}\nnot json\n`).length, 2);
    assert.equal(readCheckpoints(JSON.stringify([cp, { type: 'other' }])).length, 1);
    assert.equal(readCheckpoints(JSON.stringify({ type: 'ward-receipt-anchor', checkpoints: [cp] })).length, 1);
  });
});

test('CLI: checkpoint, truncate, verify --checkpoints fails', () => {
  calls(3);
  const cli = resolve('dist/cli.js');
  const file = join(dir, 'checkpoints.jsonl');
  const made = spawnSync(process.execPath, [cli, 'receipts', 'checkpoint', log(), `--append=${file}`], { env: process.env, encoding: 'utf8' });
  assert.equal(made.status, 0, made.stderr);
  assert.equal(JSON.parse(made.stdout).seq, 3);
  const ok = spawnSync(process.execPath, [cli, 'receipts', 'verify', log(), `--checkpoints=${file}`], { env: process.env, encoding: 'utf8' });
  assert.equal(ok.status, 0, ok.stdout);
  assert.match(ok.stdout, /matches 1 checkpoint/);
  const l = lines(); l.pop(); writeFileSync(log(), l.join('\n') + '\n');
  const bad = spawnSync(process.execPath, [cli, 'receipts', 'verify', log(), `--checkpoints=${file}`], { env: process.env, encoding: 'utf8' });
  assert.equal(bad.status, 1);
  assert.match(bad.stdout, /were removed/);
  assert.ok(loadReceiptKeys().keyId);
});
