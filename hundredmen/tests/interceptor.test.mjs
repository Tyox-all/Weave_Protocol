// Hundredmen's decision flow: WARD first, then scan, reputation, mode and review.
// The WARD argument cases and terminated sessions are regressions fixed in 1.2.0.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { Interceptor } from '../dist/index.js';
import { WardPolicyManager } from '../dist/ward.js';

const WARD = `---
ward: "1.0"
agent: t
---

## Filesystem

allow:
  - read: /workspace/**
  - write: /workspace/out/**
deny:
  - read: /workspace/secrets/**
default: deny

## Network

deny:
  - url: "https://evil.example/**"
default: allow

## Capabilities

requireApproval:
  - run_shell
deny:
  - nuke_everything
default: allow
`;

function setup(config = {}) {
  const i = new Interceptor({ scanEnabled: false, reputationEnabled: false, driftDetectionEnabled: false, ...config });
  const ward = new WardPolicyManager();
  ward.loadFromSource(WARD, 'test');
  i.setWardManager(ward);
  const session = i.createSession('agent-1');
  const call = (tool, args = {}, server = 'fs') => i.intercept(session.id, server, tool, args);
  return { i, session, call };
}

describe('WARD gate', () => {
  test('capability deny, approval and allow', async () => {
    const { call } = setup();
    assert.equal((await call('nuke_everything')).status, 'blocked');
    assert.equal((await call('run_shell')).status, 'pending');
    assert.equal((await call('read_file', { path: '/workspace/a.txt' })).status, 'approved');
  });

  test('filesystem rules apply to the path, with ".." normalized', async () => {
    const { call } = setup();
    assert.equal((await call('read_file', { path: '/workspace/secrets/key' })).status, 'blocked');
    assert.equal((await call('read_file', { path: '/workspace/x/../secrets/key' })).status, 'blocked');
  });

  test('every path argument is checked, and destinations are writes', async () => {
    const { call } = setup();
    const copy = await call('copy_file', { src: '/workspace/a.txt', dest: '/etc/cron.d/job' });
    assert.equal(copy.status, 'blocked', copy.decisionReason);
    assert.equal((await call('copy_file', { src: '/workspace/a.txt', dest: '/workspace/out/a.txt' })).status, 'approved');
    assert.equal((await call('read_files', { paths: ['/workspace/a.txt', '/workspace/secrets/key'] })).status, 'blocked');
  });

  test('a move/copy tool is a write even without a dest key', async () => {
    const { call } = setup();
    assert.equal((await call('move_file', { path: '/workspace/src/a.txt' })).status, 'blocked', 'write outside out/');
    assert.equal((await call('moveFile', { path: '/workspace/out/a.txt' })).status, 'approved');
  });

  test('URL arguments are checked in any case and scheme', async () => {
    const { call } = setup();
    assert.equal((await call('fetch', { url: 'https://evil.example/x' })).status, 'blocked');
    assert.equal((await call('fetch', { url: 'HTTPS://EVIL.EXAMPLE/x' })).status, 'blocked');
    assert.equal((await call('fetch', { urls: ['https://ok.example/', 'https://evil.example/y'] })).status, 'blocked');
    assert.equal((await call('fetch', { url: 'https://ok.example/' })).status, 'approved');
  });

  test('tool-name words, not substrings, decide the op ("format" is not "rm")', async () => {
    const { call } = setup();
    assert.equal((await call('format_text', { path: '/workspace/a.txt' })).status, 'approved');
  });

  test('without a WARD policy, calls fall through to the other checks', async () => {
    const i = new Interceptor({ scanEnabled: false, reputationEnabled: false, driftDetectionEnabled: false });
    const s = i.createSession('a');
    assert.equal((await i.intercept(s.id, 'fs', 'read_file', { path: '/anywhere' })).status, 'approved');
  });
});

describe('other checks', () => {
  test('a critical scan finding blocks', async () => {
    const { i, call } = setup({ scanEnabled: true });
    i.setScanner(async () => ({ safe: false, issues: [{ type: 'secret', severity: 'critical', message: 'AWS key' }] }));
    const c = await call('read_file', { path: '/workspace/a.txt' });
    assert.equal(c.status, 'blocked');
    assert.match(c.decisionReason, /AWS key/);
  });

  test('low reputation blocks', async () => {
    const { i, call } = setup({ reputationEnabled: true, minReputationScore: 50 });
    i.setReputationChecker(async () => 10);
    assert.equal((await call('read_file', { path: '/workspace/a.txt' })).status, 'blocked');
  });
});

describe('manual review and sessions', () => {
  test('pending calls can be approved or blocked; decided calls cannot be overridden', async () => {
    const { i, call } = setup();
    const pending = await call('run_shell');
    assert.equal(i.approveCall(pending.id, 'alice').status, 'approved');
    assert.equal(i.approveCall(pending.id, 'alice'), null, 'already decided');
    const blocked = await call('nuke_everything');
    assert.equal(i.approveCall(blocked.id, 'mallory'), null, 'a WARD block cannot be approved');
    const pending2 = await call('run_shell');
    assert.equal(i.blockCall(pending2.id, 'bob').status, 'blocked');
  });

  test('a terminated session gets nothing through', async () => {
    const { i, session, call } = setup();
    i.terminateSession(session.id, 'compromised');
    const c = await call('read_file', { path: '/workspace/a.txt' });
    assert.equal(c.status, 'blocked');
    assert.match(c.decisionReason, /terminated: compromised/);
  });

  test('unknown sessions are rejected', async () => {
    const { i } = setup();
    await assert.rejects(i.intercept('nope', 'fs', 'read_file', {}), /Session not found/);
  });
});
