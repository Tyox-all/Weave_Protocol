// adapter-codex against Codex CLI's documented hook contract
// (https://developers.openai.com/codex/hooks): stdin { cwd, tool_name,
// tool_input, ... }; deny via hookSpecificOutput.permissionDecision.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { parseWard } from '@weave_protocol/ward';
import { evaluateCall, toHookOutput, patchTargets } from '../dist/index.js';

const WARD = (ws) => `---
ward: "1.0"
agent: codex-test
---

## Filesystem

allow:
  - read: ${ws}/**
  - write: ${ws}/src/**
deny:
  - read: ${ws}/secrets/**
  - write: ${ws}/src/generated/**
default: deny

## Network

allow:
  - url: "https://docs.example.com/**"
deny:
  - url: "https://evil.example/**"
default: deny

## Capabilities

allow:
  - shell_exec
  - file_write
  - file_read
  - task_planning
  - mcp__files__*
default: deny
`;

const WS = '/workspace';
const policy = parseWard(WARD(WS));
const decide = (tool, input) => evaluateCall(policy, tool, input, WS).decision;
const patch = (...lines) => ['*** Begin Patch', ...lines, '*** End Patch'].join('\n');

describe('Bash (shell and unified exec)', () => {
  test('every URL and path in the command', () => {
    assert.equal(decide('Bash', { command: 'npm test' }), 'allow');
    assert.equal(decide('Bash', { command: 'curl https://docs.example.com/a && curl https://evil.example/s' }), 'deny');
    assert.equal(decide('Bash', { command: 'cat secrets/key' }), 'deny');
    assert.equal(decide('Bash', { command: `cat ${WS}/src/../secrets/key` }), 'deny', 'traversal');
  });
});

describe('apply_patch', () => {
  test('patchTargets reads the file markers', () => {
    assert.deepEqual(patchTargets(patch(
      '*** Add File: src/new.ts', '+x',
      '*** Update File: src/a.ts', '*** Move to: src/b.ts', '@@', '-a', '+b',
      '*** Delete File: src/old.ts',
    )), { writes: ['src/new.ts', 'src/a.ts', 'src/b.ts'], deletes: ['src/old.ts'] });
  });

  test('writes and deletes are checked against the files they touch', () => {
    assert.equal(decide('apply_patch', { command: patch('*** Update File: src/a.ts', '@@', '-a', '+b') }), 'allow');
    assert.equal(decide('apply_patch', { command: patch('*** Add File: src/generated/x.ts', '+x') }), 'deny', 'explicit deny');
    assert.equal(decide('apply_patch', { command: patch('*** Update File: README.md', '@@', '-a', '+b') }), 'deny', 'outside src/');
    assert.equal(decide('apply_patch', { command: patch('*** Update File: src/a.ts', '*** Move to: ../elsewhere/a.ts') }), 'deny', 'move target');
    assert.equal(decide('apply_patch', { command: patch('*** Delete File: src/old.ts') }), 'deny', 'no delete rule; default deny');
  });

  test('patch content mentioning denied paths is not treated as a target', () => {
    assert.equal(decide('apply_patch', { command: patch('*** Update File: src/a.ts', '@@', '+// see /workspace/secrets/key and https://evil.example') }), 'allow');
  });
});

describe('other tools', () => {
  test('MCP tools are gated by name and arguments', () => {
    assert.equal(decide('mcp__files__read', { path: `${WS}/src/a.ts` }), 'allow');
    assert.equal(decide('mcp__files__read', { path: `${WS}/secrets/key` }), 'deny');
    assert.equal(decide('mcp__other__thing', {}), 'deny');
  });

  test('update_plan is planning; unknown tools default to deny', () => {
    assert.equal(decide('update_plan', { plan: [] }), 'allow');
    assert.equal(decide('spawn_agent', {}), 'deny');
  });

  test('a non-object tool_input does not throw', () => {
    assert.equal(decide('Bash', 'npm test'), 'allow');
    assert.equal(decide('Bash', null), 'allow');
  });
});

test('output: deny and require_approval deny with a reason; allow prints nothing', () => {
  assert.equal(toHookOutput({ decision: 'allow', reasons: [] }, 'W'), undefined);
  const deny = toHookOutput({ decision: 'deny', reasons: ['nope'] }, 'W').hookSpecificOutput;
  assert.deepEqual({ ...deny, permissionDecisionReason: undefined }, { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: undefined });
  assert.match(deny.permissionDecisionReason, /nope/);
  assert.match(toHookOutput({ decision: 'require_approval', reasons: ['ask'] }, 'W').hookSpecificOutput.permissionDecisionReason, /requires approval/);
});

describe('CLI end to end (isolated CODEX_HOME)', () => {
  const cli = resolve('dist/cli.js');
  const home = mkdtempSync(join(tmpdir(), 'codex-home-'));
  const ws = mkdtempSync(join(tmpdir(), 'codex-ws-'));
  writeFileSync(join(ws, 'WARD.md'), WARD(ws));
  const env = { PATH: process.env.PATH, HOME: home, CODEX_HOME: join(home, '.codex') };
  const run = (args, input) => spawnSync(process.execPath, [cli, ...args], { input, env, encoding: 'utf8', cwd: ws });
  const hook = (payload) => {
    const r = run(['hook', 'pre-tool-use'], JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 's', cwd: ws, turn_id: 't', tool_use_id: 'u', permission_mode: 'default', ...payload }));
    assert.equal(r.status, 0, r.stderr);
    return r.stdout ? JSON.parse(r.stdout) : null;
  };

  test('a denied call prints a deny; an allowed one prints nothing', () => {
    const out = hook({ tool_name: 'Bash', tool_input: { command: 'cat secrets/key' } });
    assert.equal(out.hookSpecificOutput.permissionDecision, 'deny');
    assert.match(out.hookSpecificOutput.permissionDecisionReason, /secrets/);
    assert.equal(hook({ tool_name: 'Bash', tool_input: { command: 'ls src' } }), null);
  });

  test('an invalid WARD.md denies; no WARD.md allows', () => {
    const broken = mkdtempSync(join(tmpdir(), 'codex-ws-'));
    writeFileSync(join(broken, 'WARD.md'), '# not a policy');
    assert.match(hook({ cwd: broken, tool_name: 'Bash', tool_input: { command: 'ls' } }).hookSpecificOutput.permissionDecisionReason, /could not be loaded/);
    const none = mkdtempSync(join(tmpdir(), 'codex-ws-'));
    assert.equal(hook({ cwd: none, tool_name: 'Bash', tool_input: { command: 'ls' } }), null);
  });

  test('a malformed payload allows by default and denies with --fail-closed', () => {
    assert.equal(run(['hook', 'pre-tool-use'], '{not json').stdout, '');
    assert.equal(JSON.parse(run(['hook', 'pre-tool-use', '--fail-closed'], '{not json').stdout).hookSpecificOutput.permissionDecision, 'deny');
  });

  test('init and disable edit hooks.json idempotently, keeping other hooks', () => {
    const path = join(home, '.codex', 'hooks.json');
    mkdirSync(join(home, '.codex'), { recursive: true });
    writeFileSync(path, JSON.stringify({ description: 'mine', hooks: { PreToolUse: [{ matcher: '^Bash$', hooks: [{ type: 'command', command: 'my-check' }] }], Stop: [] } }));

    assert.equal(run(['init']).status, 0);
    const r = run(['init', '--fail-closed', '--timeout=20']);
    assert.match(r.stderr, /\/hooks/, 'tells the user to trust the hook');
    const f = JSON.parse(readFileSync(path, 'utf8'));
    assert.equal(f.description, 'mine');
    assert.deepEqual(f.hooks.Stop, []);
    assert.equal(f.hooks.PreToolUse.length, 2);
    assert.deepEqual(f.hooks.PreToolUse[1], {
      matcher: '*',
      hooks: [{ type: 'command', command: 'weave-ward-codex hook pre-tool-use --fail-closed', timeout: 20, statusMessage: 'Weave: checking WARD.md' }],
    });
    assert.ok(existsSync(`${path}.weave-backup`));

    assert.equal(run(['disable']).status, 0);
    assert.deepEqual(JSON.parse(readFileSync(path, 'utf8')).hooks.PreToolUse.map((g) => g.hooks[0].command), ['my-check']);
  });
});

async function runAsync(cmd, args, { input, ...opts }) {
  const { spawn } = await import('node:child_process');
  return new Promise((resolve) => {
    const child = spawn(cmd, args, opts);
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('close', (status) => resolve({ status, stdout, stderr }));
    child.stdin.end(input);
  });
}

async function fakeDashboard() {
  const { createServer } = await import('node:http');
  const received = [];
  const server = createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => { received.push(JSON.parse(raw)); res.writeHead(201); res.end('{}'); });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${server.address().port}`, received, close: () => server.close() };
}

test('reports the decision to the dashboard when WEAVE_DASHBOARD_URL is set', async () => {
  const dash = await fakeDashboard();
  try {
    const home = mkdtempSync(join(tmpdir(), 'report-home-'));
    const ws = mkdtempSync(join(tmpdir(), 'report-ws-'));
    writeFileSync(join(ws, 'WARD.md'), WARD(ws));
    // Async spawn: spawnSync would block this process, so the fake dashboard
    // couldn't accept the hook's report before the hook gave up.
    const r = await runAsync(process.execPath, [resolve('dist/cli.js'), ...['hook', 'pre-tool-use']], {
      input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 's', cwd: ws, tool_name: 'Bash', tool_input: { command: 'cat secrets/key' } }),
      env: { PATH: process.env.PATH, HOME: home, WEAVE_DASHBOARD_URL: dash.url }, encoding: 'utf8', cwd: ws,
    });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(dash.received.length, 1);
    assert.equal(dash.received[0].surface, 'codex');
    assert.equal(dash.received[0].decision, 'deny');
    assert.equal(dash.received[0].subject, 'Bash');
  } finally {
    dash.close();
  }
});
