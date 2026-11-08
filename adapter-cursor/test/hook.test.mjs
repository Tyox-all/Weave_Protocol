// adapter-cursor against Cursor's documented agent hooks
// (https://cursor.com/docs/agent/hooks): beforeShellExecution { command, cwd },
// beforeMCPExecution { tool_name, tool_input: string, mcp_server_name },
// beforeReadFile { file_path }, preToolUse { tool_name, tool_input, cwd };
// output { permission, user_message, agent_message }.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { parseWard } from '@weave_protocol/ward';
import { toToolCall, evaluateCall, toHookOutput } from '../dist/index.js';

const WARD = (ws) => `---
ward: "1.0"
agent: cursor-test
---

## Filesystem

allow:
  - read: ${ws}/**
  - write: ${ws}/src/**
deny:
  - read: ${ws}/secrets/**
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
  - file_read
  - file_write
  - mcp__files__*
requireApproval:
  - mcp__mail__*
default: deny
`;

const WS = '/workspace';
const policy = parseWard(WARD(WS));
const base = { conversation_id: 'c', workspace_roots: [WS] };
const decide = (payload) => {
  const call = toToolCall({ ...base, ...payload });
  return call ? evaluateCall(policy, call).decision : 'skipped';
};

describe('events', () => {
  test('beforeShellExecution: every URL and path, relative to cwd', () => {
    assert.equal(decide({ hook_event_name: 'beforeShellExecution', command: 'npm test', cwd: WS }), 'allow');
    assert.equal(decide({ hook_event_name: 'beforeShellExecution', command: 'curl https://docs.example.com/a; curl https://evil.example/s', cwd: WS }), 'deny');
    assert.equal(decide({ hook_event_name: 'beforeShellExecution', command: 'cat key', cwd: `${WS}/secrets` }), 'deny');
  });

  test('beforeReadFile uses file_path', () => {
    assert.equal(decide({ hook_event_name: 'beforeReadFile', file_path: `${WS}/src/a.ts` }), 'allow');
    assert.equal(decide({ hook_event_name: 'beforeReadFile', file_path: `${WS}/secrets/key` }), 'deny');
    assert.equal(decide({ hook_event_name: 'beforeReadFile', file_path: `${WS}/src/../secrets/key` }), 'deny', 'traversal');
  });

  test('beforeMCPExecution: tool_input is a JSON string; named mcp__<server>__<tool>', () => {
    assert.deepEqual(toToolCall({ ...base, hook_event_name: 'beforeMCPExecution', mcp_server_name: 'files', tool_name: 'copy', tool_input: '{"source":"a"}' }).tool, 'mcp__files__copy');
    assert.equal(decide({ hook_event_name: 'beforeMCPExecution', mcp_server_name: 'files', tool_name: 'read', tool_input: JSON.stringify({ path: `${WS}/src/a` }) }), 'allow');
    assert.equal(decide({ hook_event_name: 'beforeMCPExecution', mcp_server_name: 'files', tool_name: 'read', tool_input: JSON.stringify({ path: `${WS}/secrets/k` }) }), 'deny');
    assert.equal(decide({ hook_event_name: 'beforeMCPExecution', mcp_server_name: 'mail', tool_name: 'send', tool_input: '{}' }), 'require_approval');
    assert.equal(decide({ hook_event_name: 'beforeMCPExecution', mcp_server_name: 'files', tool_name: 'x', tool_input: 'not json' }), 'allow', 'bad JSON input is just empty args');
  });

  test('preToolUse covers the remaining tools and skips Shell, Read and MCP', () => {
    assert.equal(decide({ hook_event_name: 'preToolUse', tool_name: 'Write', tool_input: { file_path: `${WS}/src/a.ts`, contents: 'x' }, cwd: WS }), 'allow');
    assert.equal(decide({ hook_event_name: 'preToolUse', tool_name: 'Write', tool_input: { target_file: `${WS}/README.md` }, cwd: WS }), 'deny', 'outside src/');
    assert.equal(decide({ hook_event_name: 'preToolUse', tool_name: 'Delete', tool_input: { path: `${WS}/src/a.ts` }, cwd: WS }), 'deny', 'no delete capability');
    assert.equal(decide({ hook_event_name: 'preToolUse', tool_name: 'Shell', tool_input: { command: 'cat secrets/key' } }), 'skipped');
    assert.equal(decide({ hook_event_name: 'preToolUse', tool_name: 'Read', tool_input: {} }), 'skipped');
    assert.equal(decide({ hook_event_name: 'preToolUse', tool_name: 'MCP:copy', tool_input: {} }), 'skipped');
  });

  test('other events are left alone', () => {
    assert.equal(toToolCall({ ...base, hook_event_name: 'afterFileEdit', file_path: 'x' }), null);
  });
});

describe('output', () => {
  test('allow prints nothing; deny carries the reason to user and agent', () => {
    assert.equal(toHookOutput({ decision: 'allow', reasons: [] }, 'W', true), undefined);
    const d = toHookOutput({ decision: 'deny', reasons: ['nope'] }, 'W', false);
    assert.equal(d.permission, 'deny');
    assert.match(d.user_message, /nope/);
    assert.equal(d.agent_message, d.user_message);
  });

  test('require_approval is "ask" where Cursor enforces it, "deny" elsewhere', () => {
    assert.equal(toHookOutput({ decision: 'require_approval', reasons: ['r'] }, 'W', true).permission, 'ask');
    assert.equal(toHookOutput({ decision: 'require_approval', reasons: ['r'] }, 'W', false).permission, 'deny');
  });
});

describe('CLI end to end (isolated HOME)', () => {
  const cli = resolve('dist/cli.js');
  const home = mkdtempSync(join(tmpdir(), 'cursor-home-'));
  const ws = mkdtempSync(join(tmpdir(), 'cursor-ws-'));
  writeFileSync(join(ws, 'WARD.md'), WARD(ws));
  const env = { PATH: process.env.PATH, HOME: home };
  const run = (args, input) => spawnSync(process.execPath, [cli, ...args], { input, env, encoding: 'utf8', cwd: home });
  const hook = (payload) => {
    const r = run(['hook'], JSON.stringify({ conversation_id: 'c', workspace_roots: [ws], ...payload }));
    assert.equal(r.status, 0, r.stderr);
    return r.stdout ? JSON.parse(r.stdout) : null;
  };

  test('a denied read prints deny; an allowed one prints nothing', () => {
    assert.equal(hook({ hook_event_name: 'beforeReadFile', file_path: join(ws, 'secrets', 'k') }).permission, 'deny');
    assert.equal(hook({ hook_event_name: 'beforeReadFile', file_path: join(ws, 'src', 'a.ts') }), null);
  });

  test('an MCP call needing approval prints "ask"', () => {
    assert.equal(hook({ hook_event_name: 'beforeMCPExecution', mcp_server_name: 'mail', tool_name: 'send', tool_input: '{}' }).permission, 'ask');
  });

  test('an invalid WARD.md denies; a malformed payload allows unless --fail-closed', () => {
    const broken = mkdtempSync(join(tmpdir(), 'cursor-ws-'));
    writeFileSync(join(broken, 'WARD.md'), '# not a policy');
    assert.match(hook({ workspace_roots: [broken], hook_event_name: 'beforeShellExecution', command: 'ls', cwd: broken }).user_message, /could not be loaded/);
    assert.equal(run(['hook'], '{bad').stdout, '');
    assert.equal(JSON.parse(run(['hook', '--fail-closed'], '{bad').stdout).permission, 'deny');
  });

  test('init and disable edit hooks.json on all four events, keeping other hooks', () => {
    const path = join(home, '.cursor', 'hooks.json');
    mkdirSync(join(home, '.cursor'), { recursive: true });
    writeFileSync(path, JSON.stringify({ version: 1, hooks: { beforeShellExecution: [{ command: './my-audit.sh' }], afterFileEdit: [{ command: './fmt.sh' }] } }));
    assert.equal(run(['init']).status, 0);
    assert.equal(run(['init', '--timeout=5']).status, 0);
    const f = JSON.parse(readFileSync(path, 'utf8'));
    assert.equal(f.version, 1);
    assert.deepEqual(f.hooks.afterFileEdit, [{ command: './fmt.sh' }]);
    assert.deepEqual(f.hooks.beforeShellExecution, [{ command: './my-audit.sh' }, { command: 'weave-ward-cursor hook', timeout: 5 }]);
    for (const ev of ['beforeMCPExecution', 'beforeReadFile', 'preToolUse']) assert.deepEqual(f.hooks[ev], [{ command: 'weave-ward-cursor hook', timeout: 5 }], ev);
    assert.ok(existsSync(`${path}.weave-backup`));
    assert.equal(run(['status'], '').stderr.includes('installed'), true);

    assert.equal(run(['disable']).status, 0);
    const after = JSON.parse(readFileSync(path, 'utf8'));
    assert.deepEqual(Object.keys(after.hooks).sort(), ['afterFileEdit', 'beforeShellExecution']);
    assert.deepEqual(after.hooks.beforeShellExecution, [{ command: './my-audit.sh' }]);
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
    const r = await runAsync(process.execPath, [resolve('dist/cli.js'), ...['hook']], {
      input: JSON.stringify({ hook_event_name: 'beforeReadFile', workspace_roots: [ws], file_path: join(ws, 'secrets', 'k') }),
      // A cold first request on a slow CI runner can exceed the 250ms default
      env: { PATH: process.env.PATH, HOME: home, WEAVE_DASHBOARD_URL: dash.url, WEAVE_DASHBOARD_TIMEOUT_MS: '5000' }, encoding: 'utf8', cwd: ws,
    });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(dash.received.length, 1);
    assert.equal(dash.received[0].surface, 'cursor');
    assert.equal(dash.received[0].decision, 'deny');
    assert.equal(dash.received[0].subject, 'Read');
  } finally {
    dash.close();
  }
});

// Session limits: WARD.md's maxToolCalls holds across separate hook processes, per
// conversation_id, through Ward's ledger (Ward 0.3.6).
test('session limits hold across hook processes', async () => {
  const { spawnSync: run } = await import('node:child_process');
  const { mkdtempSync: tmp, writeFileSync: write, mkdirSync: mk } = await import('node:fs');
  const { tmpdir: td } = await import('node:os');
  const { join: j, resolve: r } = await import('node:path');
  const ws = tmp(j(td(), 'limits-ws-'));
  const home = tmp(j(td(), 'limits-home-'));
  mk(j(ws, '.'), { recursive: true });
  write(j(ws, '.', 'WARD.md'), `---\nward: "1.0"\nagent: limits-e2e\n---\n\n## Filesystem\n\nallow:\n  - read: ${ws}/**\ndefault: deny\n\n## Capabilities\n\ndefault: allow\n\n## Behavioral Limits\n\nmaxToolCalls: 2\n`);
  const env = { PATH: process.env.PATH, HOME: home, WEAVE_LEDGER_DIR: j(home, 'ledger') };
  const hook = (session) => {
    const out = run(process.execPath, [r('dist/cli.js'), 'hook'], { input: JSON.stringify({ hook_event_name: 'beforeReadFile', conversation_id: session, workspace_roots: [ws], file_path: j(ws, 'a.txt') }), env, encoding: 'utf8', cwd: ws });
    assert.equal(out.status, 0, out.stderr);
    return out.stdout;
  };
  assert.doesNotMatch(hook('one'), /Max tool calls/);
  assert.doesNotMatch(hook('one'), /Max tool calls/);
  assert.match(hook('one'), /Max tool calls/);
  assert.doesNotMatch(hook('two'), /Max tool calls/, 'another session has its own count');
});
