// adapter-trae against TRAE's documented PreToolUse hook contract.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createServer } from 'node:http';
import { parseWard } from '@weave_protocol/ward';
import { evaluateCall, toHookOutput } from '../dist/index.js';

const SHELL = 'RunCommand';
const WARD = (ws) => `---
ward: "1.0"
agent: trae-test
---

## Filesystem

allow:
  - read: ${ws}/**
  - write: ${ws}/out/**
  - list: ${ws}/**
deny:
  - read: ${ws}/secrets/**
  - list: ${ws}/secrets/**
default: deny

## Network

allow:
  - url: "https://docs.example.com/**"
  - url: "https://api.openai.com/**"
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
  - task_planning
  - mcp__files__*
requireApproval:
  - web_search
default: deny
`;

const WS = '/workspace';
const policy = parseWard(WARD(WS));
const decide = (tool, input) => evaluateCall(policy, tool, input, WS).decision;

describe('built-in tools', () => {
  test('file tools', () => {
    assert.equal(decide('Read', { file_path: `${WS}/src/a.ts` }), 'allow');
    assert.equal(decide('Read', { file_path: `${WS}/secrets/key` }), 'deny');
    assert.equal(decide('Read', { file_path: `${WS}/out/../secrets/key` }), 'deny', 'traversal');
    assert.equal(decide('Write', { file_path: `${WS}/out/a.md`, content: 'x' }), 'allow');
    assert.equal(decide('Edit', { file_path: `${WS}/src/a.ts`, old_string: 'a', new_string: 'b' }), 'deny', 'write outside out/');
    assert.equal(decide('Grep', { pattern: 'KEY', path: `${WS}/secrets` }), 'deny');
    assert.equal(decide('Glob', { pattern: '**/*.ts', path: WS }), 'allow');
  });

  test('a path argument under another name is still checked', () => {
    assert.equal(decide('Read', { target_file: `${WS}/secrets/key` }), 'deny');
  });

  test(`${SHELL}: every URL and path in the command`, () => {
    assert.equal(decide(SHELL, { command: 'npm test' }), 'allow');
    assert.equal(decide(SHELL, { command: 'curl https://docs.example.com/a && curl https://evil.example/s' }), 'deny');
    assert.equal(decide(SHELL, { command: `cat ${WS}/secrets/key` }), 'deny');
  });

  test('WebFetch checks its url; WebSearch needs approval', () => {
    assert.equal(decide('WebFetch', { url: 'https://docs.example.com/guide', prompt: 'x' }), 'allow');
    assert.equal(decide('WebFetch', { url: 'https://evil.example/x', prompt: 'x' }), 'deny');
    assert.equal(decide('WebSearch', { query: 'x' }), 'require_approval');
  });

  test('unknown tools default to deny; MCP tools are gated by name and arguments', () => {
    assert.equal(decide('some_new_tool', {}), 'deny');
    assert.equal(decide('mcp__files__copy', { source: `${WS}/a`, destination: `${WS}/out/a` }), 'allow');
    assert.equal(decide('mcp__files__copy', { source: `${WS}/a`, destination: '/etc/cron.d/x' }), 'deny');
  });

  test('model_jurisdictions blocks a Chinese model endpoint the URL rules allow', () => {
    const p = parseWard(WARD(WS).replace('  - url: "https://api.openai.com/**"', '  - url: "https://api.openai.com/**"\n  - url: "https://**"').replace('default: deny\n\n## Capabilities', 'model_jurisdictions:\n  deny: [cn]\ndefault: deny\n\n## Capabilities'));
    assert.equal(evaluateCall(p, SHELL, { command: 'curl https://api.deepseek.com/v1/chat/completions' }, WS).decision, 'deny');
    assert.equal(evaluateCall(p, SHELL, { command: 'curl https://api.openai.com/v1/models' }, WS).decision, 'allow');
  });
});

test('output: deny → "deny", require_approval → "ask", allow prints nothing', () => {
  assert.deepEqual(toHookOutput({ decision: 'allow', reasons: [] }, 'W'), {});
  const deny = toHookOutput({ decision: 'deny', reasons: ['nope'] }, 'W').hookSpecificOutput;
  assert.equal(deny.hookEventName, 'PreToolUse');
  assert.equal(deny.permissionDecision, 'deny');
  assert.match(deny.permissionDecisionReason, /nope/);
  assert.equal(toHookOutput({ decision: 'require_approval', reasons: ['x'] }, 'W').hookSpecificOutput.permissionDecision, 'ask');
});

describe('CLI end to end (isolated HOME)', () => {
  const cli = resolve('dist/cli.js');
  const home = mkdtempSync(join(tmpdir(), 'trae-home-'));
  const ws = mkdtempSync(join(tmpdir(), 'trae-ws-'));
  writeFileSync(join(ws, 'WARD.md'), WARD(ws));
  const env = { PATH: process.env.PATH, HOME: home, WEAVE_LEDGER_DIR: join(home, 'ledger'), WEAVE_RECEIPTS: '0' };
  const run = (args, input, extra = {}) => spawnSync(process.execPath, [cli, ...args], { input, env: { ...env, ...extra }, encoding: 'utf8', cwd: ws });
  const hook = (payload, extra) => {
    const r = run(['hook', 'pre-tool-use'], JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 's', cwd: ws, ...payload }), extra);
    assert.equal(r.status, 0, 'the hook must never exit non-zero: TRAE would let the call through');
    return JSON.parse(r.stdout);
  };

  test('a denied call prints a deny decision; an allowed one prints {}', () => {
    const out = hook({ tool_name: 'Read', tool_input: { file_path: join(ws, 'secrets', 'key') } });
    assert.equal(out.hookSpecificOutput.permissionDecision, 'deny');
    assert.match(out.hookSpecificOutput.permissionDecisionReason, /secrets/);
    assert.deepEqual(hook({ tool_name: 'Read', tool_input: { file_path: join(ws, 'src', 'a.ts') } }), {});
  });

  test('with no cwd, the workspace comes from TRAE_PROJECT_DIR or workspace_roots', () => {
    const payload = { hook_event_name: 'PreToolUse', session_id: 's', tool_name: 'Read', tool_input: { file_path: join(ws, 'secrets', 'key') } };
    const viaEnv = spawnSync(process.execPath, [cli, 'hook', 'pre-tool-use'], { input: JSON.stringify(payload), env: { ...env, TRAE_PROJECT_DIR: ws }, encoding: 'utf8', cwd: tmpdir() });
    assert.equal(JSON.parse(viaEnv.stdout).hookSpecificOutput.permissionDecision, 'deny');
    const viaRoots = spawnSync(process.execPath, [cli, 'hook', 'pre-tool-use'], { input: JSON.stringify({ ...payload, workspace_roots: [ws] }), env, encoding: 'utf8', cwd: tmpdir() });
    assert.equal(JSON.parse(viaRoots.stdout).hookSpecificOutput.permissionDecision, 'deny');
  });

  test('an invalid or unreadable WARD.md denies; no WARD.md allows', () => {
    const broken = mkdtempSync(join(tmpdir(), 'trae-ws-'));
    writeFileSync(join(broken, 'WARD.md'), '# not a policy');
    const out = hook({ cwd: broken, tool_name: 'Read', tool_input: { file_path: join(broken, 'a') } });
    assert.equal(out.hookSpecificOutput.permissionDecision, 'deny');
    assert.match(out.hookSpecificOutput.permissionDecisionReason, /could not be loaded/);
    assert.equal(hook({ tool_name: 'Read', tool_input: { file_path: join(ws, 'a') } }, { WEAVE_WARD_PATH: ws }).hookSpecificOutput.permissionDecision, 'deny');
    const none = mkdtempSync(join(tmpdir(), 'trae-ws-'));
    assert.deepEqual(hook({ cwd: none, tool_name: SHELL, tool_input: { command: 'ls' } }), {});
  });

  test('a malformed payload allows by default and denies with --fail-closed, always exiting 0', () => {
    const open = run(['hook', 'pre-tool-use'], '{not json');
    assert.equal(open.status, 0);
    assert.equal(open.stdout, '{}');
    const closed = run(['hook', 'pre-tool-use', '--fail-closed'], '{not json');
    assert.equal(closed.status, 0);
    assert.equal(JSON.parse(closed.stdout).hookSpecificOutput.permissionDecision, 'deny');
  });

  test('init and disable edit hooks.json idempotently, keeping other settings and hooks', () => {
    const path = join(home, '.trae', 'hooks.json');
    mkdirSync(join(home, '.trae'), { recursive: true });
    writeFileSync(path, JSON.stringify({ theme: 'dark', hooks: { PreToolUse: [{ matcher: 'Write', hooks: [{ command: 'my-check' }] }] } }));
    assert.equal(run(['init']).status, 0);
    assert.equal(run(['init', '--fail-closed', '--timeout=15']).status, 0);
    const s = JSON.parse(readFileSync(path, 'utf8'));
    assert.equal(s.theme, 'dark');
    assert.equal(s.hooks.PreToolUse.length, 2, 'one of ours, one of theirs');
    const ours = s.hooks.PreToolUse.find((e) => e.hooks[0].command.includes('weave-trae'));
    assert.deepEqual(ours.hooks[0], { command: 'weave-trae hook pre-tool-use --fail-closed', timeout: 15 });
    assert.equal(ours.matcher, '.*');
    assert.ok(existsSync(`${path}.weave-backup`));
    assert.equal(s.version, 1, 'hooks.json keeps its version field');
    assert.equal(run(['status']).status, 0);
    assert.equal(run(['disable']).status, 0);
    assert.deepEqual(JSON.parse(readFileSync(path, 'utf8')).hooks.PreToolUse.map((e) => e.hooks[0].command), ['my-check']);
  });

  test("init also installs into TRAE's China build (~/.trae-cn) when it exists", () => {
    const cnHome = mkdtempSync(join(tmpdir(), 'trae-cn-home-'));
    mkdirSync(join(cnHome, '.trae-cn'), { recursive: true });
    const r = run(['init'], undefined, { HOME: cnHome });
    assert.equal(r.status, 0);
    for (const dir of ['.trae', '.trae-cn']) {
      const s = JSON.parse(readFileSync(join(cnHome, dir, 'hooks.json'), 'utf8'));
      assert.ok(s.hooks.PreToolUse.some((e) => e.hooks[0].command.includes('weave-trae')), dir);
    }
    assert.equal(run(['disable'], undefined, { HOME: cnHome }).status, 0);
    assert.equal(JSON.parse(readFileSync(join(cnHome, '.trae-cn', 'hooks.json'), 'utf8')).hooks.PreToolUse, undefined);
  });

  test('session limits hold across hook processes, per session_id', () => {
    const lws = mkdtempSync(join(tmpdir(), 'trae-limits-'));
    writeFileSync(join(lws, 'WARD.md'), `---\nward: "1.0"\nagent: trae-limits\n---\n\n## Filesystem\n\nallow:\n  - read: ${lws}/**\ndefault: deny\n\n## Capabilities\n\ndefault: allow\n\n## Behavioral Limits\n\nmaxToolCalls: 2\n`);
    const call = (session) => JSON.stringify(hook({ cwd: lws, session_id: session, tool_name: 'Read', tool_input: { file_path: join(lws, 'a.txt') } }));
    assert.doesNotMatch(call('one'), /Max tool calls/);
    assert.doesNotMatch(call('one'), /Max tool calls/);
    assert.match(call('one'), /Max tool calls/);
    assert.doesNotMatch(call('two'), /Max tool calls/, 'another session has its own count');
  });
});

test('reports the decision to the dashboard as trae when WEAVE_DASHBOARD_URL is set', async () => {
  const received = [];
  const server = createServer((req, res) => { let raw = ''; req.on('data', (c) => (raw += c)); req.on('end', () => { received.push(JSON.parse(raw)); res.writeHead(201); res.end('{}'); }); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    const home = mkdtempSync(join(tmpdir(), 'trae-report-'));
    const ws = mkdtempSync(join(tmpdir(), 'trae-report-ws-'));
    writeFileSync(join(ws, 'WARD.md'), WARD(ws));
    const r = await new Promise((done) => {
      const child = spawn(process.execPath, [resolve('dist/cli.js'), 'hook', 'pre-tool-use'], {
        env: { PATH: process.env.PATH, HOME: home, WEAVE_DASHBOARD_URL: `http://127.0.0.1:${server.address().port}`, WEAVE_DASHBOARD_TIMEOUT_MS: '5000' }, cwd: ws,
      });
      let stdout = '';
      child.stdout.on('data', (d) => (stdout += d));
      child.on('close', (status) => done({ status, stdout }));
      child.stdin.end(JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 's', cwd: ws, tool_name: 'Read', tool_input: { file_path: join(ws, 'secrets', 'k') } }));
    });
    assert.equal(r.status, 0);
    assert.equal(received.length, 1);
    assert.equal(received[0].surface, 'trae');
    assert.equal(received[0].decision, 'deny');
  } finally {
    server.close();
  }
});
