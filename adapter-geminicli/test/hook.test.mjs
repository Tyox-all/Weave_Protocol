// adapter-geminicli against Gemini CLI's documented hook contract
// (https://geminicli.com/docs/hooks/reference, /docs/reference/tools):
// stdin { cwd, tool_name, tool_input, ... }, stdout { decision, reason }.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { parseWard } from '@weave_protocol/ward';
import { evaluateCall, toHookOutput, normalizeInput } from '../dist/index.js';

const WARD = (ws) => `---
ward: "1.0"
agent: gemini-test
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
  - mcp_files_*
requireApproval:
  - web_search
default: deny
`;

const WS = '/workspace';
const policy = parseWard(WARD(WS));
const decide = (tool, input) => evaluateCall(policy, tool, input, WS).decision;

describe('built-in tools', () => {
  test('file tools use their documented argument names', () => {
    assert.equal(decide('read_file', { file_path: `${WS}/src/a.ts` }), 'allow');
    assert.equal(decide('read_file', { file_path: `${WS}/secrets/key` }), 'deny');
    assert.equal(decide('read_file', { file_path: `${WS}/out/../secrets/key` }), 'deny', 'traversal');
    assert.equal(decide('write_file', { file_path: `${WS}/out/a.md`, content: 'see /etc/passwd' }), 'allow');
    assert.equal(decide('replace', { file_path: `${WS}/src/a.ts`, old_string: 'a', new_string: 'b' }), 'deny', 'write outside out/');
    assert.equal(decide('list_directory', { dir_path: `${WS}/secrets` }), 'deny');
    assert.equal(decide('grep_search', { pattern: 'KEY', dir_path: `${WS}/secrets` }), 'deny');
    assert.equal(decide('glob', { pattern: '**/*.ts', dir_path: WS }), 'allow');
  });

  test('read_many_files checks every include entry', () => {
    assert.equal(decide('read_many_files', { include: [`${WS}/src/a.ts`, `${WS}/secrets/key`] }), 'deny');
    assert.equal(decide('read_many_files', { include: ['src/**/*.ts'] }), 'allow');
  });

  test('run_shell_command: every URL and path, resolved against dir_path', () => {
    assert.equal(decide('run_shell_command', { command: 'npm test' }), 'allow');
    assert.equal(decide('run_shell_command', { command: 'curl https://docs.example.com/a && curl https://evil.example/s' }), 'deny');
    assert.equal(decide('run_shell_command', { command: 'cat key', dir_path: `${WS}/secrets` }), 'deny', 'relative to dir_path');
    assert.equal(decide('run_shell_command', { command: 'cat secrets/key', dir_path: WS }), 'deny');
  });

  test("web_fetch: URLs inside the prompt are checked", () => {
    assert.deepEqual(normalizeInput('web_fetch', { prompt: 'Summarize https://docs.example.com/a, then https://evil.example/x.' }, WS).args.urls,
      ['https://docs.example.com/a', 'https://evil.example/x']);
    assert.equal(decide('web_fetch', { prompt: 'Summarize https://docs.example.com/guide' }), 'allow');
    assert.equal(decide('web_fetch', { prompt: 'Compare https://docs.example.com/a with https://evil.example/b' }), 'deny');
  });

  test('planning tools share one capability; unknown tools default to deny', () => {
    for (const t of ['ask_user', 'write_todos', 'enter_plan_mode', 'tracker_create_task']) assert.equal(decide(t, {}), 'allow', t);
    assert.equal(decide('google_web_search', { query: 'x' }), 'require_approval');
    assert.equal(decide('some_new_tool', {}), 'deny');
    assert.equal(decide('invoke_agent', {}), 'deny', 'subagent is its own capability');
  });

  test('MCP tools (mcp_<server>_<tool>) are gated by name and arguments', () => {
    assert.equal(decide('mcp_files_copy', { source: `${WS}/a`, destination: `${WS}/out/a` }), 'allow');
    assert.equal(decide('mcp_files_copy', { source: `${WS}/a`, destination: '/etc/cron.d/x' }), 'deny');
    assert.equal(decide('mcp_other_thing', {}), 'deny');
  });
});

test('output: deny and require_approval deny with a reason; allow prints nothing', () => {
  assert.deepEqual(toHookOutput({ decision: 'allow', reasons: [] }, 'W'), {});
  const deny = toHookOutput({ decision: 'deny', reasons: ['nope'] }, 'W');
  assert.equal(deny.decision, 'deny');
  assert.match(deny.reason, /nope/);
  assert.match(toHookOutput({ decision: 'require_approval', reasons: ['ask first'] }, 'W').reason, /requires approval/);
});

describe('CLI end to end (isolated HOME)', () => {
  const cli = resolve('dist/cli.js');
  const home = mkdtempSync(join(tmpdir(), 'gemini-home-'));
  const ws = mkdtempSync(join(tmpdir(), 'gemini-ws-'));
  writeFileSync(join(ws, 'WARD.md'), WARD(ws));
  const env = { PATH: process.env.PATH, HOME: home };
  const run = (args, input) => spawnSync(process.execPath, [cli, ...args], { input, env, encoding: 'utf8', cwd: ws });
  const hook = (payload) => {
    const r = run(['hook', 'before-tool'], JSON.stringify({ hook_event_name: 'BeforeTool', session_id: 's', cwd: ws, ...payload }));
    assert.equal(r.status, 0, r.stderr);
    return JSON.parse(r.stdout);
  };

  test('a denied call prints a deny decision; an allowed one prints {}', () => {
    const out = hook({ tool_name: 'read_file', tool_input: { file_path: join(ws, 'secrets', 'key') } });
    assert.equal(out.decision, 'deny');
    assert.match(out.reason, /secrets/);
    assert.deepEqual(hook({ tool_name: 'read_file', tool_input: { file_path: join(ws, 'src', 'a.ts') } }), {});
  });

  test('an invalid WARD.md denies; no WARD.md allows', () => {
    const broken = mkdtempSync(join(tmpdir(), 'gemini-ws-'));
    writeFileSync(join(broken, 'WARD.md'), '# not a policy');
    const out = hook({ cwd: broken, tool_name: 'read_file', tool_input: { file_path: join(broken, 'a') } });
    assert.equal(out.decision, 'deny');
    assert.match(out.reason, /could not be loaded/);
    const none = mkdtempSync(join(tmpdir(), 'gemini-ws-'));
    assert.deepEqual(hook({ cwd: none, tool_name: 'run_shell_command', tool_input: { command: 'ls' } }), {});
  });

  test('a malformed payload allows by default and denies with --fail-closed', () => {
    assert.equal(run(['hook', 'before-tool'], '{not json').stdout, '{}');
    assert.equal(JSON.parse(run(['hook', 'before-tool', '--fail-closed'], '{not json').stdout).decision, 'deny');
  });

  test('init and disable edit settings.json idempotently, keeping other hooks', () => {
    const settingsPath = join(home, '.gemini', 'settings.json');
    mkdirSync(join(home, '.gemini'), { recursive: true });
    writeFileSync(settingsPath, JSON.stringify({ theme: 'dark', hooks: { BeforeTool: [{ matcher: 'write_file', hooks: [{ type: 'command', name: 'mine', command: 'my-check' }] }] } }));

    assert.equal(run(['init']).status, 0);
    assert.equal(run(['init', '--fail-closed', '--timeout=3000']).status, 0);
    const s = JSON.parse(readFileSync(settingsPath, 'utf8'));
    assert.equal(s.theme, 'dark');
    assert.equal(s.hooks.BeforeTool.length, 2, 'one of ours, one of theirs');
    const ours = s.hooks.BeforeTool.find((e) => e.hooks[0].name === 'weave-ward');
    assert.deepEqual(ours.hooks[0], {
      type: 'command', name: 'weave-ward', command: 'weave-gemini hook before-tool --fail-closed', timeout: 3000,
      description: 'Weave Protocol: enforce WARD.md on every tool call',
    });
    assert.equal(ours.matcher, '.*');
    assert.ok(existsSync(`${settingsPath}.weave-backup`));

    assert.equal(run(['status']).status, 0);
    assert.equal(run(['disable']).status, 0);
    const after = JSON.parse(readFileSync(settingsPath, 'utf8'));
    assert.deepEqual(after.hooks.BeforeTool.map((e) => e.hooks[0].name), ['mine']);
  });

  test('test command dry-runs a call', () => {
    assert.equal(run(['test', 'read_file', `--input=${JSON.stringify({ file_path: join(ws, 'secrets', 'k') })}`]).status, 1);
    assert.equal(run(['test', 'read_file', `--input=${JSON.stringify({ file_path: join(ws, 'a') })}`]).status, 0);
  });
});
