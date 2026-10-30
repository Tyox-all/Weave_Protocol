// WARD hook for Antigravity, against the documented hook contract
// (https://antigravity.google/docs/hooks): payload { toolCall: { name, args },
// workspacePaths }, output { decision: "deny" | "ask", reason }, hooks in
// ~/.gemini/config/hooks.json as a named hook.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseWard } from '@weave_protocol/ward';
import { evaluateCall, parsePayload, toHookOutput } from '../dist/hook.js';

const ws = mkdtempSync(join(tmpdir(), 'agy-ward-ws-'));
const WARD = `---
ward: "1.0"
agent: test-agent
---

# WARD.md

## Filesystem

allow:
  - read: ${ws}/**
  - write: ${ws}/**
deny:
  - read: ~/.ssh/**
  - write: /etc/**
default: deny

## Network

allow:
  - url: "https://api.github.com/**"
default: deny

## Capabilities

allow:
  - file_read
  - file_write
  - file_list
requireApproval:
  - shell_exec
  - http_request
deny:
  - generate_image
default: deny
`;
writeFileSync(join(ws, 'WARD.md'), WARD);
const policy = parseWard(WARD);
const call = (name, args) => evaluateCall(policy, name, args).decision;

describe('payload parsing', () => {
  test('reads the documented camelCase payload', () => {
    assert.deepEqual(parsePayload({ toolCall: { name: 'view_file', args: { AbsolutePath: '/x' } }, workspacePaths: ['/w', '/w2'] }),
      { tool: 'view_file', args: { AbsolutePath: '/x' }, cwd: '/w' });
  });
  test('still accepts the legacy snake_case fields', () => {
    assert.deepEqual(parsePayload({ tool_name: 'view_file', tool_input: { a: 1 }, cwd: '/c' }), { tool: 'view_file', args: { a: 1 }, cwd: '/c' });
  });
});

describe('WARD decisions for Antigravity tool names', () => {
  test('filesystem rules apply to each tool\'s own path argument', () => {
    assert.equal(call('view_file', { AbsolutePath: join(ws, 'README.md') }), 'allow');
    assert.equal(call('view_file', { AbsolutePath: '~/.ssh/id_ed25519' }), 'deny');
    assert.equal(call('write_to_file', { TargetFile: join(ws, 'a.txt'), CodeContent: 'x' }), 'allow');
    assert.equal(call('write_to_file', { TargetFile: '/etc/hosts', CodeContent: 'x' }), 'deny');
    assert.equal(call('replace_file_content', { TargetFile: '/etc/hosts' }), 'deny');
    assert.equal(call('multi_replace_file_content', { TargetFile: '/etc/hosts' }), 'deny');
    assert.equal(call('list_dir', { DirectoryPath: ws }), 'deny', 'no list rule in this policy → default deny');
    assert.equal(call('grep_search', { SearchPath: '~/.ssh/config', Query: 'Host' }), 'deny');
  });

  test('run_command: shell needs approval, and the command line is scanned', () => {
    assert.equal(call('run_command', { CommandLine: 'ls', Cwd: ws }), 'require_approval');
    assert.equal(call('run_command', { CommandLine: 'cat ~/.ssh/id_ed25519', Cwd: ws }), 'deny', 'touches a denied path');
  });

  test('read_url_content: network rules apply to Url', () => {
    assert.equal(call('read_url_content', { Url: 'https://evil.example.com/x' }), 'deny');
    assert.equal(call('read_url_content', { Url: 'https://api.github.com/repos' }), 'require_approval');
  });

  test('denied capability by raw tool name', () => {
    assert.equal(call('generate_image', { Prompt: 'x' }), 'deny');
  });

  test('outputs use Antigravity decision values: deny and ask', () => {
    assert.equal(toHookOutput({ decision: 'deny', reasons: ['r'] }, 'W').decision, 'deny');
    assert.equal(toHookOutput({ decision: 'require_approval', reasons: ['r'] }, 'W').decision, 'ask');
    assert.equal(toHookOutput({ decision: 'allow', reasons: [] }, 'W'), undefined);
  });
});

describe('end to end', () => {
  const home = mkdtempSync(join(tmpdir(), 'agy-ward-home-'));
  const env = { ...process.env, HOME: home, ANTIGRAVITY_GLOBAL_CONFIG_DIR: join(home, '.gemini', 'config'), ANTIGRAVITY_CONFIG_DIR: join(home, '.gemini', 'antigravity-cli') };
  const hook = (payload) => {
    const r = spawnSync(process.execPath, ['dist/cli.js', 'hook', 'pre-tool-use'], { input: JSON.stringify(payload), env, encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    return r.stdout ? JSON.parse(r.stdout) : null;
  };

  test('the hook command answers documented payloads with documented decisions', () => {
    assert.equal(hook({ toolCall: { name: 'write_to_file', args: { TargetFile: '/etc/hosts', CodeContent: 'x' } }, workspacePaths: [ws] }).decision, 'deny');
    assert.equal(hook({ toolCall: { name: 'run_command', args: { CommandLine: 'ls', Cwd: ws } }, workspacePaths: [ws] }).decision, 'ask');
    assert.equal(hook({ toolCall: { name: 'view_file', args: { AbsolutePath: join(ws, 'WARD.md') } }, workspacePaths: [ws] }), null, 'allowed: no output');
  });

  test('init writes a named hook to hooks.json and migrates the old settings.json entry', () => {
    const legacy = join(home, '.gemini', 'antigravity-cli', 'settings.json');
    mkdirSync(join(home, '.gemini', 'antigravity-cli'), { recursive: true });
    writeFileSync(legacy, JSON.stringify({ hooks: { PreToolUse: [
      { matcher: '*', hooks: [{ type: 'command', command: 'weave-antigravity hook pre-tool-use # WEAVE_WARD_HOOK' }] },
      { matcher: 'x', hooks: [{ type: 'command', command: 'mine' }] },
    ] } }));
    const hooksPath = join(home, '.gemini', 'config', 'hooks.json');
    mkdirSync(join(home, '.gemini', 'config'), { recursive: true });
    writeFileSync(hooksPath, JSON.stringify({ 'weave-mund': { enabled: true }, other: { enabled: true } }));

    const run = (args) => spawnSync(process.execPath, ['dist/cli.js', ...args], { env, encoding: 'utf8' });
    const init = run(['init']);
    assert.equal(init.status, 0, init.stderr);
    assert.match(init.stderr, /Migrated/);
    const cfg = JSON.parse(readFileSync(hooksPath, 'utf8'));
    assert.deepEqual(Object.keys(cfg).sort(), ['other', 'weave-mund', 'weave-ward']);
    assert.deepEqual(cfg['weave-ward'].PreToolUse[0], { matcher: '*', hooks: [{ type: 'command', command: 'weave-antigravity hook pre-tool-use', timeout: 5 }] });
    assert.deepEqual(JSON.parse(readFileSync(legacy, 'utf8')).hooks.PreToolUse.map((e) => e.matcher), ['x'], 'legacy WARD entry removed, user entry kept');
    assert.ok(existsSync(`${hooksPath}.weave-backup`));

    assert.equal(run(['disable']).status, 0);
    assert.deepEqual(Object.keys(JSON.parse(readFileSync(hooksPath, 'utf8'))).sort(), ['other', 'weave-mund']);

    const wsInit = run(['init', `--workspace=${ws}`]);
    assert.equal(wsInit.status, 0);
    assert.ok('weave-ward' in JSON.parse(readFileSync(join(ws, '.agents', 'hooks.json'), 'utf8')));
    rmSync(home, { recursive: true, force: true });
    rmSync(ws, { recursive: true, force: true });
  });
});
