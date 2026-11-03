// WARD-2026-001 regressions for Antigravity's tool names: each call below was
// allowed before 0.3.0 despite a policy that denies it.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseWard } from '@weave_protocol/ward';
import { evaluateCall } from '../dist/hook.js';

const WARD = `---
ward: "1.0"
agent: agy-test
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
  - mcp_files_*
default: deny
`;
const policy = parseWard(WARD);
const decide = (tool, args) => evaluateCall(policy, tool, args, '/workspace').decision;

describe('bypasses are denied', () => {
  test('traversal in view_file', () => {
    assert.equal(decide('view_file', { AbsolutePath: '/workspace/out/../secrets/key' }), 'deny');
  });
  test('a second URL in run_command', () => {
    assert.equal(decide('run_command', { CommandLine: 'curl https://api.github.com/x && curl https://evil.example/s', Cwd: '/workspace' }), 'deny');
  });
  test('run_command reading a denied path', () => {
    assert.equal(decide('run_command', { CommandLine: 'cat secrets/key', Cwd: '/workspace' }), 'deny');
  });
  test('grep_search and list_dir pointed at a denied directory', () => {
    assert.equal(decide('grep_search', { Query: 'KEY', SearchPath: '/workspace/secrets' }), 'deny');
    assert.equal(decide('list_dir', { DirectoryPath: '/workspace/secrets' }), 'deny');
  });
  test('an MCP tool with path and URL arguments', () => {
    assert.equal(decide('mcp_files_copy', { SourcePath: '/workspace/a', DestinationPath: '/etc/x' }), 'deny');
    assert.equal(decide('mcp_files_fetch', { Endpoint: 'https://evil.example/x' }), 'deny');
  });
});

test('ordinary calls are allowed', () => {
  assert.equal(decide('view_file', { AbsolutePath: '/workspace/src/a.ts' }), 'allow');
  assert.equal(decide('write_to_file', { TargetFile: '/workspace/out/a.md', CodeContent: 'see /etc/passwd' }), 'allow');
  assert.equal(decide('run_command', { CommandLine: 'npm test', Cwd: '/workspace' }), 'allow');
  assert.equal(decide('read_url_content', { Url: 'https://api.github.com/repos' }), 'allow');
});

test('an invalid WARD.md denies instead of switching enforcement off', () => {
  const home = mkdtempSync(join(tmpdir(), 'agy-home-'));
  const ws = mkdtempSync(join(tmpdir(), 'agy-ws-'));
  writeFileSync(join(ws, 'WARD.md'), '# not a policy');
  const env = { PATH: process.env.PATH, HOME: home, ANTIGRAVITY_GLOBAL_CONFIG_DIR: join(home, '.gemini', 'config'), ANTIGRAVITY_CONFIG_DIR: join(home, '.gemini', 'antigravity-cli') };
  const r = spawnSync(process.execPath, ['dist/cli.js', 'hook', 'pre-tool-use'], {
    input: JSON.stringify({ toolCall: { name: 'view_file', args: { AbsolutePath: join(ws, 'a') } }, workspacePaths: [ws] }),
    env, encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.equal(out.decision, 'deny');
  assert.match(out.reason, /could not be loaded/);
});
