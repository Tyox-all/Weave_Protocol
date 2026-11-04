// adapter-opencode against OpenCode's plugin contract (opencode.ai/docs/plugins,
// and the v1 plugin loader and tool schemas in anomalyco/opencode v1.19.5):
// default export { id, server }, tool.execute.before(input, output) throws to block.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { parseWard } from '@weave_protocol/ward';
import plugin from '../dist/index.js';
import * as entry from '../dist/index.js';
import { evaluateCall, patchTargets } from '../dist/lib.js';

const WARD = (ws) => `---
ward: "1.0"
agent: opencode-test
---

## Filesystem

allow:
  - read: ${ws}/**
  - list: ${ws}/**
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
  - file_list
  - http_request
  - task_planning
  - files_*
default: deny
`;

const WS = '/workspace';
const policy = parseWard(WARD(WS));
const decide = (tool, args) => evaluateCall(policy, tool, args, WS).decision;

describe('plugin shape (OpenCode v1 loader)', () => {
  test('the main entry default-exports only { id, server }', () => {
    assert.deepEqual(Object.keys(entry), ['default']);
    assert.equal(plugin.id, 'weave-ward');
    assert.equal(typeof plugin.server, 'function');
    assert.equal('tui' in plugin, false);
  });
});

describe('decisions with OpenCode 1.19 tool arguments', () => {
  test('read / write / edit use filePath', () => {
    assert.equal(decide('read', { filePath: `${WS}/src/a.ts` }), 'allow');
    assert.equal(decide('read', { filePath: `${WS}/secrets/key` }), 'deny');
    assert.equal(decide('read', { filePath: 'secrets/key' }), 'deny', 'relative to the project');
    assert.equal(decide('write', { filePath: `${WS}/src/b.ts`, content: 'see /etc/passwd' }), 'allow');
    assert.equal(decide('edit', { filePath: `${WS}/README.md`, oldString: 'a', newString: 'b' }), 'deny', 'outside src/');
  });

  test('bash checks every URL and path, relative to workdir', () => {
    assert.equal(decide('bash', { command: 'npm test' }), 'allow');
    assert.equal(decide('bash', { command: 'curl https://docs.example.com/a && curl https://evil.example/s' }), 'deny');
    assert.equal(decide('bash', { command: 'cat key', workdir: `${WS}/secrets` }), 'deny');
  });

  test('glob, grep and webfetch', () => {
    assert.equal(decide('grep', { pattern: 'KEY', path: `${WS}/secrets` }), 'deny');
    assert.equal(decide('glob', { pattern: '**/*.ts', path: `${WS}/src` }), 'allow');
    assert.equal(decide('webfetch', { url: 'https://docs.example.com/guide', format: 'markdown' }), 'allow');
    assert.equal(decide('webfetch', { url: 'https://evil.example/x' }), 'deny');
  });

  test('apply_patch is decided on the files in its patchText', () => {
    const p = (...l) => ['*** Begin Patch', ...l, '*** End Patch'].join('\n');
    assert.deepEqual(patchTargets(p('*** Add File: src/n.ts', '*** Delete File: src/o.ts')), { writes: ['src/n.ts'], deletes: ['src/o.ts'] });
    assert.equal(decide('apply_patch', { patchText: p('*** Update File: src/a.ts', '@@', '-a', '+b') }), 'allow');
    assert.equal(decide('apply_patch', { patchText: p('*** Add File: secrets/new', '+x') }), 'deny');
    assert.equal(decide('apply_patch', { patchText: p('*** Update File: src/a.ts', '+// /workspace/secrets/key') }), 'allow', 'content is not a target');
  });

  test('planning tools, MCP tools (<server>_<tool>) and unknown tools', () => {
    assert.equal(decide('todowrite', { todos: [] }), 'allow');
    assert.equal(decide('files_copy', { source: `${WS}/src/a`, destination: '/etc/x' }), 'deny');
    assert.equal(decide('task', { prompt: 'x', description: 'y' }), 'deny', 'subagent not allowed');
  });
});

describe('the tool.execute.before hook', () => {
  const ws = mkdtempSync(join(tmpdir(), 'opencode-ws-'));
  writeFileSync(join(ws, 'WARD.md'), WARD(ws));

  test('throws with the WARD reason on a denied call, and passes allowed ones', async () => {
    const hooks = await plugin.server({ directory: ws });
    await assert.rejects(hooks['tool.execute.before']({ tool: 'read', sessionID: 's', callID: 'c' }, { args: { filePath: join(ws, 'secrets', 'k') } }), /WARD: Denied by filesystem rule/);
    await hooks['tool.execute.before']({ tool: 'read' }, { args: { filePath: join(ws, 'src', 'a.ts') } });
  });

  test('picks up WARD.md edits without a restart', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'opencode-ws-'));
    const hooks = await plugin.server({ directory: dir });
    await hooks['tool.execute.before']({ tool: 'bash' }, { args: { command: 'ls' } });
    writeFileSync(join(dir, 'WARD.md'), WARD(dir).replace('  - shell_exec\n', ''));
    await assert.rejects(hooks['tool.execute.before']({ tool: 'bash' }, { args: { command: 'ls' } }), /WARD/);
  });

  test('an invalid WARD.md blocks every call', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'opencode-ws-'));
    writeFileSync(join(dir, 'WARD.md'), '# not a policy');
    const hooks = await plugin.server({ directory: dir });
    await assert.rejects(hooks['tool.execute.before']({ tool: 'read' }, { args: { filePath: join(dir, 'a') } }), /could not be loaded/);
  });
});

describe('CLI (isolated XDG_CONFIG_HOME)', () => {
  const cli = resolve('dist/cli.js');
  const xdg = mkdtempSync(join(tmpdir(), 'opencode-xdg-'));
  const env = { PATH: process.env.PATH, HOME: xdg, XDG_CONFIG_HOME: xdg };
  const run = (args, cwd = xdg) => spawnSync(process.execPath, [cli, ...args], { env, encoding: 'utf8', cwd });
  const cfgPath = join(xdg, 'opencode', 'opencode.json');

  test('init and disable edit opencode.json idempotently, keeping other plugins', () => {
    mkdirSync(join(xdg, 'opencode'), { recursive: true });
    writeFileSync(cfgPath, JSON.stringify({ model: 'x/y', plugin: ['opencode-wakatime', ['@weave_protocol/adapter-opencode@0.0.1', {}]] }));
    assert.equal(run(['init']).status, 0);
    assert.equal(run(['init']).status, 0);
    const cfg = JSON.parse(readFileSync(cfgPath, 'utf8'));
    assert.equal(cfg.model, 'x/y');
    assert.deepEqual(cfg.plugin, ['opencode-wakatime', '@weave_protocol/adapter-opencode']);
    assert.ok(existsSync(`${cfgPath}.weave-backup`));
    assert.equal(run(['disable']).status, 0);
    assert.deepEqual(JSON.parse(readFileSync(cfgPath, 'utf8')).plugin, ['opencode-wakatime']);
  });

  test('an opencode.jsonc is never rewritten', () => {
    const x = mkdtempSync(join(tmpdir(), 'opencode-xdg-'));
    mkdirSync(join(x, 'opencode'));
    writeFileSync(join(x, 'opencode', 'opencode.jsonc'), '// mine\n{}');
    const r = spawnSync(process.execPath, [cli, 'init'], { env: { ...env, XDG_CONFIG_HOME: x }, encoding: 'utf8' });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /by hand/);
    assert.equal(readFileSync(join(x, 'opencode', 'opencode.jsonc'), 'utf8'), '// mine\n{}');
  });

  test('test command dry-runs a call', () => {
    const ws = mkdtempSync(join(tmpdir(), 'opencode-ws-'));
    writeFileSync(join(ws, 'WARD.md'), WARD(ws));
    assert.equal(run(['test', 'read', `--input=${JSON.stringify({ filePath: join(ws, 'secrets', 'k') })}`], ws).status, 1);
    assert.equal(run(['test', 'read', `--input=${JSON.stringify({ filePath: join(ws, 'src', 'a') })}`], ws).status, 0);
  });
});

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
  const prev = process.env.WEAVE_DASHBOARD_URL;
  process.env.WEAVE_DASHBOARD_URL = dash.url;
  // A cold first request on a slow CI runner can exceed the 250ms default
  process.env.WEAVE_DASHBOARD_TIMEOUT_MS = '5000';
  try {
    const ws = mkdtempSync(join(tmpdir(), 'report-ws-'));
    writeFileSync(join(ws, 'WARD.md'), WARD(ws));
    const hooks = await plugin.server({ directory: ws });
    await assert.rejects(hooks['tool.execute.before']({ tool: 'read' }, { args: { filePath: join(ws, 'secrets', 'k') } }));
    for (let i = 0; i < 500 && dash.received.length === 0; i++) await new Promise((r) => setTimeout(r, 10));
    assert.equal(dash.received[0]?.surface, 'opencode');
    assert.equal(dash.received[0].decision, 'deny');
    assert.equal(dash.received[0].subject, 'read');
  } finally {
    if (prev === undefined) delete process.env.WEAVE_DASHBOARD_URL; else process.env.WEAVE_DASHBOARD_URL = prev;
    delete process.env.WEAVE_DASHBOARD_TIMEOUT_MS;
    dash.close();
  }
});
