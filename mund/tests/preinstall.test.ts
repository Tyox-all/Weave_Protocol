/**
 * Pre-install checks (agent-audit). Every fixture under
 * tests/fixtures/preinstall is a published detection claim: the verdict in
 * its expected file is what Mund must return.
 */
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  auditCachePath, checkMcpServerConfig, discoverAntigravityMcpServers, discoverMcpServers, discoverSkillDirs, launchedPackage, runAgentAudit, scanSkillDir, verdictFor,
} from '../src/agent-audit.js';
import { BaselineStore } from '../src/rugpull.js';

const FX = join(__dirname, 'fixtures', 'preinstall');
const FAKE_SERVER = join(FX, 'fake-mcp-server.mjs');

describe('skill fixtures (detection claims)', () => {
  for (const name of readdirSync(join(FX, 'skills'))) {
    const expected = JSON.parse(readFileSync(join(FX, 'skills', name, 'expected.json'), 'utf8'));
    it(`${name} → ${expected.verdict}`, async () => {
      const audit = await scanSkillDir(join(FX, 'skills', name));
      expect(audit.verdict).toBe(expected.verdict);
      if (expected.rule) expect(audit.issues.map((i) => i.rule_id)).toContain(expected.rule);
    });
  }
});

describe('MCP config fixtures (detection claims)', () => {
  for (const file of readdirSync(join(FX, 'mcp-config'))) {
    const fx = JSON.parse(readFileSync(join(FX, 'mcp-config', file), 'utf8'));
    it(`${file.replace('.json', '')} → ${fx.expected.verdict}`, async () => {
      const issues = await checkMcpServerConfig('fixture', fx.config);
      expect(verdictFor(issues)).toBe(fx.expected.verdict);
      if (fx.expected.rule) expect(issues.map((i) => i.rule_id)).toContain(fx.expected.rule);
    });
  }
});

describe('launchedPackage', () => {
  it.each([
    [{ command: 'npx', args: ['-y', '@scope/pkg@1.2.3', '--flag'] }, { name: '@scope/pkg', version: '1.2.3' }],
    [{ command: '/usr/local/bin/npx', args: ['pkg'] }, { name: 'pkg' }],
    [{ command: 'pnpm', args: ['dlx', 'pkg@2'] }, { name: 'pkg', version: '2' }],
    [{ command: 'uvx', args: ['mcp-server-git'] }, { name: 'mcp-server-git' }],
    [{ command: 'node', args: ['server.js'] }, null],
  ])('%j', (config, expected) => expect(launchedPackage(config)).toEqual(expected));
});

describe('discovery and live checks', () => {
  let home: string;
  let project: string;
  let store: BaselineStore;
  const writeJson = (p: string, v: unknown) => { mkdirSync(join(p, '..'), { recursive: true }); writeFileSync(p, JSON.stringify(v)); };
  const fake = (env: Record<string, string> = {}) => ({ command: process.execPath, args: [FAKE_SERVER], env });

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'mund-home-'));
    project = mkdtempSync(join(tmpdir(), 'mund-proj-'));
    store = new BaselineStore(join(home, 'baselines.json'));
    process.env.MUND_AUDIT_CACHE_DIR = join(home, 'cache');
  });
  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    rmSync(project, { recursive: true, force: true });
    delete process.env.MUND_AUDIT_CACHE_DIR;
  });

  it('finds project, local, user and Claude Desktop servers plus skills', () => {
    writeJson(join(project, '.mcp.json'), { mcpServers: { proj: fake() } });
    writeJson(join(home, '.claude.json'), { mcpServers: { usr: fake() }, projects: { [project]: { mcpServers: { loc: fake() } } } });
    mkdirSync(join(project, '.claude', 'skills', 'fmt'), { recursive: true });
    writeFileSync(join(project, '.claude', 'skills', 'fmt', 'SKILL.md'), 'Formats tables.');
    const servers = discoverMcpServers(project, home);
    expect(servers.map((s) => [s.name, s.scope, s.approved])).toEqual([
      ['proj', 'project', false], ['loc', 'local', true], ['usr', 'user', true],
    ]);
  });

  it('never starts an unapproved project server, but checks it statically', async () => {
    writeJson(join(project, '.mcp.json'), { mcpServers: { proj: fake() } });
    const r = await runAgentAudit({ cwd: project, home, live: true, store });
    expect(r.servers[0].live).toMatchObject({ status: 'skipped' });
    expect(r.servers[0].live.reason).toMatch(/not approved/);
  });

  it('live-checks a project server once it is approved, and writes the verdict cache', async () => {
    writeJson(join(project, '.mcp.json'), { mcpServers: { proj: fake() } });
    writeJson(join(home, '.claude.json'), { projects: { [project]: { enabledMcpjsonServers: ['proj'] } } });
    const r = await runAgentAudit({ cwd: project, home, live: true, store });
    expect(r.servers[0]).toMatchObject({ verdict: 'allow', live: { status: 'ok', tools: 1, rugpull: 'baseline_created' } });
    expect(JSON.parse(readFileSync(auditCachePath(project), 'utf8')).servers[0].name).toBe('proj');
  });

  it('detects a rug pull: changed description warns until accepted', async () => {
    writeJson(join(home, '.claude.json'), { mcpServers: { notes: fake() } });
    await runAgentAudit({ cwd: project, home, live: true, store });
    writeJson(join(home, '.claude.json'), { mcpServers: { notes: fake({ TOOL_DESC: 'Read a saved note by title, newest first.' }) } });
    const changed = await runAgentAudit({ cwd: project, home, live: true, store });
    expect(changed.servers[0]).toMatchObject({ verdict: 'warn', live: { rugpull: 'changed' } });
    await runAgentAudit({ cwd: project, home, live: true, store, accept: ['notes'] });
    expect((await runAgentAudit({ cwd: project, home, live: true, store })).servers[0]).toMatchObject({ verdict: 'allow', live: { rugpull: 'unchanged' } });
  });

  it('blocks a rug pull that adds command execution', async () => {
    writeJson(join(home, '.claude.json'), { mcpServers: { notes: fake() } });
    await runAgentAudit({ cwd: project, home, live: true, store });
    writeJson(join(home, '.claude.json'), { mcpServers: { notes: fake({ EXTRA_TOOL: 'run', EXTRA_DESC: 'Run a shell command on the host.' }) } });
    const r = await runAgentAudit({ cwd: project, home, live: true, store });
    expect(r.servers[0].verdict).toBe('block');
    expect(r.servers[0].issues.some((i) => i.rule_id === 'mcp_rugpull_tool_added' && i.severity === 'critical')).toBe(true);
  });

  it('never starts a server whose package or URL is already distrusted', async () => {
    // The launcher path doesn't exist, so even a regression couldn't run anything.
    writeJson(join(home, '.claude.json'), { mcpServers: { squat: { command: join(home, 'no-such-dir', 'npx'), args: ['-y', '@modelcontextprotcol/server-filesystem@1.0.0'] } } });
    const r = await runAgentAudit({ cwd: project, home, live: true, store });
    expect(r.servers[0].verdict).toBe('block');
    expect(r.servers[0].live).toMatchObject({ status: 'skipped' });
    expect(r.servers[0].live.reason).toMatch(/not started/);
  });

  it('Antigravity layout: workspace servers static-only, global servers live, disabled never started', async () => {
    writeJson(join(project, '.agents', 'mcp_config.json'), { mcpServers: { ws: fake() } });
    writeJson(join(home, '.gemini', 'config', 'mcp_config.json'), { mcpServers: {
      glob: fake(), off: { ...fake(), disabled: true }, remote: { serverUrl: 'http://mcp.example.com/mcp' },
    } });
    mkdirSync(join(project, '.agents', 'skills', 'fmt'), { recursive: true });
    writeFileSync(join(project, '.agents', 'skills', 'fmt', 'SKILL.md'), 'Formats tables.');
    mkdirSync(join(home, '.gemini', 'antigravity-cli', 'plugins', 'p1', 'skills', 'ps'), { recursive: true });
    writeFileSync(join(home, '.gemini', 'antigravity-cli', 'plugins', 'p1', 'skills', 'ps', 'SKILL.md'), 'Plugin skill.');

    expect(discoverAntigravityMcpServers(project, home).map((s) => [s.name, s.scope, s.approved])).toEqual([
      ['ws', 'workspace', false], ['glob', 'global', true], ['off', 'global', false], ['remote', 'global', true],
    ]);
    expect(discoverSkillDirs(project, home, 'antigravity').map((d) => d.scope)).toEqual(['workspace', 'plugin']);

    const r = await runAgentAudit({ cwd: project, home, live: true, store, harness: 'antigravity', timeoutMs: 4000 });
    const by = Object.fromEntries(r.servers.map((s) => [s.name, s]));
    expect(by.ws.live.status).toBe('skipped');
    expect(by.glob.live).toMatchObject({ status: 'ok', tools: 1 });
    expect(by.off.live.reason).toMatch(/disabled/);
    expect(by.remote.issues.map((i) => i.rule_id)).toContain('mcp_insecure_transport');
    expect(readFileSync(auditCachePath(project, 'antigravity'), 'utf8')).toContain('"glob"');
    expect(auditCachePath(project, 'antigravity')).not.toBe(auditCachePath(project));
  });

  it('reports a server that fails to start without crashing the audit', async () => {
    writeJson(join(home, '.claude.json'), { mcpServers: { broken: { command: join(home, 'does-not-exist') } } });
    const r = await runAgentAudit({ cwd: project, home, live: true, store, timeoutMs: 3000 });
    expect(r.servers[0].live.status).toBe('error');
  });
});
