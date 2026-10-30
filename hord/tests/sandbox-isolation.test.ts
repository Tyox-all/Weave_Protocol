/**
 * Sandbox isolation: unit tests for the launch plan, plus real (benign)
 * escape attempts run through the sandbox on the current host. Where the
 * host can't isolate (e.g. Linux without bwrap/user namespaces), the
 * enforcement assertions follow the isolation report instead.
 */
import { existsSync, rmSync, writeFileSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';
import { afterAll, describe, expect, it } from 'vitest';
import { SandboxManager } from '../src/sandbox/executor.js';
import { MemoryStorage } from '../src/storage/memory.js';
import { IsolationLevel, PromotionRecommendation } from '../src/types.js';
import { macProfile, missingForStrict, planLaunch, scrubbedEnv } from '../src/sandbox/isolation.js';
import { SANDBOX } from '../src/constants.js';

const base = { limits: SANDBOX.DEFAULT_LIMITS, network: SANDBOX.DEFAULT_NETWORK_POLICY, filesystem: SANDBOX.DEFAULT_FILESYSTEM_POLICY };

describe('launch plan', () => {
  it('scrubs the environment down to PATH/HOME/TMPDIR/LANG + explicit vars', () => {
    expect(Object.keys(scrubbedEnv('/w', '/opt/node/bin', { FOO: '1' })).sort()).toEqual(['FOO', 'HOME', 'LANG', 'PATH', 'TMPDIR']);
  });

  it('macOS: wraps with sandbox-exec; profile denies network and writes outside the workdir', () => {
    const p = planLaunch('node', ['x.js'], { ...base, workdir: '/tmp', platform: 'darwin', available: { 'sandbox-exec': true } });
    expect(p.command).toBe('/usr/bin/sandbox-exec');
    expect(p.report).toMatchObject({ mechanism: 'sandbox-exec', network: 'blocked', filesystem: 'restricted', limits: { memory: 'watchdog' } });
    const profile = macProfile({ workdir: '/w', home: '/Users/u', allowNetwork: false, blocked: [] });
    expect(profile).toContain('(deny network*)');
    expect(profile).toContain('(deny file-write*)');
    expect(profile).toContain('(allow file-write* (subpath "/w")');
    expect(profile).toContain('(deny file-read* (subpath "/Users/u"))');
    expect(macProfile({ workdir: '/w', home: '/h', allowNetwork: true, blocked: [] })).not.toContain('deny network');
  });

  it('Linux: prefers bwrap (net + fs), falls back to unshare (net only), else reports none', () => {
    const lin = (available: Record<string, boolean>, allow = false) =>
      planLaunch('python3', ['s.py'], { ...base, network: { ...base.network, allow_outbound: allow }, workdir: '/tmp', platform: 'linux', available });
    const bw = lin({ bwrap: true, unshare: true });
    expect(bw.command).toBe('bwrap');
    expect(bw.args).toContain('--unshare-net');
    expect(bw.report).toMatchObject({ network: 'blocked', filesystem: 'restricted', limits: { memory: 'watchdog' } });
    expect(lin({ bwrap: true }, true).args).not.toContain('--unshare-net');
    expect(lin({ bwrap: false, unshare: true }).report).toMatchObject({ mechanism: 'unshare', network: 'blocked', filesystem: 'not_isolated' });
    const none = lin({ bwrap: false, unshare: false });
    expect(none.report).toMatchObject({ mechanism: 'none', network: 'not_isolated' });
    expect(missingForStrict(none.report, base.network)).toEqual(['network isolation', 'filesystem isolation']);
  });
});

// ─── Real escape attempts on this host ─────────────────────────

const manager = new SandboxManager(new MemoryStorage());
const run = async (content: string, opts: { language?: string; memory_mb?: number; timeout_ms?: number; allow_outbound?: boolean; enforcement?: 'strict' } = {}) => {
  const sandbox = await manager.createSandbox({
    type: 'code',
    isolation_level: IsolationLevel.PROCESS,
    resource_limits: { ...SANDBOX.DEFAULT_LIMITS, memory_mb: opts.memory_mb ?? 256 },
    network_policy: { ...SANDBOX.DEFAULT_NETWORK_POLICY, allow_outbound: !!opts.allow_outbound },
    filesystem_policy: SANDBOX.DEFAULT_FILESYSTEM_POLICY,
    timeout_ms: opts.timeout_ms ?? 15000,
    enforcement: opts.enforcement,
  });
  return manager.execute({ sandbox_id: sandbox.id, type: 'code', language: opts.language ?? 'javascript', content } as any);
};

const probe = join(homedir(), `.hord-sandbox-probe-${process.pid}`);
afterAll(() => rmSync(probe, { force: true }));

describe('escape attempts', () => {
  it('cannot see the parent process environment', async () => {
    process.env.HORD_TEST_SECRET = 'sk-test-should-not-leak';
    const r = await run(`console.log(process.env.HORD_TEST_SECRET ?? 'none')`);
    delete process.env.HORD_TEST_SECRET;
    expect(r.stdout.trim()).toBe('none');
    expect(r.isolation?.environment).toBe('scrubbed');
  });

  it('cannot open network connections when outbound is not allowed', async () => {
    const r = await run(`
      const s = require('net').connect(80, '1.1.1.1');
      s.on('connect', () => { console.log('connected'); s.destroy(); });
      s.on('error', (e) => console.log('blocked ' + e.code));
      setTimeout(() => { console.log('timeout'); process.exit(0); }, 3000);`);
    if (r.isolation?.network === 'blocked') expect(r.stdout).not.toContain('connected');
    else expect(r.security_events.some((e) => e.type === 'isolation_unavailable')).toBe(true);
  });

  it('cannot write outside its workdir or read the user\'s home directory', async () => {
    writeFileSync(probe, 'private');
    const escape = join(homedir(), `.hord-sandbox-escape-${process.pid}`);
    const r = await run(`
      const fs = require('fs');
      try { fs.writeFileSync('inside.txt', 'ok'); console.log('inside:ok'); } catch (e) { console.log('inside:' + e.code); }
      try { fs.writeFileSync(${JSON.stringify(escape)}, 'x'); console.log('escape-write:ok'); } catch (e) { console.log('escape-write:' + e.code); }
      try { console.log('home-read:' + fs.readFileSync(${JSON.stringify(probe)}, 'utf8')); } catch (e) { console.log('home-read:' + e.code); }`);
    expect(r.stdout).toContain('inside:ok');
    // Judge by what reaches the host: under bwrap $HOME is a private tmpfs, so a
    // write there "succeeds" but is thrown away, and the real home isn't visible.
    if (r.isolation?.filesystem === 'restricted') {
      expect(existsSync(escape)).toBe(false);
      expect(r.stdout).not.toContain('home-read:private');
    }
    rmSync(escape, { force: true });
  });

  it('is killed when it exceeds its memory limit, and reports real peak memory', async () => {
    const r = await run(`const keep = []; for (let i = 0; i < 60; i++) { keep.push(Buffer.alloc(10 * 1024 * 1024, 1)); } setTimeout(() => console.log('survived'), 2000);`,
      { memory_mb: 128 });
    expect(r.stdout).not.toContain('survived');
    expect(r.status).toBe('violation');
    expect(r.promotion_recommendation).toBe(PromotionRecommendation.BLOCK);
    expect(r.resource_usage.memory_peak_mb).toBeGreaterThan(0);
  }, 20000);

  it('timeouts kill the whole process group, not just the parent', async () => {
    const r = await run(`sleep 30 & echo "child=$!"; wait`, { language: 'bash', timeout_ms: 1500 });
    expect(r.status).toBe('timeout');
    const childPid = Number(r.stdout.match(/child=(\d+)/)?.[1]);
    expect(childPid).toBeGreaterThan(0);
    await new Promise((res) => setTimeout(res, 300));
    const alive = (() => { try { process.kill(childPid, 0); return true; } catch { return false; } })();
    expect(alive).toBe(false);
  });

  it('a signal-killed process is a failure, not exit code 0', async () => {
    const r = await run(`kill -9 $$`, { language: 'bash' });
    expect(r.exit_code).toBe(137);
    expect(r.status).toBe('failure');
  });

  it('a clean run with full isolation is not downgraded; missing isolation means review', async () => {
    const r = await run(`console.log(1 + 1)`);
    expect(r.stdout.trim()).toBe('2');
    const gaps = missingForStrict(r.isolation!, SANDBOX.DEFAULT_NETWORK_POLICY);
    expect(r.promotion_recommendation).toBe(gaps.length ? PromotionRecommendation.REVIEW : PromotionRecommendation.SAFE);
  });

  it('strict mode runs only when isolation is complete', async () => {
    const r = run(`console.log('ran')`, { enforcement: 'strict' });
    const report = planLaunch('true', [], { ...base, workdir: '/tmp' }).report;
    if (missingForStrict(report, base.network).length) await expect(r).rejects.toThrow(/Strict sandbox cannot run/);
    else expect((await r).stdout.trim()).toBe('ran');
  });
});

