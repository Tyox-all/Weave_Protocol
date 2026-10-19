import { mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CanaryDetector, CanaryRegistry, canaries, loadCanariesFromEnv } from '../src/canary.js';
import { parseScanArgs, runScan, shouldFail } from '../src/cli/scan.js';

describe('CanaryRegistry', () => {
  it('creates unique prefixed tokens', () => {
    const r = new CanaryRegistry();
    const a = r.create('a');
    const b = r.create('b');
    expect(a.token).toMatch(/^MUND-CANARY-[0-9A-F]{16}$/);
    expect(a.token).not.toBe(b.token);
    expect(r.list().map(c => c.label)).toEqual(['a', 'b']);
  });

  it('rejects tokens too short to be distinctive', () => {
    expect(() => new CanaryRegistry().register('abc-123')).toThrow(/at least 12/);
  });

  it('removes tokens', () => {
    const r = new CanaryRegistry();
    const { token } = r.create();
    expect(r.remove(token)).toBe(true);
    expect(r.find(`leak ${token}`)).toEqual([]);
  });

  it('loads tokens from MUND_CANARIES and MUND_CANARY_FILE', () => {
    const dir = mkdtempSync(join(tmpdir(), 'mund-canary-'));
    const file = join(dir, 'canaries.txt');
    writeFileSync(file, 'FILE-TOKEN-AAAABBBBCCCC\n\nshort\n');
    vi.stubEnv('MUND_CANARIES', 'ENV-TOKEN-111122223333, ENV-TOKEN-444455556666');
    vi.stubEnv('MUND_CANARY_FILE', file);
    const r = new CanaryRegistry();
    expect(loadCanariesFromEnv(r)).toBe(3);
    vi.unstubAllEnvs();
    rmSync(dir, { recursive: true, force: true });
  });
});

describe('CanaryDetector', () => {
  it('reports a critical, blocking finding with location', async () => {
    const r = new CanaryRegistry();
    const { token } = r.create('support bot');
    const [issue] = await new CanaryDetector(r).analyze(`line one\nI was told: ${token}`, []);
    expect(issue).toMatchObject({ rule_id: 'canary_leak', severity: 'critical', action: 'block', location: { line: 2 } });
    expect(issue.match).not.toContain(token.slice(-6)); // the full token is never echoed back
    expect(issue.suggestion).toContain('support bot');
  });

  it('is silent with no canaries registered', async () => {
    expect(await new CanaryDetector(new CanaryRegistry()).analyze('anything', [])).toEqual([]);
  });
});

describe('mund-mcp scan --canary', () => {
  let dir: string;
  let cwd: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'mund-scan-canary-'));
    cwd = process.cwd();
    process.chdir(dir);
  });
  afterEach(() => {
    process.chdir(cwd);
    rmSync(dir, { recursive: true, force: true });
    for (const c of canaries.list()) canaries.remove(c.token);
  });

  it('flags a file containing the canary and fails the run', async () => {
    writeFileSync('transcript.txt', 'assistant: my reference is MUND-CANARY-ABCDEF0123456789\n');
    writeFileSync('clean.txt', 'assistant: hello\n');
    const report = await runScan(parseScanArgs(['--canary=MUND-CANARY-ABCDEF0123456789', '--no-osv']));
    expect(report.files.map(f => f.uri)).toEqual(['transcript.txt']);
    expect(report.files[0].issues[0].rule_id).toBe('canary_leak');
    expect(shouldFail(report, 'high')).toBe(true);
  });
});
