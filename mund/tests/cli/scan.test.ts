import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { parseScanArgs, runScan, formatReport, shouldFail } from '../../src/cli/scan.js';
import { OsvClient } from '../../src/osv.js';

describe('parseScanArgs', () => {
  it('defaults to text, fail-on high, current dir, OSV on', () => {
    expect(parseScanArgs([])).toEqual({ paths: ['.'], format: 'text', failOn: 'high', osv: true, offline: false, canaries: [] });
  });

  it('accepts --flag=value and --flag value', () => {
    expect(parseScanArgs(['src', '--format=sarif', '--output', 'o.sarif', '--fail-on=none', '--no-osv', '--offline']))
      .toEqual({ paths: ['src'], format: 'sarif', output: 'o.sarif', failOn: 'none', osv: false, offline: true, canaries: [] });
  });

  it('rejects unknown formats and options', () => {
    expect(() => parseScanArgs(['--format=xml'])).toThrow(/Unknown format/);
    expect(() => parseScanArgs(['--nope'])).toThrow(/Unknown option/);
    expect(() => parseScanArgs(['--format'])).toThrow(/needs a value/);
  });
});

describe('runScan', () => {
  let dir: string;
  let cwd: string;

  beforeEach(() => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    dir = mkdtempSync(join(tmpdir(), 'mund-scan-'));
    cwd = process.cwd();
    process.chdir(dir);
    writeFileSync('clean.txt', 'hello world\n');
    writeFileSync('leak.js', 'const ok = 1;\nconst k = "AKIAIOSFODNN7EXAMPLE";\n');
    writeFileSync('blob.bin', Buffer.from([0, 1, 2, 'A'.charCodeAt(0)]));
    mkdirSync('node_modules/x', { recursive: true });
    writeFileSync('node_modules/x/leak.js', 'AKIAIOSFODNN7EXAMPLE');
    writeFileSync('package-lock.json', JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/lodash': { version: '4.17.15' } } }));
  });

  afterEach(() => {
    process.chdir(cwd);
    rmSync(dir, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  const fakeOsv = () => ({
    lookup: vi.fn(async () => ({
      source: 'live' as const, unchecked: [],
      advisories: new Map([['lodash@4.17.15', [{ id: 'GHSA-x', summary: 'bad', severity: 'high' as const, aliases: [], url: 'u' }]]]),
    })),
  }) as unknown as OsvClient;

  it('scans text files, skips binaries and node_modules, and checks lockfiles', async () => {
    const report = await runScan(parseScanArgs([]), fakeOsv());
    expect(report.files_scanned).toBe(2);
    expect(report.files.map(f => f.uri)).toEqual(['leak.js', 'package-lock.json']);
    expect(report.files[0].issues[0]).toMatchObject({ rule_id: 'aws_access_key_id', location: { line: 2 } });
    expect(report.osv).toEqual({ source: 'live', lockfiles: 1, unchecked: 0 });
    expect(report.risk.label).toBe('critical');
  });

  it('skips OSV with --no-osv', async () => {
    const osv = fakeOsv();
    const report = await runScan(parseScanArgs(['--no-osv']), osv);
    expect(osv.lookup).not.toHaveBeenCalled();
    expect(report.osv).toBeUndefined();
  });

  it('formats SARIF with repo-relative URIs', async () => {
    const report = await runScan(parseScanArgs([]), fakeOsv());
    const sarif = JSON.parse(formatReport(report, 'sarif'));
    expect(sarif.runs[0].results.map((r: any) => r.locations[0].physicalLocation.artifactLocation.uri))
      .toEqual(['leak.js', 'package-lock.json']);
  });

  it('formats a readable text summary', async () => {
    const text = formatReport(await runScan(parseScanArgs([]), fakeOsv()), 'text');
    expect(text).toContain('leak.js  (risk');
    expect(text).toMatch(/Risk score: \d+\/100 \(critical\)/);
    expect(text).toContain('Dependencies: OSV.dev (live)');
  });

  it('applies --fail-on thresholds', async () => {
    const report = await runScan(parseScanArgs([]), fakeOsv());
    expect(shouldFail(report, 'high')).toBe(true);
    expect(shouldFail(report, 'none')).toBe(false);
    const clean = await runScan(parseScanArgs(['clean.txt']), fakeOsv());
    expect(shouldFail(clean, 'low')).toBe(false);
  });
});
