import { mkdtempSync, rmSync, readFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { OsvClient, parseNpmLockfile, parseSeverity, advisoriesToIssues } from '../src/osv.js';

const LOCK_V3 = JSON.stringify({
  name: 'app', lockfileVersion: 3,
  packages: {
    '': { name: 'app' },
    'node_modules/lodash': { version: '4.17.15' },
    'node_modules/a/node_modules/lodash': { version: '4.17.15' },
    'node_modules/@scope/pkg': { version: '1.0.0' },
    'node_modules/linked': { link: true },
    'packages/workspace': { version: '0.0.1' },
  },
}, null, 2);

const GHSA = {
  id: 'GHSA-35jh-r3h4-6jhm',
  summary: 'Command Injection in lodash',
  aliases: ['CVE-2021-23337'],
  database_specific: { severity: 'HIGH' },
  affected: [{ package: { name: 'lodash', ecosystem: 'npm' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }],
};

function fakeFetch(): typeof fetch {
  return vi.fn(async (url: string | URL | Request) => {
    const u = String(url);
    if (u.endsWith('/querybatch')) {
      return Response.json({ results: [{ vulns: [{ id: GHSA.id }] }, { vulns: [] }] });
    }
    if (u.includes('/vulns/')) return Response.json(GHSA);
    return new Response('nope', { status: 404 });
  }) as unknown as typeof fetch;
}

const failingFetch = (() => Promise.reject(new Error('ENOTFOUND'))) as unknown as typeof fetch;

describe('parseNpmLockfile', () => {
  it('reads v3 packages, dedupes, skips root/links/workspaces', () => {
    const pkgs = parseNpmLockfile(LOCK_V3);
    expect(pkgs.map(p => `${p.name}@${p.version}`)).toEqual(['lodash@4.17.15', '@scope/pkg@1.0.0']);
    expect(pkgs[0].path).toBe('node_modules/lodash');
  });

  it('reads v1 nested dependencies', () => {
    const lock = JSON.stringify({ lockfileVersion: 1, dependencies: { a: { version: '1.0.0', dependencies: { b: { version: '2.0.0' } } }, local: { version: 'file:../x' } } });
    expect(parseNpmLockfile(lock).map(p => `${p.name}@${p.version}`)).toEqual(['a@1.0.0', 'b@2.0.0']);
  });
});

describe('parseSeverity', () => {
  it('prefers the database label over CVSS vectors', () => {
    expect(parseSeverity({ database_specific: { severity: 'MODERATE' }, severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L' }] })).toBe('medium');
  });
  it('falls back to a numeric score', () => {
    expect(parseSeverity({ severity: [{ type: 'CVSS_V3', score: '9.8' }] })).toBe('critical');
  });
  it('defaults to medium when unknown', () => {
    expect(parseSeverity({ severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N' }] })).toBe('medium');
  });
});

describe('OsvClient', () => {
  let dir: string;
  let cachePath: string;
  const pkgs = [{ name: 'lodash', version: '4.17.15', path: 'node_modules/lodash' }, { name: 'qs', version: '6.16.1' }];

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'mund-osv-'));
    cachePath = join(dir, 'cache.json');
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('looks up live and writes the cache', async () => {
    const result = await new OsvClient({ cachePath, fetch: fakeFetch() }).lookup(pkgs);
    expect(result.source).toBe('live');
    expect(result.advisories.get('lodash@4.17.15')).toEqual([expect.objectContaining({ id: GHSA.id, severity: 'high', fixed: '4.17.21' })]);
    expect(result.advisories.get('qs@6.16.1')).toEqual([]);
    expect(JSON.parse(readFileSync(cachePath, 'utf8')).packages['lodash@4.17.15'].advisories).toHaveLength(1);
  });

  it('falls back to the cache when OSV is unreachable', async () => {
    await new OsvClient({ cachePath, fetch: fakeFetch() }).lookup(pkgs);
    const result = await new OsvClient({ cachePath, fetch: failingFetch }).lookup(pkgs);
    expect(result.source).toBe('cache');
    expect(result.error).toMatch(/ENOTFOUND/);
    expect(result.advisories.get('lodash@4.17.15')).toHaveLength(1);
    expect(result.unchecked).toEqual([]);
  });

  it('reports packages with no cached answer as unchecked, not clean', async () => {
    const result = await new OsvClient({ cachePath, fetch: failingFetch }).lookup(pkgs);
    expect(result.source).toBe('unavailable');
    expect(result.unchecked).toEqual(['lodash@4.17.15', 'qs@6.16.1']);
  });

  it('never touches the network in offline mode', async () => {
    const f = fakeFetch();
    const result = await new OsvClient({ cachePath, fetch: f, offline: true }).lookup(pkgs);
    expect(f).not.toHaveBeenCalled();
    expect(result.error).toBe('offline mode');
    expect(existsSync(cachePath)).toBe(false);
  });
});

describe('advisoriesToIssues', () => {
  it('locates findings at the package entry in the lockfile', async () => {
    const pkgs = parseNpmLockfile(LOCK_V3);
    const result = { source: 'live' as const, unchecked: [], advisories: new Map([['lodash@4.17.15', [{ id: GHSA.id, summary: 'x', severity: 'high' as const, aliases: [], fixed: '4.17.21', url: 'u' }]]]) };
    const [issue] = advisoriesToIssues(pkgs, result, LOCK_V3);
    expect(issue).toMatchObject({ rule_id: GHSA.id, type: 'dependency', severity: 'high', match: 'lodash@4.17.15' });
    expect(LOCK_V3.split('\n')[issue.location!.line! - 1]).toContain('"node_modules/lodash"');
    expect(issue.suggestion).toContain('4.17.21');
  });
});
