/**
 * Mund - The Guardian Protocol
 * OSV.dev dependency vulnerability lookups with an offline fallback
 *
 * Live path: POST /v1/querybatch for every name@version in a lockfile,
 * then GET /v1/vulns/{id} once per unique advisory for details.
 *
 * Offline path: every successful live lookup is written to an on-disk
 * cache. When the network is unavailable (or MUND_OFFLINE=1 / --offline),
 * results come from that cache and are reported with source "cache", so
 * callers can tell a clean result from an unchecked one. Packages that
 * were never looked up are reported as unchecked, never as clean.
 */

import { readFile, writeFile, mkdir } from 'fs/promises';
import { homedir } from 'os';
import { dirname, join } from 'path';
import type { SecurityIssue, Severity } from './types.js';

const OSV_API = 'https://api.osv.dev/v1';
const BATCH_SIZE = 1000;
const DETAIL_CONCURRENCY = 8;

export interface LockedPackage {
  name: string;
  version: string;
  /** Lockfile key, e.g. "node_modules/qs", used to locate the finding. */
  path?: string;
}

export interface OsvAdvisory {
  id: string;
  summary: string;
  severity: Severity;
  aliases: string[];
  fixed?: string;
  url: string;
}

export type OsvSource = 'live' | 'cache' | 'unavailable';

export interface OsvLookupResult {
  source: OsvSource;
  /** Keyed by "name@version". */
  advisories: Map<string, OsvAdvisory[]>;
  /** name@version keys with no live or cached answer. */
  unchecked: string[];
  /** Why the live lookup did not run or failed, if it didn't. */
  error?: string;
}

export interface OsvClientOptions {
  offline?: boolean;
  cachePath?: string;
  timeoutMs?: number;
  fetch?: typeof fetch;
}

interface CacheFile {
  version: 1;
  packages: Record<string, { checkedAt: string; advisories: OsvAdvisory[] }>;
}

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{ type: string; score: string }>;
  database_specific?: { severity?: string };
  affected?: Array<{
    package?: { name: string; ecosystem: string };
    ranges?: Array<{ events: Array<{ introduced?: string; fixed?: string }> }>;
  }>;
}

export function defaultCachePath(): string {
  if (process.env.MUND_OSV_CACHE) return process.env.MUND_OSV_CACHE;
  const base = process.env.XDG_CACHE_HOME || join(homedir(), '.cache');
  return join(base, 'mund', 'osv-cache.json');
}

// ============================================================================
// Lockfile parsing
// ============================================================================

/** Parse an npm package-lock.json (lockfileVersion 1, 2 or 3). */
export function parseNpmLockfile(content: string): LockedPackage[] {
  const lock = JSON.parse(content) as {
    packages?: Record<string, { version?: string; name?: string; link?: boolean }>;
    dependencies?: Record<string, V1Dep>;
  };
  const seen = new Map<string, LockedPackage>();
  const add = (pkg: LockedPackage) => {
    const key = `${pkg.name}@${pkg.version}`;
    if (!seen.has(key)) seen.set(key, pkg);
  };

  if (lock.packages) {
    for (const [path, entry] of Object.entries(lock.packages)) {
      if (!path || entry.link || !entry.version) continue;
      const idx = path.lastIndexOf('node_modules/');
      if (idx === -1) continue; // workspace package, not a dependency
      add({ name: entry.name ?? path.slice(idx + 'node_modules/'.length), version: entry.version, path });
    }
  } else if (lock.dependencies) {
    const walk = (deps: Record<string, V1Dep>) => {
      for (const [name, dep] of Object.entries(deps)) {
        if (dep.version && !dep.version.startsWith('file:')) add({ name, version: dep.version });
        if (dep.dependencies) walk(dep.dependencies);
      }
    };
    walk(lock.dependencies);
  }

  return [...seen.values()];
}

interface V1Dep {
  version?: string;
  dependencies?: Record<string, V1Dep>;
}

// ============================================================================
// Client
// ============================================================================

export class OsvClient {
  private readonly offline: boolean;
  private readonly cachePath: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: OsvClientOptions = {}) {
    this.offline = options.offline ?? process.env.MUND_OFFLINE === '1';
    this.cachePath = options.cachePath ?? defaultCachePath();
    this.timeoutMs = options.timeoutMs ?? 15000;
    this.fetchImpl = options.fetch ?? fetch;
  }

  async lookup(packages: LockedPackage[], ecosystem = 'npm'): Promise<OsvLookupResult> {
    const keys = packages.map(p => `${p.name}@${p.version}`);
    if (packages.length === 0) return { source: 'live', advisories: new Map(), unchecked: [] };

    if (!this.offline) {
      try {
        const advisories = await this.lookupLive(packages, ecosystem);
        await this.writeCache(advisories);
        return { source: 'live', advisories, unchecked: [] };
      } catch (error) {
        return this.lookupCached(keys, `OSV.dev unreachable: ${(error as Error).message}`);
      }
    }
    return this.lookupCached(keys, 'offline mode');
  }

  private async lookupLive(packages: LockedPackage[], ecosystem: string): Promise<Map<string, OsvAdvisory[]>> {
    const idsByKey = new Map<string, string[]>();

    for (let i = 0; i < packages.length; i += BATCH_SIZE) {
      const chunk = packages.slice(i, i + BATCH_SIZE);
      const body = { queries: chunk.map(p => ({ package: { name: p.name, ecosystem }, version: p.version })) };
      const data = await this.request<{ results: Array<{ vulns?: Array<{ id: string }> }> }>(
        `${OSV_API}/querybatch`, { method: 'POST', body: JSON.stringify(body) },
      );
      chunk.forEach((p, j) => {
        idsByKey.set(`${p.name}@${p.version}`, (data.results[j]?.vulns ?? []).map(v => v.id));
      });
    }

    const uniqueIds = [...new Set([...idsByKey.values()].flat())];
    const details = new Map<string, OsvVuln>();
    for (let i = 0; i < uniqueIds.length; i += DETAIL_CONCURRENCY) {
      const batch = uniqueIds.slice(i, i + DETAIL_CONCURRENCY);
      const fetched = await Promise.all(batch.map(id => this.request<OsvVuln>(`${OSV_API}/vulns/${encodeURIComponent(id)}`)));
      fetched.forEach(v => details.set(v.id, v));
    }

    const advisories = new Map<string, OsvAdvisory[]>();
    for (const [key, ids] of idsByKey) {
      const name = key.slice(0, key.lastIndexOf('@'));
      advisories.set(key, ids.map(id => toAdvisory(details.get(id) ?? { id }, name)));
    }
    return advisories;
  }

  private async lookupCached(keys: string[], reason: string): Promise<OsvLookupResult> {
    const cache = await this.readCache();
    const advisories = new Map<string, OsvAdvisory[]>();
    const unchecked: string[] = [];

    for (const key of keys) {
      const hit = cache?.packages[key];
      if (hit) advisories.set(key, hit.advisories);
      else unchecked.push(key);
    }

    const source: OsvSource = advisories.size > 0 ? 'cache' : 'unavailable';
    return { source, advisories, unchecked, error: reason };
  }

  private async request<T>(url: string, init: RequestInit = {}): Promise<T> {
    const res = await this.fetchImpl(url, {
      ...init,
      headers: { 'Content-Type': 'application/json' },
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!res.ok) throw new Error(`${res.status} ${res.statusText} from ${url}`);
    return (await res.json()) as T;
  }

  private async readCache(): Promise<CacheFile | null> {
    try {
      const cache = JSON.parse(await readFile(this.cachePath, 'utf8')) as CacheFile;
      return cache.version === 1 && cache.packages ? cache : null;
    } catch {
      return null;
    }
  }

  private async writeCache(advisories: Map<string, OsvAdvisory[]>): Promise<void> {
    const cache: CacheFile = (await this.readCache()) ?? { version: 1, packages: {} };
    const checkedAt = new Date().toISOString();
    for (const [key, list] of advisories) cache.packages[key] = { checkedAt, advisories: list };
    try {
      await mkdir(dirname(this.cachePath), { recursive: true });
      await writeFile(this.cachePath, JSON.stringify(cache));
    } catch {
      // A read-only cache dir shouldn't fail the scan; we just lose the fallback.
    }
  }
}

function toAdvisory(vuln: OsvVuln, packageName: string): OsvAdvisory {
  let fixed: string | undefined;
  for (const affected of vuln.affected ?? []) {
    if (affected.package && affected.package.name !== packageName) continue;
    for (const range of affected.ranges ?? []) {
      for (const event of range.events) if (event.fixed) fixed = event.fixed;
    }
  }

  return {
    id: vuln.id,
    summary: vuln.summary || vuln.details?.split('\n')[0]?.slice(0, 200) || 'No summary available',
    severity: parseSeverity(vuln),
    aliases: vuln.aliases ?? [],
    fixed,
    url: `https://osv.dev/vulnerability/${encodeURIComponent(vuln.id)}`,
  };
}

/**
 * OSV `severity[].score` is usually a CVSS *vector* string, not a number,
 * so prefer the database's own label (GHSA sets it for npm advisories).
 */
export function parseSeverity(vuln: Pick<OsvVuln, 'severity' | 'database_specific'>): Severity {
  const label = vuln.database_specific?.severity?.toLowerCase();
  if (label === 'critical') return 'critical';
  if (label === 'high') return 'high';
  if (label === 'moderate' || label === 'medium') return 'medium';
  if (label === 'low') return 'low';

  for (const s of vuln.severity ?? []) {
    const score = Number(s.score);
    if (!Number.isNaN(score)) {
      if (score >= 9) return 'critical';
      if (score >= 7) return 'high';
      if (score >= 4) return 'medium';
      if (score > 0) return 'low';
    }
  }
  return 'medium';
}

// ============================================================================
// Findings
// ============================================================================

/** Turn lookup results into SecurityIssues located in the lockfile. */
export function advisoriesToIssues(
  packages: LockedPackage[],
  result: OsvLookupResult,
  lockfileContent: string,
): SecurityIssue[] {
  const issues: SecurityIssue[] = [];

  for (const pkg of packages) {
    const key = `${pkg.name}@${pkg.version}`;
    for (const adv of result.advisories.get(key) ?? []) {
      const needle = pkg.path ? `"${pkg.path}"` : `"${pkg.name}"`;
      const start = Math.max(0, lockfileContent.indexOf(needle));
      const before = lockfileContent.slice(0, start).split('\n');

      issues.push({
        rule_id: adv.id,
        rule_name: `${key}: ${adv.summary}`,
        type: 'dependency',
        severity: adv.severity,
        action: 'alert',
        match: key,
        location: { start, end: start + needle.length, line: before.length, column: before[before.length - 1].length + 1 },
        suggestion: adv.fixed
          ? `Upgrade ${pkg.name} to ${adv.fixed} or later. ${adv.url}`
          : `No fixed version published yet. ${adv.url}`,
      });
    }
  }
  return issues;
}
