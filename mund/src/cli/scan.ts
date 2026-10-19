/**
 * Mund - The Guardian Protocol
 * `mund-mcp scan` - scan files on disk and report as text, JSON or SARIF
 *
 *   mund-mcp scan [paths...] [--format=text|json|sarif] [--output=FILE]
 *                 [--fail-on=critical|high|medium|low|none]
 *                 [--no-osv] [--offline]
 */

import { readFile, writeFile, readdir, stat } from 'fs/promises';
import { basename, join, relative, resolve, sep } from 'path';
import type { SecurityIssue, Severity } from '../types.js';
import { DEFAULT_RULES } from '../constants.js';
import { AnalyzerEngine } from '../analyzers/index.js';
import { computeRiskScore, type RiskScore } from '../scoring.js';
import { toSarif, type SarifTarget } from '../sarif.js';
import { OsvClient, parseNpmLockfile, advisoriesToIssues, type OsvSource } from '../osv.js';
import { getVersion } from '../version.js';
import { canaries, loadCanariesFromEnv } from '../canary.js';

export type OutputFormat = 'text' | 'json' | 'sarif';
type FailOn = Severity | 'none';

export interface ScanCliOptions {
  paths: string[];
  format: OutputFormat;
  output?: string;
  failOn: FailOn;
  osv: boolean;
  offline: boolean;
  canaries: string[];
}

export interface FileReport extends SarifTarget {
  risk: RiskScore;
}

export interface ScanReport {
  tool: { name: 'mund'; version: string };
  risk: RiskScore;
  files_scanned: number;
  osv?: { source: OsvSource; lockfiles: number; unchecked: number; error?: string };
  files: FileReport[];
}

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.turbo', 'vendor', '__pycache__', '.venv']);
const LOCKFILES = new Set(['package-lock.json', 'npm-shrinkwrap.json']);
const MAX_FILE_BYTES = 1024 * 1024;
const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export const SCAN_USAGE = `Usage: mund-mcp scan [paths...] [options]

Scan files for secrets, PII, injection, exfiltration and dangerous code,
plus known-vulnerable npm dependencies (via OSV.dev) in package-lock.json.

Options:
  --format=FORMAT    text (default), json, or sarif
  --output=FILE      Write the report to FILE instead of stdout
  --fail-on=LEVEL    Exit 1 if any finding is at or above LEVEL
                     (critical, high [default], medium, low, none)
  --no-osv           Skip dependency vulnerability lookups
  --offline          Use only the local OSV cache (also: MUND_OFFLINE=1)
  --canary=TOKEN     Flag any file containing this canary token (repeatable;
                     also MUND_CANARIES / MUND_CANARY_FILE)

Examples:
  mund-mcp scan .
  mund-mcp scan src --format=sarif --output=mund.sarif
`;

export function parseScanArgs(args: string[]): ScanCliOptions {
  const opts: ScanCliOptions = { paths: [], format: 'text', failOn: 'high', osv: true, offline: false, canaries: [] };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const [flag, inline] = arg.startsWith('--') && arg.includes('=') ? [arg.slice(0, arg.indexOf('=')), arg.slice(arg.indexOf('=') + 1)] : [arg, undefined];
    const value = () => {
      const v = inline ?? args[++i];
      if (v === undefined) throw new Error(`${flag} needs a value`);
      return v;
    };

    switch (flag) {
      case '--format': {
        const v = value();
        if (v !== 'text' && v !== 'json' && v !== 'sarif') throw new Error(`Unknown format "${v}" (expected text, json or sarif)`);
        opts.format = v;
        break;
      }
      case '--output':
      case '-o':
        opts.output = value();
        break;
      case '--fail-on': {
        const v = value();
        if (v !== 'none' && !(v in SEVERITY_RANK)) throw new Error(`Unknown --fail-on level "${v}"`);
        opts.failOn = v as FailOn;
        break;
      }
      case '--no-osv':
        opts.osv = false;
        break;
      case '--offline':
        opts.offline = true;
        break;
      case '--canary':
        opts.canaries.push(value());
        break;
      default:
        if (flag.startsWith('-')) throw new Error(`Unknown option ${flag}`);
        opts.paths.push(arg);
    }
  }

  if (opts.paths.length === 0) opts.paths.push('.');
  return opts;
}

export async function runScan(opts: ScanCliOptions, osvClient?: OsvClient): Promise<ScanReport> {
  const cwd = process.cwd();
  loadCanariesFromEnv();
  for (const token of opts.canaries) canaries.register(token, 'cli');
  const engine = new AnalyzerEngine();
  const files: FileReport[] = [];
  const lockfiles: string[] = [];
  let scanned = 0;

  for (const file of await collectFiles(opts.paths.map(p => resolve(cwd, p)))) {
    if (LOCKFILES.has(basename(file))) {
      lockfiles.push(file);
      continue;
    }
    const content = await readText(file);
    if (content === null) continue;
    scanned++;
    const issues = await engine.analyzeAll(content, DEFAULT_RULES);
    if (issues.length > 0) files.push({ uri: toUri(cwd, file), issues, risk: computeRiskScore(issues) });
  }

  let osv: ScanReport['osv'];
  if (opts.osv && lockfiles.length > 0) {
    const client = osvClient ?? new OsvClient({ offline: opts.offline });
    let source: OsvSource = 'live';
    let unchecked = 0;
    let error: string | undefined;

    for (const lockfile of lockfiles) {
      const content = await readFile(lockfile, 'utf8');
      let packages;
      try {
        packages = parseNpmLockfile(content);
      } catch {
        continue; // malformed lockfile; nothing to look up
      }
      const result = await client.lookup(packages);
      // Report the weakest source across lockfiles.
      if (result.source === 'unavailable' || (result.source === 'cache' && source === 'live')) source = result.source;
      unchecked += result.unchecked.length;
      error ??= result.error;

      const issues = advisoriesToIssues(packages, result, content);
      if (issues.length > 0) files.push({ uri: toUri(cwd, lockfile), issues, risk: computeRiskScore(issues) });
    }
    osv = { source, lockfiles: lockfiles.length, unchecked, ...(error ? { error } : {}) };
  }

  return {
    tool: { name: 'mund', version: getVersion() },
    risk: computeRiskScore(files.flatMap(f => f.issues)),
    files_scanned: scanned,
    ...(osv ? { osv } : {}),
    files,
  };
}

export function formatReport(report: ScanReport, format: OutputFormat): string {
  if (format === 'json') return JSON.stringify(report, null, 2);
  if (format === 'sarif') return JSON.stringify(toSarif(report.files, { toolVersion: report.tool.version }), null, 2);

  const lines: string[] = [];
  for (const file of report.files) {
    lines.push(`${file.uri}  (risk ${file.risk.score}/100, ${file.risk.label})`);
    for (const issue of file.issues) {
      const where = issue.location?.line ? `${issue.location.line}:${issue.location.column ?? 1}` : '-';
      lines.push(`  ${where.padEnd(8)} ${issue.severity.padEnd(8)} ${issue.rule_name}`);
    }
    lines.push('');
  }

  const total = report.files.reduce((n, f) => n + f.issues.length, 0);
  const { counts } = report.risk;
  lines.push(`Scanned ${report.files_scanned} file(s): ${total} finding(s) ` +
    `(${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low)`);
  lines.push(`Risk score: ${report.risk.score}/100 (${report.risk.label})`);
  if (report.osv) {
    const note = report.osv.source === 'live' ? 'live' : `${report.osv.source} - ${report.osv.error ?? ''}`.trim();
    lines.push(`Dependencies: OSV.dev (${note})` + (report.osv.unchecked ? `, ${report.osv.unchecked} package(s) unchecked` : ''));
  }
  return lines.join('\n');
}

export function shouldFail(report: ScanReport, failOn: FailOn): boolean {
  if (failOn === 'none') return false;
  const threshold = SEVERITY_RANK[failOn];
  return report.files.some(f => f.issues.some((i: SecurityIssue) => SEVERITY_RANK[i.severity] <= threshold));
}

/** Entry point for `mund-mcp scan`. Returns the process exit code. */
export async function runScanCli(args: string[]): Promise<number> {
  if (args.includes('--help') || args.includes('-h')) {
    process.stdout.write(SCAN_USAGE);
    return 0;
  }

  let opts: ScanCliOptions;
  try {
    opts = parseScanArgs(args);
  } catch (error) {
    process.stderr.write(`mund scan: ${(error as Error).message}\n\n${SCAN_USAGE}`);
    return 2;
  }

  const report = await runScan(opts);
  const out = formatReport(report, opts.format) + '\n';
  if (opts.output) await writeFile(opts.output, out);
  else process.stdout.write(out);

  return shouldFail(report, opts.failOn) ? 1 : 0;
}

async function collectFiles(roots: string[]): Promise<string[]> {
  const out: string[] = [];
  const walk = async (path: string) => {
    const info = await stat(path).catch(() => null);
    if (!info) return;
    if (info.isFile()) {
      out.push(path);
    } else if (info.isDirectory()) {
      for (const entry of await readdir(path, { withFileTypes: true })) {
        if (entry.isDirectory() && SKIP_DIRS.has(entry.name)) continue;
        if (entry.isDirectory() || entry.isFile()) await walk(join(path, entry.name));
      }
    }
  };
  for (const root of roots) await walk(root);
  return out.sort();
}

/** Read a file as UTF-8 text, or null if it's too big or looks binary. */
async function readText(file: string): Promise<string | null> {
  const info = await stat(file);
  if (info.size > MAX_FILE_BYTES) return null;
  const buf = await readFile(file);
  if (buf.subarray(0, 8000).includes(0)) return null;
  return buf.toString('utf8');
}

function toUri(cwd: string, file: string): string {
  return relative(cwd, file).split(sep).join('/');
}
