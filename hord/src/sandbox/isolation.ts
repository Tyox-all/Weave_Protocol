/**
 * Hord sandbox isolation.
 *
 * Wraps sandboxed processes with whatever isolation the host OS provides,
 * and reports exactly what was enforced:
 *
 *   environment  always scrubbed: only PATH/HOME/TMPDIR/LANG plus what the
 *                caller passes, so the parent's API keys never leak in
 *   network      macOS: sandbox-exec profile denies network*
 *                Linux: bwrap --unshare-net, or unshare -rn
 *   filesystem   macOS: writes only inside the workdir; no reads of $HOME
 *                except the workdir and the interpreter's install root
 *                Linux (bwrap): read-only /, private /tmp and $HOME, workdir bind-mounted rw
 *   limits       ulimit -t (CPU), -f (file size), -n (fds)
 *   memory       a watchdog sums RSS for the process group, kills it over the limit,
 *                and reports the real peak. (RLIMIT_AS is not used: macOS ignores it,
 *                and runtimes like V8 reserve gigabytes of address space at startup,
 *                so any useful cap would crash them before they run.)
 *   processes    the child gets its own process group; timeouts kill the whole group
 *
 * Not used: `ulimit -u` (max processes) counts ALL of the user's processes,
 * so any small value would stop the sandbox from launching at all.
 */

import { spawnSync, execFileSync } from 'child_process';
import { existsSync, realpathSync } from 'fs';
import { homedir } from 'os';
import { delimiter, dirname, isAbsolute, join, sep } from 'path';
import type { NetworkPolicy, ResourceLimits, FilesystemPolicy } from '../types.js';

export type Mechanism = 'sandbox-exec' | 'bwrap' | 'unshare' | 'none';

export interface IsolationReport {
  platform: NodeJS.Platform;
  mechanism: Mechanism;
  network: 'blocked' | 'allowed' | 'not_isolated';
  filesystem: 'restricted' | 'not_isolated';
  environment: 'scrubbed';
  limits: {
    cpu_seconds: boolean;
    file_size: boolean;
    file_descriptors: boolean;
    memory: 'watchdog' | 'none';
  };
  process_group: boolean;
}

export interface LaunchPlan {
  command: string;
  args: string[];
  env: Record<string, string>;
  detached: boolean;
  report: IsolationReport;
}

export interface LaunchOptions {
  workdir: string;
  limits: ResourceLimits;
  network: NetworkPolicy;
  filesystem: FilesystemPolicy;
  environment?: Record<string, string>;
  /** For tests: pretend these mechanisms are (un)available. */
  available?: Partial<Record<Exclude<Mechanism, 'none'>, boolean>>;
  platform?: NodeJS.Platform;
}

// ─── Detection ──────────────────────────────────────────────────

let detected: Record<Exclude<Mechanism, 'none'>, boolean> | null = null;

/** Which mechanisms actually work here (probed once: user namespaces are often disabled). */
export function detectMechanisms(): Record<Exclude<Mechanism, 'none'>, boolean> {
  if (detected) return detected;
  const works = (cmd: string, args: string[]) => {
    try {
      return spawnSync(cmd, args, { stdio: 'ignore', timeout: 5000 }).status === 0;
    } catch {
      return false;
    }
  };
  detected = {
    'sandbox-exec': process.platform === 'darwin' && works('/usr/bin/sandbox-exec', ['-p', '(version 1)(allow default)', '/usr/bin/true']),
    bwrap: process.platform === 'linux' && works('bwrap', ['--ro-bind', '/', '/', '--unshare-net', '--', '/bin/true']),
    unshare: process.platform === 'linux' && works('unshare', ['-rn', '/bin/true']),
  };
  return detected;
}

// ─── Helpers ────────────────────────────────────────────────────

const real = (p: string) => {
  try {
    return realpathSync(p);
  } catch {
    return p;
  }
};

/** Resolve a bare command on PATH to an absolute, symlink-free path. */
export function resolveCommand(command: string, pathEnv = process.env.PATH ?? ''): string {
  if (isAbsolute(command)) return real(command);
  for (const dir of pathEnv.split(delimiter)) {
    const candidate = join(dir, command);
    if (dir && existsSync(candidate)) return real(candidate);
  }
  return command;
}

/** Install root of an interpreter (…/bin/node → …), so a sandbox can still load it. */
function installRoot(resolved: string): string {
  const bin = dirname(resolved);
  return bin.endsWith(`${sep}bin`) ? dirname(bin) : bin;
}

const sbplString = (s: string) => `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;

/** sandbox-exec (SBPL) profile: default allow, with network and filesystem carved out. */
export function macProfile(opts: { workdir: string; home: string; interpreterRoot?: string; allowNetwork: boolean; blocked: string[] }): string {
  const wd = sbplString(opts.workdir);
  const lines = [
    '(version 1)',
    '(allow default)',
    ...(opts.allowNetwork ? [] : ['(deny network*)']),
    '(deny file-write*)',
    `(allow file-write* (subpath ${wd}) (literal "/dev/null") (literal "/dev/stdout") (literal "/dev/stderr") (literal "/dev/tty") (regex #"^/dev/fd/"))`,
    `(deny file-read* (subpath ${sbplString(opts.home)}))`,
    ...opts.blocked.filter((p) => existsSync(p)).map((p) => `(deny file-read* (subpath ${sbplString(real(p))}))`),
    `(allow file-read* (subpath ${wd})${opts.interpreterRoot ? ` (subpath ${sbplString(opts.interpreterRoot)})` : ''})`,
  ];
  return lines.join('\n');
}

/** Minimal environment: nothing from the parent except a safe PATH. */
export function scrubbedEnv(workdir: string, interpreterBin: string | undefined, extra: Record<string, string> = {}): Record<string, string> {
  const path = [...(interpreterBin ? [interpreterBin] : []), '/usr/local/bin', '/usr/bin', '/bin'].join(delimiter);
  return { PATH: path, HOME: workdir, TMPDIR: workdir, LANG: 'C.UTF-8', ...extra };
}

/**
 * ulimit prelude, run by /bin/sh before exec'ing the real command. Units:
 * -t seconds, -f 512-byte blocks (POSIX sh), -n descriptors.
 * Each limit is applied best-effort so an unsupported one can't stop the run.
 */
function ulimitPrelude(limits: ResourceLimits): string {
  const parts: string[] = [];
  if (limits.cpu_seconds > 0) parts.push(`ulimit -t ${Math.ceil(limits.cpu_seconds)} 2>/dev/null`);
  if (limits.max_file_size_mb) parts.push(`ulimit -f ${Math.ceil(limits.max_file_size_mb * 2048)} 2>/dev/null`);
  if (limits.max_file_descriptors) parts.push(`ulimit -n ${limits.max_file_descriptors} 2>/dev/null`);
  parts.push('exec "$@"');
  return parts.join('; ');
}

// ─── Launch planning ────────────────────────────────────────────

export function planLaunch(command: string, args: string[], opts: LaunchOptions): LaunchPlan {
  const platform = opts.platform ?? process.platform;
  const has = { ...detectMechanisms(), ...opts.available };
  const workdir = real(opts.workdir);
  const resolved = resolveCommand(command);
  const interpreterBin = isAbsolute(resolved) ? dirname(resolved) : undefined;
  const allowNetwork = !!opts.network.allow_outbound;
  const posix = platform !== 'win32';

  const env = scrubbedEnv(workdir, interpreterBin, opts.environment);
  const prelude = posix ? ulimitPrelude(opts.limits) : null;
  const inner = prelude ? ['/bin/sh', '-c', prelude, 'hord-sandbox', resolved, ...args] : [resolved, ...args];

  let mechanism: Mechanism = 'none';
  let wrapped = inner;

  if (platform === 'darwin' && has['sandbox-exec']) {
    mechanism = 'sandbox-exec';
    const profile = macProfile({
      workdir,
      home: real(homedir()),
      interpreterRoot: isAbsolute(resolved) ? installRoot(resolved) : undefined,
      allowNetwork,
      blocked: opts.filesystem.blocked_paths ?? [],
    });
    wrapped = ['/usr/bin/sandbox-exec', '-p', profile, ...inner];
  } else if (platform === 'linux' && has.bwrap) {
    mechanism = 'bwrap';
    const home = real(homedir());
    const root = isAbsolute(resolved) ? installRoot(resolved) : undefined;
    wrapped = [
      'bwrap', '--ro-bind', '/', '/', '--dev', '/dev', '--proc', '/proc',
      '--tmpfs', '/tmp', '--tmpfs', home,
      ...(root && root.startsWith(home) ? ['--ro-bind', root, root] : []),
      '--bind', workdir, workdir, '--chdir', workdir,
      '--unshare-pid', '--unshare-ipc', '--unshare-uts', ...(allowNetwork ? [] : ['--unshare-net']),
      '--die-with-parent', '--new-session', '--', ...inner,
    ];
  } else if (platform === 'linux' && has.unshare && !allowNetwork) {
    mechanism = 'unshare';
    wrapped = ['unshare', '-rn', ...inner];
  }

  const networkIsolated = mechanism === 'sandbox-exec' || mechanism === 'bwrap' || mechanism === 'unshare';
  return {
    command: wrapped[0],
    args: wrapped.slice(1),
    env,
    detached: posix,
    report: {
      platform,
      mechanism,
      network: allowNetwork ? 'allowed' : networkIsolated ? 'blocked' : 'not_isolated',
      filesystem: mechanism === 'sandbox-exec' || mechanism === 'bwrap' ? 'restricted' : 'not_isolated',
      environment: 'scrubbed',
      limits: {
        cpu_seconds: posix && opts.limits.cpu_seconds > 0,
        file_size: posix && !!opts.limits.max_file_size_mb,
        file_descriptors: posix && !!opts.limits.max_file_descriptors,
        memory: posix && opts.limits.memory_mb > 0 ? 'watchdog' : 'none',
      },
      process_group: posix,
    },
  };
}

/** What a strict sandbox requires but this host can't provide. */
export function missingForStrict(report: IsolationReport, network: NetworkPolicy): string[] {
  const missing: string[] = [];
  if (!network.allow_outbound && report.network !== 'blocked') missing.push('network isolation');
  if (report.filesystem !== 'restricted') missing.push('filesystem isolation');
  if (report.limits.memory === 'none') missing.push('memory limit');
  return missing;
}

// ─── Memory watchdog ────────────────────────────────────────────

/** Sum RSS (MB) of every process in a process group. */
export function groupRssMb(pgid: number): number {
  try {
    const out = execFileSync('ps', ['-A', '-o', 'pgid=,rss='], { encoding: 'utf8', timeout: 2000 });
    let kb = 0;
    for (const line of out.split('\n')) {
      const [g, rss] = line.trim().split(/\s+/).map(Number);
      if (g === pgid && Number.isFinite(rss)) kb += rss;
    }
    return kb / 1024;
  } catch {
    return 0;
  }
}

/**
 * Poll the group's memory; call onExceed (once) when it passes the limit.
 * Returns a stop function that yields the peak observed RSS in MB.
 */
export function startMemoryWatchdog(pgid: number, limitMb: number, onExceed: (rssMb: number) => void, intervalMs = 100): () => number {
  let peak = 0;
  let fired = false;
  const timer = setInterval(() => {
    const rss = groupRssMb(pgid);
    peak = Math.max(peak, rss);
    if (!fired && limitMb > 0 && rss > limitMb) {
      fired = true;
      onExceed(rss);
    }
  }, intervalMs);
  timer.unref();
  return () => {
    clearInterval(timer);
    return Math.round(peak * 10) / 10;
  };
}
