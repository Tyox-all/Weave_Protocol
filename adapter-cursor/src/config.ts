/**
 * Manage ~/.cursor/hooks.json — install, remove, inspect the WARD hook on
 * the four events it handles. Cursor reloads hooks.json on save.
 *
 * Safety rules:
 *  - Back up hooks.json before changing it, and write atomically
 *  - Idempotent: init twice leaves one entry per event
 *  - Our entries are found by their command; other hooks are untouched
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync, copyFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';
import { EVENTS, type CursorHookEntry } from './types.js';

export function cursorDir(): string {
  return join(homedir(), '.cursor');
}

export function hooksJsonPath(): string {
  return join(cursorDir(), 'hooks.json');
}

/** User-global WARD.md, used when a project has none. */
export function userWardPath(): string {
  return join(cursorDir(), 'WARD.md');
}

export interface HooksFile {
  version?: number;
  hooks?: Record<string, CursorHookEntry[] | undefined>;
  [other: string]: unknown;
}

export function readHooks(path = hooksJsonPath()): HooksFile {
  if (!existsSync(path)) return {};
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as HooksFile;
  } catch (err) {
    throw new Error(
      `Failed to parse ${path}; fix the JSON or move it aside and re-run. ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

export function writeHooks(file: HooksFile, path = hooksJsonPath()): void {
  mkdirSync(dirname(path), { recursive: true });
  if (existsSync(path)) copyFileSync(path, `${path}.weave-backup`);
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, JSON.stringify(file, null, 2) + '\n', 'utf8');
  renameSync(tmp, path);
}

/** The command marker: our entries run "<binary> hook". */
const HOOK_ARGS = ' hook';

export interface InstallOptions {
  /** Command that runs this CLI. Default: "weave-ward-cursor" */
  binary?: string;
  /** Hook timeout in seconds. Default 10 */
  timeoutSeconds?: number;
  /** Deny on malformed payloads and evaluator errors. Default: allow */
  failClosed?: boolean;
}

/** Our entries: the published bin, or this package's built CLI run by path. */
const anyOurs = (e: CursorHookEntry) =>
  typeof e.command === 'string' && /(^|[\s/])weave-ward-cursor hook\b|adapter-cursor\/dist\/cli\.js hook\b/.test(e.command);

export function isHookInstalled(file: HooksFile = readHooks()): boolean {
  return EVENTS.every((ev) => (file.hooks?.[ev] ?? []).some(anyOurs));
}

export function installHook(opts: InstallOptions = {}): HooksFile {
  const binary = opts.binary ?? 'weave-ward-cursor';
  const file = readHooks();
  file.version ??= 1;
  const hooks = (file.hooks ??= {});
  const command = `${binary}${HOOK_ARGS}${opts.failClosed ? ' --fail-closed' : ''}`;
  for (const ev of EVENTS) {
    const keep = (hooks[ev] ?? []).filter((e) => !anyOurs(e));
    hooks[ev] = [...keep, { command, timeout: opts.timeoutSeconds ?? 10 }];
  }
  writeHooks(file);
  return file;
}

export function removeHook(): { removed: number; file: HooksFile } {
  const file = readHooks();
  let removed = 0;
  for (const ev of EVENTS) {
    const before = file.hooks?.[ev];
    if (!before) continue;
    const after = before.filter((e) => !anyOurs(e));
    removed += before.length - after.length;
    if (after.length) file.hooks![ev] = after;
    else delete file.hooks![ev];
  }
  if (removed > 0) writeHooks(file);
  return { removed, file };
}
