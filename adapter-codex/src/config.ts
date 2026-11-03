/**
 * Manage $CODEX_HOME/hooks.json (default ~/.codex/hooks.json) — install,
 * remove, inspect the WARD hook.
 *
 * Safety rules:
 *  - Back up hooks.json before changing it, and write atomically
 *  - Idempotent: init twice leaves one entry
 *  - Our entry is found by its statusMessage; other hooks are untouched
 *
 * Codex skips new or changed hooks until they are trusted: after init, run
 * /hooks in Codex and trust the Weave hook.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync, copyFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { homedir } from 'node:os';
import type { CodexHookGroup } from './types.js';

export const STATUS_MESSAGE = 'Weave: checking WARD.md';

export function codexHome(): string {
  return process.env.CODEX_HOME ? resolve(process.env.CODEX_HOME) : join(homedir(), '.codex');
}

export function hooksJsonPath(): string {
  return join(codexHome(), 'hooks.json');
}

/** User-global WARD.md, used when a project has none. */
export function userWardPath(): string {
  return join(codexHome(), 'WARD.md');
}

export interface HooksFile {
  description?: string;
  hooks?: {
    PreToolUse?: CodexHookGroup[];
    [event: string]: CodexHookGroup[] | undefined;
  };
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

export interface InstallOptions {
  /** Command that runs this CLI. Default: "weave-ward-codex" */
  binary?: string;
  /** Regex of tool names to gate. Default: every tool */
  matcher?: string;
  /** Hook timeout in seconds (Codex's unit). Default 10 */
  timeoutSeconds?: number;
  /** Deny on malformed payloads and evaluator errors. Default: allow */
  failClosed?: boolean;
}

const ours = (g: CodexHookGroup) => g.hooks?.some((h) => h.statusMessage === STATUS_MESSAGE);

export function isHookInstalled(file: HooksFile = readHooks()): boolean {
  return (file.hooks?.PreToolUse ?? []).some(ours);
}

export function installHook(opts: InstallOptions = {}): HooksFile {
  const file = readHooks();
  const command = `${opts.binary ?? 'weave-ward-codex'} hook pre-tool-use${opts.failClosed ? ' --fail-closed' : ''}`;
  const group: CodexHookGroup = {
    matcher: opts.matcher ?? '*',
    hooks: [{ type: 'command', command, timeout: opts.timeoutSeconds ?? 10, statusMessage: STATUS_MESSAGE }],
  };
  const hooks = (file.hooks ??= {});
  hooks.PreToolUse = [...(hooks.PreToolUse ?? []).filter((g) => !ours(g)), group];
  writeHooks(file);
  return file;
}

export function removeHook(): { removed: number; file: HooksFile } {
  const file = readHooks();
  const before = file.hooks?.PreToolUse ?? [];
  const after = before.filter((g) => !ours(g));
  const removed = before.length - after.length;
  if (removed > 0 && file.hooks) {
    if (after.length) file.hooks.PreToolUse = after;
    else delete file.hooks.PreToolUse;
    writeHooks(file);
  }
  return { removed, file };
}
