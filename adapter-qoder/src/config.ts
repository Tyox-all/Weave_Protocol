/**
 * Manage Qoder CLI's hook config: install, remove, inspect the WARD hook.
 *
 * Safety rules:
 *  - Back up the file before changing it, and write atomically
 *  - Idempotent: init twice leaves one entry
 *  - Our entry is found by its command (`weave-qoder hook …`); other hooks and
 *    keys are untouched
 *
 * Installed at user level (~/.qoder/settings.json), so it applies to every project.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync, copyFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';
import type { HookEntry } from './types.js';

/** Our hook's command starts with this, which is how we find our entry. */
export const HOOK_NAME = 'weave-qoder hook';

export function configDir(): string {
  return join(homedir(), '.qoder');
}

export function configDirs(): string[] {
  return [configDir()];
}

export function hooksConfigPath(dir = configDir()): string {
  return join(dir, 'settings.json');
}

/** User-global WARD.md, used when a project has none. */
export function userWardPath(): string {
  return join(configDir(), 'WARD.md');
}

export interface HookSettings {
  hooks?: {
    PreToolUse?: HookEntry[];
    [event: string]: HookEntry[] | unknown;
  };
  [other: string]: unknown;
}

export function readSettings(path = hooksConfigPath()): HookSettings {
  if (!existsSync(path)) return {};
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as HookSettings;
  } catch (err) {
    throw new Error(
      `Failed to parse ${path}; fix the JSON or move it aside and re-run. ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

export function writeSettings(settings: HookSettings, path = hooksConfigPath()): void {
  mkdirSync(dirname(path), { recursive: true });
  if (existsSync(path)) copyFileSync(path, `${path}.weave-backup`);
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, JSON.stringify(settings, null, 2) + '\n', 'utf8');
  renameSync(tmp, path);
}

export interface InstallOptions {
  /** Command that runs this CLI. Default: "weave-qoder" */
  binary?: string;
  /** Regex of tool names to gate. Default: every tool */
  matcher?: string;
  /** Hook timeout in seconds. Default 10 */
  timeoutSeconds?: number;
  /** Deny on malformed payloads and evaluator errors. Default: allow */
  failClosed?: boolean;
}

const ours = (e: HookEntry) => e.hooks?.some((h) => typeof h.command === 'string' && h.command.includes(HOOK_NAME));

export function isHookInstalled(settings: HookSettings = readSettings()): boolean {
  return (settings.hooks?.PreToolUse ?? []).some(ours);
}

/** Install in every config folder; returns the files written. */
export function installHook(opts: InstallOptions = {}): string[] {
  const command = `${opts.binary ?? 'weave-qoder'} hook pre-tool-use${opts.failClosed ? ' --fail-closed' : ''}`;
  const written: string[] = [];
  for (const dir of configDirs()) {
    const path = hooksConfigPath(dir);
    const settings = readSettings(path);
    const entry: HookEntry = { matcher: opts.matcher ?? '.*', hooks: [{ type: 'command' as const, command, timeout: opts.timeoutSeconds ?? 10 }] };
    const hooks = (settings.hooks ??= {});
    hooks.PreToolUse = [...((hooks.PreToolUse as HookEntry[] | undefined) ?? []).filter((e) => !ours(e)), entry];
    writeSettings(settings, path);
    written.push(path);
  }
  return written;
}

export function removeHook(): { removed: number } {
  let removed = 0;
  for (const dir of configDirs()) {
    const path = hooksConfigPath(dir);
    if (!existsSync(path)) continue;
    const settings = readSettings(path);
    const before = (settings.hooks?.PreToolUse as HookEntry[] | undefined) ?? [];
    const after = before.filter((e) => !ours(e));
    if (after.length !== before.length && settings.hooks) {
      removed += before.length - after.length;
      if (after.length) settings.hooks.PreToolUse = after;
      else delete settings.hooks.PreToolUse;
      writeSettings(settings, path);
    }
  }
  return { removed };
}
