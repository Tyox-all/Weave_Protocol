/**
 * Manage ~/.gemini/settings.json — install, remove, inspect the WARD hook.
 *
 * Safety rules:
 *  - Back up settings.json before changing it, and write atomically
 *  - Idempotent: init twice leaves one entry
 *  - Our entry is found by its hook name; other hooks and keys are untouched
 *
 * Installed at user level. Gemini CLI fingerprints project-level hooks and
 * warns when they change; a user-level hook applies to every project.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync, copyFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';
import type { GeminiHookEntry } from './types.js';

export const HOOK_NAME = 'weave-ward';

export function geminiConfigDir(): string {
  return join(homedir(), '.gemini');
}

export function geminiSettingsPath(): string {
  return join(geminiConfigDir(), 'settings.json');
}

/** User-global WARD.md, used when a project has none. */
export function userWardPath(): string {
  return join(geminiConfigDir(), 'WARD.md');
}

export interface GeminiSettings {
  hooks?: {
    BeforeTool?: GeminiHookEntry[];
    [event: string]: GeminiHookEntry[] | unknown;
  };
  [other: string]: unknown;
}

export function readSettings(path = geminiSettingsPath()): GeminiSettings {
  if (!existsSync(path)) return {};
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as GeminiSettings;
  } catch (err) {
    throw new Error(
      `Failed to parse ${path}; fix the JSON or move it aside and re-run. ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

export function writeSettings(settings: GeminiSettings, path = geminiSettingsPath()): void {
  mkdirSync(dirname(path), { recursive: true });
  if (existsSync(path)) copyFileSync(path, `${path}.weave-backup`);
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, JSON.stringify(settings, null, 2) + '\n', 'utf8');
  renameSync(tmp, path);
}

export interface InstallOptions {
  /** Command that runs this CLI. Default: "weave-gemini" */
  binary?: string;
  /** Regex of tool names to gate. Default: every tool */
  matcher?: string;
  /** Hook timeout in milliseconds (Gemini CLI's unit). Default 5000 */
  timeoutMs?: number;
  /** Deny on malformed payloads and evaluator errors. Default: allow */
  failClosed?: boolean;
}

const ours = (e: GeminiHookEntry) => e.hooks?.some((h) => h.name === HOOK_NAME);

export function isHookInstalled(settings: GeminiSettings = readSettings()): boolean {
  return (settings.hooks?.BeforeTool ?? []).some(ours);
}

export function installHook(opts: InstallOptions = {}): GeminiSettings {
  const settings = readSettings();
  const command = `${opts.binary ?? 'weave-gemini'} hook before-tool${opts.failClosed ? ' --fail-closed' : ''}`;
  const entry: GeminiHookEntry = {
    matcher: opts.matcher ?? '.*',
    hooks: [{
      type: 'command',
      name: HOOK_NAME,
      command,
      timeout: opts.timeoutMs ?? 5000,
      description: 'Weave Protocol: enforce WARD.md on every tool call',
    }],
  };
  const hooks = (settings.hooks ??= {});
  hooks.BeforeTool = [...(hooks.BeforeTool ?? []).filter((e) => !ours(e)), entry];
  writeSettings(settings);
  return settings;
}

export function removeHook(): { removed: number; settings: GeminiSettings } {
  const settings = readSettings();
  const before = settings.hooks?.BeforeTool ?? [];
  const after = before.filter((e) => !ours(e));
  const removed = before.length - after.length;
  if (removed > 0 && settings.hooks) {
    if (after.length) settings.hooks.BeforeTool = after;
    else delete settings.hooks.BeforeTool;
    writeSettings(settings);
  }
  return { removed, settings };
}
