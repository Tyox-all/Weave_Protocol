/**
 * Manage ~/.qwen/settings.json — install, remove, inspect the WARD hook.
 *
 * Safety rules:
 *  - Back up settings.json before changing it, and write atomically
 *  - Idempotent: init twice leaves one entry
 *  - Our entry is found by its hook name; other hooks and keys are untouched
 *
 * Installed at user level (~/.qwen/settings.json), so it applies to every
 * project. Qwen Code has no per-hook description field; unknown fields are
 * left out.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync, copyFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';
import type { QwenHookEntry } from './types.js';

export const HOOK_NAME = 'weave-ward';

export function qwenConfigDir(): string {
  return join(homedir(), '.qwen');
}

export function qwenSettingsPath(): string {
  return join(qwenConfigDir(), 'settings.json');
}

/** User-global WARD.md, used when a project has none. */
export function userWardPath(): string {
  return join(qwenConfigDir(), 'WARD.md');
}

export interface QwenSettings {
  hooks?: {
    PreToolUse?: QwenHookEntry[];
    [event: string]: QwenHookEntry[] | unknown;
  };
  [other: string]: unknown;
}

export function readSettings(path = qwenSettingsPath()): QwenSettings {
  if (!existsSync(path)) return {};
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as QwenSettings;
  } catch (err) {
    throw new Error(
      `Failed to parse ${path}; fix the JSON or move it aside and re-run. ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

export function writeSettings(settings: QwenSettings, path = qwenSettingsPath()): void {
  mkdirSync(dirname(path), { recursive: true });
  if (existsSync(path)) copyFileSync(path, `${path}.weave-backup`);
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, JSON.stringify(settings, null, 2) + '\n', 'utf8');
  renameSync(tmp, path);
}

export interface InstallOptions {
  /** Command that runs this CLI. Default: "weave-qwen" */
  binary?: string;
  /** Regex of tool names to gate. Default: every tool */
  matcher?: string;
  /** Hook timeout in seconds (Qwen Code's unit). Default 10 */
  timeoutSeconds?: number;
  /** Deny on malformed payloads and evaluator errors. Default: allow */
  failClosed?: boolean;
}

const ours = (e: QwenHookEntry) => e.hooks?.some((h) => h.name === HOOK_NAME);

export function isHookInstalled(settings: QwenSettings = readSettings()): boolean {
  return (settings.hooks?.PreToolUse ?? []).some(ours);
}

export function installHook(opts: InstallOptions = {}): QwenSettings {
  const settings = readSettings();
  const command = `${opts.binary ?? 'weave-qwen'} hook pre-tool-use${opts.failClosed ? ' --fail-closed' : ''}`;
  const entry: QwenHookEntry = {
    matcher: opts.matcher ?? '.*',
    hooks: [{
      type: 'command',
      name: HOOK_NAME,
      command,
      timeout: opts.timeoutSeconds ?? 10,
    }],
  };
  const hooks = (settings.hooks ??= {});
  hooks.PreToolUse = [...(hooks.PreToolUse ?? []).filter((e) => !ours(e)), entry];
  writeSettings(settings);
  return settings;
}

export function removeHook(): { removed: number; settings: QwenSettings } {
  const settings = readSettings();
  const before = settings.hooks?.PreToolUse ?? [];
  const after = before.filter((e) => !ours(e));
  const removed = before.length - after.length;
  if (removed > 0 && settings.hooks) {
    if (after.length) settings.hooks.PreToolUse = after;
    else delete settings.hooks.PreToolUse;
    writeSettings(settings);
  }
  return { removed, settings };
}
