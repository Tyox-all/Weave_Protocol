/**
 * Manage ~/.gemini/antigravity-cli/settings.json — install, remove,
 * inspect the WARD hook.
 *
 * Safety rules:
 *  - Always back up existing settings.json before modifying
 *  - Use atomic writes (write to .tmp then rename)
 *  - Idempotent: running `init` twice doesn't duplicate hook entries
 *  - Preserve unknown keys (other hooks, other config) untouched
 */

import {
  readFileSync,
  writeFileSync,
  existsSync,
  mkdirSync,
  renameSync,
  copyFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { homedir } from 'node:os';
import type { AntigravitySettingsHooksEntry } from './types.js';

// ============================================================================
// Paths
// ============================================================================

export function antigravityConfigDir(): string {
  return process.env.ANTIGRAVITY_CONFIG_DIR
    ? resolve(process.env.ANTIGRAVITY_CONFIG_DIR)
    : join(homedir(), '.gemini', 'antigravity-cli');
}

export function antigravitySettingsPath(): string {
  return join(antigravityConfigDir(), 'settings.json');
}

export function userWardPath(): string {
  return join(antigravityConfigDir(), 'WARD.md');
}

// ============================================================================
// Read / write
// ============================================================================

export interface AntigravitySettings {
  hooks?: {
    PreToolUse?: AntigravitySettingsHooksEntry[];
    PostToolUse?: AntigravitySettingsHooksEntry[];
    Stop?: AntigravitySettingsHooksEntry[];
    SessionStart?: AntigravitySettingsHooksEntry[];
    [other: string]: AntigravitySettingsHooksEntry[] | undefined;
  };
  [other: string]: unknown;
}

export function readSettings(): AntigravitySettings {
  const path = antigravitySettingsPath();
  if (!existsSync(path)) return {};
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as AntigravitySettings;
  } catch (err) {
    throw new Error(
      `Failed to parse ${path} — please fix the JSON syntax or back it up and re-run. Original: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
}

export function writeSettings(settings: AntigravitySettings): void {
  const path = antigravitySettingsPath();
  mkdirSync(dirname(path), { recursive: true });

  // Backup existing
  if (existsSync(path)) {
    const backup = `${path}.weave-backup`;
    copyFileSync(path, backup);
  }

  // Atomic write
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, JSON.stringify(settings, null, 2) + '\n', 'utf8');
  renameSync(tmp, path);
}

// ============================================================================
// Hook install / remove
// ============================================================================

/**
 * Unique tag in the hook command so we can find and remove our own entries
 * without touching hooks the user added manually.
 */
export const WARD_HOOK_MARKER = '# WEAVE_WARD_HOOK';

export interface InstallOptions {
  /** Path to the weave-antigravity binary. Defaults to "weave-antigravity". */
  binary?: string;
  /** Restrict the hook to specific tool names. Default: all tools. */
  toolMatcher?: string;
  /** Hook timeout in seconds. */
  timeoutSeconds?: number;
  /** Block on error or fail-open? Default: fail-open (false). */
  failClosed?: boolean;
}

// ============================================================================
// hooks.json (Antigravity's real hook config)
// ============================================================================

/**
 * Antigravity reads hooks from ~/.gemini/config/hooks.json (global) or
 * <workspace>/.agents/hooks.json, as named hooks:
 *   { "<name>": { "enabled": true, "PreToolUse": [{ "matcher", "hooks": [...] }] } }
 * (https://antigravity.google/docs/hooks)
 */
export function hooksJsonPath(opts: { workspace?: string } = {}): string {
  if (opts.workspace) return join(resolve(opts.workspace), '.agents', 'hooks.json');
  const base = process.env.ANTIGRAVITY_GLOBAL_CONFIG_DIR
    ? resolve(process.env.ANTIGRAVITY_GLOBAL_CONFIG_DIR)
    : join(homedir(), '.gemini', 'config');
  return join(base, 'hooks.json');
}

export function readHooksJson(path: string): Record<string, unknown> {
  if (!existsSync(path)) return {};
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
  } catch (err) {
    throw new Error(`Failed to parse ${path}; fix the JSON or move it aside. ${err instanceof Error ? err.message : String(err)}`);
  }
}

export function writeHooksJson(path: string, config: Record<string, unknown>): void {
  mkdirSync(dirname(path), { recursive: true });
  if (existsSync(path)) copyFileSync(path, `${path}.weave-backup`);
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, JSON.stringify(config, null, 2) + '\n', 'utf8');
  renameSync(tmp, path);
}

/** Name of the WARD hook inside hooks.json. */
export const WARD_HOOK_NAME = 'weave-ward';

export function isHookInstalled(opts: { workspace?: string } = {}): boolean {
  return WARD_HOOK_NAME in readHooksJson(hooksJsonPath(opts));
}

/** True if a pre-0.2 WARD entry is still sitting in the old settings.json. */
export function isLegacyHookInstalled(): boolean {
  try {
    return (readSettings().hooks?.PreToolUse ?? []).some((e) =>
      e.hooks?.some((h) => h.command?.includes(WARD_HOOK_MARKER) ?? false),
    );
  } catch {
    return false;
  }
}

/** Remove pre-0.2 WARD entries from ~/.gemini/antigravity-cli/settings.json. */
export function removeLegacyHook(): number {
  if (!existsSync(antigravitySettingsPath())) return 0;
  const settings = readSettings();
  if (!settings.hooks?.PreToolUse) return 0;
  const before = settings.hooks.PreToolUse.length;
  settings.hooks.PreToolUse = settings.hooks.PreToolUse.filter(
    (e) => !e.hooks?.some((h) => h.command?.includes(WARD_HOOK_MARKER) ?? false),
  );
  const removed = before - settings.hooks.PreToolUse.length;
  if (removed > 0) writeSettings(settings);
  return removed;
}

export function installHook(opts: InstallOptions & { workspace?: string } = {}): { path: string; migrated: number } {
  const path = hooksJsonPath(opts);
  const config = readHooksJson(path);
  const binary = opts.binary || 'weave-antigravity';
  const failFlag = opts.failClosed ? ' --fail-closed' : '';
  config[WARD_HOOK_NAME] = {
    enabled: true,
    PreToolUse: [
      {
        matcher: opts.toolMatcher || '*',
        hooks: [{ type: 'command', command: `${binary} hook pre-tool-use${failFlag}`, timeout: opts.timeoutSeconds ?? 5 }],
      },
    ],
  };
  writeHooksJson(path, config);
  return { path, migrated: removeLegacyHook() };
}

export function removeHook(opts: { workspace?: string } = {}): { removed: number; path: string } {
  const path = hooksJsonPath(opts);
  const config = readHooksJson(path);
  let removed = 0;
  if (WARD_HOOK_NAME in config) {
    delete config[WARD_HOOK_NAME];
    writeHooksJson(path, config);
    removed++;
  }
  removed += removeLegacyHook();
  return { removed, path };
}
