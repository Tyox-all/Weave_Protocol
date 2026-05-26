/**
 * Manage ~/.claude/settings.json — install, remove, inspect the WARD hook.
 *
 * Safety rules:
 *  - Always back up existing settings.json before modifying
 *  - Use atomic writes (write to .tmp then rename)
 *  - Idempotent: running `init` twice doesn't duplicate hook entries
 *  - Preserve unknown keys (other hooks, other config) untouched
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync, copyFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { homedir } from 'node:os';
import type { ClaudeSettingsHooksEntry } from './types.js';

// ============================================================================
// Paths
// ============================================================================

export function claudeConfigDir(): string {
  return process.env.CLAUDE_CONFIG_DIR
    ? resolve(process.env.CLAUDE_CONFIG_DIR)
    : join(homedir(), '.claude');
}

export function claudeSettingsPath(): string {
  return join(claudeConfigDir(), 'settings.json');
}

export function userWardPath(): string {
  return join(claudeConfigDir(), 'WARD.md');
}

// ============================================================================
// Read / write
// ============================================================================

export interface ClaudeSettings {
  hooks?: {
    PreToolUse?: ClaudeSettingsHooksEntry[];
    PostToolUse?: ClaudeSettingsHooksEntry[];
    Stop?: ClaudeSettingsHooksEntry[];
    SessionStart?: ClaudeSettingsHooksEntry[];
    [other: string]: ClaudeSettingsHooksEntry[] | undefined;
  };
  [other: string]: unknown;
}

export function readSettings(): ClaudeSettings {
  const path = claudeSettingsPath();
  if (!existsSync(path)) return {};
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as ClaudeSettings;
  } catch (err) {
    throw new Error(
      `Failed to parse ${path} — please fix the JSON syntax or back it up and re-run. Original: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
}

export function writeSettings(settings: ClaudeSettings): void {
  const path = claudeSettingsPath();
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
 * The unique tag we put inside the hook command so we can find and remove
 * our own entries without affecting hooks the user added manually.
 */
export const WARD_HOOK_MARKER = '# WEAVE_WARD_HOOK';

export interface InstallOptions {
  /** Path to the weave-claude-code binary. Defaults to "weave-claude-code". */
  binary?: string;
  /** Restrict the hook to specific tool names. Default: all tools. */
  toolMatcher?: string;
  /** Hook timeout in seconds. */
  timeoutSeconds?: number;
  /** Block on error or fail-open? Default: fail-open (false). */
  failClosed?: boolean;
}

export function isHookInstalled(settings: ClaudeSettings): boolean {
  const entries = settings.hooks?.PreToolUse || [];
  return entries.some((e) =>
    e.hooks?.some((h) => h.command.includes(WARD_HOOK_MARKER)),
  );
}

export function installHook(opts: InstallOptions = {}): ClaudeSettings {
  const settings = readSettings();
  const binary = opts.binary || 'weave-claude-code';
  const matcher = opts.toolMatcher || '*';
  const failFlag = opts.failClosed ? ' --fail-closed' : '';

  // Construct the command with our marker
  const command = `${binary} hook pre-tool-use${failFlag} ${WARD_HOOK_MARKER}`;

  const entry: ClaudeSettingsHooksEntry = {
    matcher,
    hooks: [
      {
        type: 'command',
        command,
        timeout: opts.timeoutSeconds ?? 5,
      },
    ],
  };

  if (!settings.hooks) settings.hooks = {};
  if (!settings.hooks.PreToolUse) settings.hooks.PreToolUse = [];

  // Remove any existing WARD entries first (idempotent)
  settings.hooks.PreToolUse = settings.hooks.PreToolUse.filter(
    (e) => !e.hooks?.some((h) => h.command.includes(WARD_HOOK_MARKER)),
  );

  // Add our new entry
  settings.hooks.PreToolUse.push(entry);

  writeSettings(settings);
  return settings;
}

export function removeHook(): { removed: number; settings: ClaudeSettings } {
  const settings = readSettings();
  if (!settings.hooks?.PreToolUse) return { removed: 0, settings };

  const before = settings.hooks.PreToolUse.length;
  settings.hooks.PreToolUse = settings.hooks.PreToolUse.filter(
    (e) => !e.hooks?.some((h) => h.command.includes(WARD_HOOK_MARKER)),
  );
  const removed = before - settings.hooks.PreToolUse.length;

  if (removed > 0) writeSettings(settings);
  return { removed, settings };
}
