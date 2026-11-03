/**
 * Add or remove the plugin in OpenCode's global opencode.json
 * ($XDG_CONFIG_HOME/opencode/opencode.json, default ~/.config/opencode).
 * OpenCode installs npm plugins listed there on startup.
 *
 * Safety rules:
 *  - Back up opencode.json before changing it, and write atomically
 *  - Idempotent: init twice leaves one entry
 *  - Other plugins and settings are untouched
 *  - opencode.jsonc (JSON with comments) is never rewritten: we'd lose the
 *    comments, so init says what to add instead
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync, copyFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { opencodeConfigDir } from './policy.js';

export const PACKAGE = '@weave_protocol/adapter-opencode';

export function opencodeJsonPath(): string {
  return join(opencodeConfigDir(), 'opencode.json');
}

export function opencodeJsoncPath(): string {
  return join(opencodeConfigDir(), 'opencode.jsonc');
}

export interface OpencodeConfig {
  $schema?: string;
  plugin?: Array<string | [string, unknown]>;
  [other: string]: unknown;
}

export function readConfig(path = opencodeJsonPath()): OpencodeConfig {
  if (!existsSync(path)) return {};
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as OpencodeConfig;
  } catch (err) {
    throw new Error(
      `Failed to parse ${path}; fix the JSON or move it aside and re-run. ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

export function writeConfig(config: OpencodeConfig, path = opencodeJsonPath()): void {
  mkdirSync(dirname(path), { recursive: true });
  if (existsSync(path)) copyFileSync(path, `${path}.weave-backup`);
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, JSON.stringify(config, null, 2) + '\n', 'utf8');
  renameSync(tmp, path);
}

const entryName = (e: string | [string, unknown]) => (Array.isArray(e) ? e[0] : e);
const isOurs = (e: string | [string, unknown]) => {
  const name = entryName(e);
  return name === PACKAGE || name.startsWith(`${PACKAGE}@`);
};

export function isPluginInstalled(config: OpencodeConfig = readConfig()): boolean {
  return (config.plugin ?? []).some(isOurs);
}

/** Add the plugin to opencode.json. Throws if only an opencode.jsonc exists. */
export function installPlugin(spec = PACKAGE): OpencodeConfig {
  if (!existsSync(opencodeJsonPath()) && existsSync(opencodeJsoncPath())) {
    throw new Error(`${opencodeJsoncPath()} has comments we won't rewrite. Add "${spec}" to its "plugin" list by hand.`);
  }
  const config = readConfig();
  config.$schema ??= 'https://opencode.ai/config.json';
  config.plugin = [...(config.plugin ?? []).filter((e) => !isOurs(e)), spec];
  writeConfig(config);
  return config;
}

export function removePlugin(): { removed: number; config: OpencodeConfig } {
  const config = readConfig();
  const before = config.plugin ?? [];
  const after = before.filter((e) => !isOurs(e));
  const removed = before.length - after.length;
  if (removed > 0) {
    if (after.length) config.plugin = after;
    else delete config.plugin;
    writeConfig(config);
  }
  return { removed, config };
}
