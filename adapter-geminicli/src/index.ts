/**
 * @weave_protocol/adapter-geminicli — WARD.md enforcement for Gemini CLI.
 */

export * from './types.js';
export {
  HOOK_NAME,
  geminiConfigDir,
  geminiSettingsPath,
  userWardPath,
  readSettings,
  writeSettings,
  installHook,
  removeHook,
  isHookInstalled,
} from './config.js';
export type { GeminiSettings, InstallOptions } from './config.js';
export { resolveWardForCwd, evaluateCall, normalizeInput, toHookOutput } from './hook.js';
export type { ResolvedWard, HookDecision } from './hook.js';
