/**
 * @weave_protocol/adapter-qwencode — WARD.md enforcement for Qwen Code.
 */

export * from './types.js';
export {
  HOOK_NAME,
  qwenConfigDir,
  qwenSettingsPath,
  userWardPath,
  readSettings,
  writeSettings,
  installHook,
  removeHook,
  isHookInstalled,
} from './config.js';
export type { QwenSettings, InstallOptions } from './config.js';
export { resolveWardForCwd, evaluateCall, normalizeInput, toHookOutput } from './hook.js';
export type { ResolvedWard, HookDecision } from './hook.js';
