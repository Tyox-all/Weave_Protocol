/**
 * @weave_protocol/adapter-trae — WARD.md enforcement for TRAE.
 */

export * from './types.js';
export {
  HOOK_NAME,
  configDir,
  hooksConfigPath,
  userWardPath,
  readSettings,
  writeSettings,
  installHook,
  removeHook,
  isHookInstalled,
} from './config.js';
export type { HookSettings, InstallOptions } from './config.js';
export { resolveWardForCwd, evaluateCall, normalizeInput, toHookOutput } from './hook.js';
export type { ResolvedWard, HookDecision } from './hook.js';
