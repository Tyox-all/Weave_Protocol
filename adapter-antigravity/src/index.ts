/**
 * @weave_protocol/adapter-antigravity - public API
 */

export * from './types.js';
export {
  installHook,
  removeHook,
  readSettings,
  writeSettings,
  isHookInstalled,
  antigravitySettingsPath,
  antigravityConfigDir,
  userWardPath,
  WARD_HOOK_MARKER,
} from './config.js';
export type { AntigravitySettings, InstallOptions } from './config.js';
export {
  resolveWardForCwd,
  evaluateCall,
  runPreToolUseHook,
} from './hook.js';
export type { ResolvedWard, HookDecision } from './hook.js';
