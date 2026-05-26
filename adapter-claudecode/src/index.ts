/**
 * @weave_protocol/adapter-claudecode - public API
 */

export * from './types.js';
export {
  installHook,
  removeHook,
  readSettings,
  writeSettings,
  isHookInstalled,
  claudeSettingsPath,
  claudeConfigDir,
  userWardPath,
  WARD_HOOK_MARKER,
} from './config.js';
export type { ClaudeSettings, InstallOptions } from './config.js';
export {
  resolveWardForCwd,
  evaluateCall,
  runPreToolUseHook,
} from './hook.js';
export type { ResolvedWard, HookDecision } from './hook.js';
