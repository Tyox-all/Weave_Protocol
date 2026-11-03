/**
 * @weave_protocol/adapter-cursor — WARD.md enforcement for Cursor's agent hooks.
 */

export * from './types.js';
export {
  cursorDir,
  hooksJsonPath,
  userWardPath,
  readHooks,
  writeHooks,
  installHook,
  removeHook,
  isHookInstalled,
} from './config.js';
export type { HooksFile, InstallOptions } from './config.js';
export { resolveWardForRoot, toToolCall, evaluateCall, toHookOutput } from './hook.js';
export type { ResolvedWard, HookDecision, ToolCall } from './hook.js';
