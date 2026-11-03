/**
 * @weave_protocol/adapter-codex — WARD.md enforcement for OpenAI Codex CLI.
 */

export * from './types.js';
export { patchTargets } from './patch.js';
export type { PatchTargets } from './patch.js';
export {
  STATUS_MESSAGE,
  codexHome,
  hooksJsonPath,
  userWardPath,
  readHooks,
  writeHooks,
  installHook,
  removeHook,
  isHookInstalled,
} from './config.js';
export type { HooksFile, InstallOptions } from './config.js';
export { resolveWardForCwd, evaluateCall, toHookOutput } from './hook.js';
export type { ResolvedWard, HookDecision } from './hook.js';
