/**
 * Helpers behind the OpenCode plugin ("@weave_protocol/adapter-opencode/lib").
 * The package's main entry exports only the plugin, as OpenCode requires.
 */

export { TOOL_MAPPINGS, opencodeConfigDir, resolveWard, evaluateCall, blockMessage } from './policy.js';
export type { ResolvedWard, WardDecision } from './policy.js';
export { patchTargets } from './patch.js';
export type { PatchTargets } from './patch.js';
export {
  PACKAGE,
  opencodeJsonPath,
  opencodeJsoncPath,
  readConfig,
  writeConfig,
  installPlugin,
  removePlugin,
  isPluginInstalled,
} from './config.js';
export type { OpencodeConfig } from './config.js';
