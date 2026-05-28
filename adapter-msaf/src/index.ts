/**
 * @weave_protocol/adapter-msaf — public API
 *
 * Primary export: WardMiddleware class.
 * Plus: types, policy loader, evaluator.
 */

export { WardMiddleware } from './middleware.js';
export {
  TOOL_MAPPINGS,
  WardDeniedError,
} from './types.js';
export type {
  ToolMapping,
  MsafToolCall,
  MsafMiddlewareResult,
  MiddlewareOptions,
} from './types.js';
export {
  resolveWardForCwd,
  loadWardFromSource,
  evaluateCall,
} from './policy.js';
export type { ResolvedWard } from './policy.js';
