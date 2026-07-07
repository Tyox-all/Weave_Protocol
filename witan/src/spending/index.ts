/**
 * @weave_protocol/witan/spending — Autonomous Spending Caps.
 *
 * Public API:
 *   - SpendingTracker: the enforcement class
 *   - SpendingStore, InMemorySpendingStore: storage interface + default impl
 *   - LLM_PRICING, registerPricing, estimateLLMCost, lookupPricing
 *   - parseSpendingCapsFromWard, loadSpendingCapsFromWardFile
 *   - interactiveApprovalHandler, denyByDefaultHandler
 *   - Types: SpendingCap, CapBudget, ToolBudget, ProposedAction,
 *            CapCheck, CapViolation, WindowUsage, etc.
 */

export { SpendingTracker } from './tracker.js';
export { InMemorySpendingStore } from './store.js';
export type { SpendingStore } from './store.js';
export {
  LLM_PRICING,
  lookupPricing,
  registerPricing,
  estimateLLMCost,
  type Price,
} from './pricing.js';
export { parseSpendingCapsFromWard, loadSpendingCapsFromWardFile } from './ward-integration.js';
export {
  interactiveApprovalHandler,
  denyByDefaultHandler,
  resolveHandler,
  type ApprovalHandler,
} from './approval.js';
export { windowKey, currentRunId } from './windows.js';
export type {
  SpendingWindow,
  CapAction,
  CapBudget,
  ToolBudget,
  SpendingCap,
  ProposedLLMCall,
  ProposedToolCall,
  ProposedAction,
  CapViolation,
  CapCheck,
  LLMUsageRecord,
  ToolCallRecord,
  WindowUsage,
  PendingApprovalEvent,
  NotifyEvent,
  SpendingTrackerOptions,
} from './types.js';
