/**
 * Autonomous Spending Caps — public types for @weave_protocol/witan/spending.
 *
 * These types are consumed by external integrations (@weave_protocol/langchain,
 * harness adapters, etc.). Treat them as locked once shipped.
 */

// ─── Windows ────────────────────────────────────────────────────

export type SpendingWindow = 'run' | 'hour' | 'day' | 'week' | 'month';

// ─── Cap actions ────────────────────────────────────────────────

/**
 * What to do when a cap is exceeded.
 *
 *   block:            deny the action outright
 *   require_approval: dispatch to approvalHandler; block if not approved
 *   notify:           allow the action but fire the onNotify callback
 */
export type CapAction = 'block' | 'require_approval' | 'notify';

// ─── Cap budgets ────────────────────────────────────────────────

export interface CapBudget {
  /** Dollar cap for the window */
  usd?: number;
  /** Aggregate token cap (input + output) */
  tokens?: number;
  /** Total tool-call count cap */
  tool_calls?: number;
  /** Per-tool limits, keyed by tool name */
  tools?: Record<string, ToolBudget>;
}

export interface ToolBudget {
  /** Max cumulative amount transferred by this tool (for send_payment etc.) */
  max_amount_usd?: number;
  /** Max invocation count */
  max_calls?: number;
}

export interface SpendingCap {
  window: SpendingWindow;
  budget: CapBudget;
  onExceeded: CapAction;
  /**
   * Optional label to distinguish caps (shown in violations + CLI output).
   * If omitted, an auto-generated label is used.
   */
  label?: string;
  /**
   * Optional scope — allows the same tracker instance to enforce caps for
   * multiple isolated agents/users. Windows are scoped per (scope, window).
   * Default: 'default'.
   */
  scope?: string;
}

// ─── Proposed actions ───────────────────────────────────────────

export interface ProposedLLMCall {
  kind: 'llm';
  provider: string;
  model: string;
  estInputTokens: number;
  estOutputTokens: number;
  scope?: string;
}

export interface ProposedToolCall {
  kind: 'tool';
  tool: string;
  args?: Record<string, unknown>;
  amountUSD?: number;
  scope?: string;
}

export type ProposedAction = ProposedLLMCall | ProposedToolCall;

// ─── Check result ───────────────────────────────────────────────

export interface CapViolation {
  cap: SpendingCap;
  reason: string;
  current: number;
  proposed: number;
  limit: number;
}

export interface CapCheck {
  blocked: boolean;
  approved?: boolean;
  requiresApproval: boolean;
  violations: CapViolation[];
  reason?: string;
  approve?: () => Promise<boolean>;
}

// ─── Recorded usage ─────────────────────────────────────────────

export interface LLMUsageRecord {
  provider: string;
  model: string;
  inputTokens: number;
  outputTokens: number;
  scope?: string;
  ts?: number;
}

export interface ToolCallRecord {
  tool: string;
  args?: Record<string, unknown>;
  amountUSD?: number;
  scope?: string;
  ts?: number;
}

// ─── Snapshot / stats ───────────────────────────────────────────

export interface WindowUsage {
  window: SpendingWindow;
  scope: string;
  key: string;
  usd: number;
  tokens: number;
  toolCalls: number;
  perTool: Record<string, { calls: number; amountUSD: number }>;
}

// ─── Approval + notify events ───────────────────────────────────

export interface PendingApprovalEvent {
  proposed: ProposedAction;
  cap: SpendingCap;
  violation: CapViolation;
  summary: string;
  estimatedCostUSD: number;
}

export interface NotifyEvent {
  proposed: ProposedAction;
  cap: SpendingCap;
  violation: CapViolation;
  summary: string;
}

// ─── Tracker options ────────────────────────────────────────────

export interface SpendingTrackerOptions {
  caps: SpendingCap[];
  approvalHandler?: (event: PendingApprovalEvent) => Promise<boolean>;
  onNotify?: (event: NotifyEvent) => void;
  store?: import('./store.js').SpendingStore;
  scope?: string;
  now?: () => number;
}
