/**
 * SpendingTracker — the core enforcement class.
 *
 * Lifecycle for each proposed agent action:
 *
 *   1. Caller: await tracker.checkAction(proposed)
 *      → Tracker looks up current window usage per applicable cap
 *      → Tracker computes what the totals would become if the action proceeds
 *      → For each cap that would be exceeded, tracker classifies by action:
 *          block           → mark blocked=true
 *          require_approval → build approve() closure; caller must call it
 *          notify           → fire onNotify but allow
 *      → Returns CapCheck
 *
 *   2. Caller: if check.blocked, throw / return early
 *      Caller: if check.requiresApproval, call check.approve()
 *      Caller: proceed with the action
 *
 *   3. Caller: after the action succeeds, call recordLLM() or recordTool()
 *      → Tracker adds the actual usage to the window's counters
 *
 * The two-phase (check + record) design lets callers make different decisions
 * about what "the action proceeded" means (e.g. LLM streaming: pre-flight
 * estimate vs. actual token count).
 */

import type {
  CapCheck,
  CapViolation,
  LLMUsageRecord,
  NotifyEvent,
  PendingApprovalEvent,
  ProposedAction,
  ProposedLLMCall,
  ProposedToolCall,
  SpendingCap,
  SpendingTrackerOptions,
  ToolCallRecord,
  WindowUsage,
} from './types.js';
import { InMemorySpendingStore, type SpendingStore } from './store.js';
import { estimateLLMCost } from './pricing.js';
import { windowKey } from './windows.js';
import { resolveHandler, type ApprovalHandler } from './approval.js';

export class SpendingTracker {
  private caps: SpendingCap[];
  private store: SpendingStore;
  private handler: ApprovalHandler;
  private onNotify: (e: NotifyEvent) => void;
  private defaultScope: string;
  private now: () => number;

  constructor(opts: SpendingTrackerOptions) {
    this.caps = opts.caps;
    this.store = opts.store || new InMemorySpendingStore();
    this.handler = resolveHandler(opts.approvalHandler);
    this.onNotify = opts.onNotify || defaultNotify;
    this.defaultScope = opts.scope || 'default';
    this.now = opts.now || Date.now;
  }

  /**
   * Pre-flight check for a proposed action.
   */
  async checkAction(proposed: ProposedAction): Promise<CapCheck> {
    const scope = proposed.scope || this.defaultScope;
    const estCostUSD = this.estimateCost(proposed);

    const violations: CapViolation[] = [];
    let requiresApproval = false;
    let blocked = false;
    const approvalCaps: { cap: SpendingCap; violation: CapViolation }[] = [];

    for (const cap of this.caps) {
      // Cap scope: cap.scope narrows enforcement; if cap.scope is set and
      // doesn't match, this cap doesn't apply to this action.
      if (cap.scope && cap.scope !== scope) continue;

      const capViolations = await this.checkCap(cap, proposed, scope, estCostUSD);
      for (const v of capViolations) {
        violations.push(v);
        if (cap.onExceeded === 'block') blocked = true;
        else if (cap.onExceeded === 'require_approval') {
          requiresApproval = true;
          approvalCaps.push({ cap, violation: v });
        } else if (cap.onExceeded === 'notify') {
          this.onNotify({
            proposed,
            cap,
            violation: v,
            summary: this.buildSummary(proposed, cap, v),
          });
        }
      }
    }

    const check: CapCheck = {
      blocked,
      requiresApproval,
      violations,
      reason: violations.length ? violations.map((v) => v.reason).join('; ') : undefined,
    };

    if (requiresApproval && !blocked) {
      check.approve = async () => {
        // Sequential — first denied caps trip the whole thing.
        for (const { cap, violation } of approvalCaps) {
          const event: PendingApprovalEvent = {
            proposed,
            cap,
            violation,
            summary: this.buildSummary(proposed, cap, violation),
            estimatedCostUSD: estCostUSD,
          };
          const ok = await this.handler(event);
          if (!ok) {
            check.approved = false;
            check.blocked = true;
            return false;
          }
        }
        check.approved = true;
        return true;
      };
    }

    return check;
  }

  /**
   * Record actual LLM usage after the call completes.
   */
  async recordLLM(usage: LLMUsageRecord): Promise<void> {
    const scope = usage.scope || this.defaultScope;
    const ts = usage.ts ?? this.now();
    const cost = estimateLLMCost(usage.provider, usage.model, usage.inputTokens, usage.outputTokens);
    const tokens = usage.inputTokens + usage.outputTokens;

    for (const cap of this.caps) {
      if (cap.scope && cap.scope !== scope) continue;
      const wk = windowKey(cap.window, scope, ts);
      if (cap.budget.usd !== undefined) await this.store.add(`${wk}:usd`, cost);
      if (cap.budget.tokens !== undefined) await this.store.add(`${wk}:tokens`, tokens);
    }
  }

  /**
   * Record an actual tool-call after it succeeds.
   */
  async recordTool(call: ToolCallRecord): Promise<void> {
    const scope = call.scope || this.defaultScope;
    const ts = call.ts ?? this.now();
    const amount = call.amountUSD ?? extractPaymentAmount(call);

    for (const cap of this.caps) {
      if (cap.scope && cap.scope !== scope) continue;
      const wk = windowKey(cap.window, scope, ts);
      if (cap.budget.tool_calls !== undefined) await this.store.add(`${wk}:tool_calls`, 1);
      if (amount !== undefined && cap.budget.usd !== undefined) {
        // Payment tools also contribute to USD cap
        await this.store.add(`${wk}:usd`, amount);
      }
      const tb = cap.budget.tools?.[call.tool];
      if (tb) {
        await this.store.add(`${wk}:tool:${call.tool}:calls`, 1);
        if (amount !== undefined) {
          await this.store.add(`${wk}:tool:${call.tool}:amount_usd`, amount);
        }
      }
    }
  }

  /**
   * Get current usage for a specific window+scope for status/reporting.
   */
  async getUsage(window: SpendingCap['window'], scope?: string): Promise<WindowUsage> {
    const s = scope || this.defaultScope;
    const wk = windowKey(window, s, this.now());
    const snap = await this.store.snapshot(`${wk}:`);

    const perTool: WindowUsage['perTool'] = {};
    for (const [k, v] of Object.entries(snap)) {
      const m = k.match(/:tool:([^:]+):(calls|amount_usd)$/);
      if (m) {
        const tool = m[1];
        perTool[tool] ||= { calls: 0, amountUSD: 0 };
        if (m[2] === 'calls') perTool[tool].calls = v;
        else perTool[tool].amountUSD = v;
      }
    }

    return {
      window,
      scope: s,
      key: wk,
      usd: snap[`${wk}:usd`] || 0,
      tokens: snap[`${wk}:tokens`] || 0,
      toolCalls: snap[`${wk}:tool_calls`] || 0,
      perTool,
    };
  }

  /**
   * Reset all counters for a given window (and optional scope).
   */
  async reset(window?: SpendingCap['window'], scope?: string): Promise<number> {
    const s = scope || this.defaultScope;
    const prefixes = window
      ? [`${window}:`]
      : ['run:', 'hour:', 'day:', 'week:', 'month:'];
    let reset = 0;
    for (const p of prefixes) {
      const keys = await this.store.listKeys(p);
      for (const k of keys) {
        if (k.split(':').slice(-1)[0] === s || k.includes(`:${s}:`)) {
          await this.store.reset(k);
          reset++;
        }
      }
    }
    return reset;
  }

  /**
   * Full snapshot of all live counters (for CLI status).
   */
  async snapshot(): Promise<Record<string, number>> {
    const all: Record<string, number> = {};
    for (const w of ['run', 'hour', 'day', 'week', 'month'] as const) {
      const wk = windowKey(w, this.defaultScope, this.now());
      Object.assign(all, await this.store.snapshot(`${wk}:`));
    }
    return all;
  }

  // ─── Internals ───────────────────────────────────────────────

  private estimateCost(action: ProposedAction): number {
    if (action.kind === 'llm') {
      return estimateLLMCost(action.provider, action.model, action.estInputTokens, action.estOutputTokens);
    }
    return action.amountUSD ?? 0;
  }

  private async checkCap(
    cap: SpendingCap,
    action: ProposedAction,
    scope: string,
    estCostUSD: number,
  ): Promise<CapViolation[]> {
    const violations: CapViolation[] = [];
    const wk = windowKey(cap.window, scope, this.now());

    // USD
    if (cap.budget.usd !== undefined) {
      const current = await this.store.get(`${wk}:usd`);
      const proposed = current + estCostUSD;
      if (proposed > cap.budget.usd) {
        violations.push({
          cap,
          reason: `${cap.window} USD cap $${cap.budget.usd.toFixed(2)} exceeded (current $${current.toFixed(4)}, proposed $${proposed.toFixed(4)})`,
          current,
          proposed,
          limit: cap.budget.usd,
        });
      }
    }

    // Tokens
    if (cap.budget.tokens !== undefined && action.kind === 'llm') {
      const current = await this.store.get(`${wk}:tokens`);
      const proposed = current + action.estInputTokens + action.estOutputTokens;
      if (proposed > cap.budget.tokens) {
        violations.push({
          cap,
          reason: `${cap.window} token cap ${cap.budget.tokens} exceeded (current ${current}, proposed ${proposed})`,
          current,
          proposed,
          limit: cap.budget.tokens,
        });
      }
    }

    // Total tool call count
    if (cap.budget.tool_calls !== undefined && action.kind === 'tool') {
      const current = await this.store.get(`${wk}:tool_calls`);
      const proposed = current + 1;
      if (proposed > cap.budget.tool_calls) {
        violations.push({
          cap,
          reason: `${cap.window} tool-call cap ${cap.budget.tool_calls} exceeded (current ${current})`,
          current,
          proposed,
          limit: cap.budget.tool_calls,
        });
      }
    }

    // Per-tool budgets
    if (cap.budget.tools && action.kind === 'tool') {
      const tb = cap.budget.tools[action.tool];
      if (tb) {
        if (tb.max_calls !== undefined) {
          const current = await this.store.get(`${wk}:tool:${action.tool}:calls`);
          const proposed = current + 1;
          if (proposed > tb.max_calls) {
            violations.push({
              cap,
              reason: `${cap.window} ${action.tool} call cap ${tb.max_calls} exceeded`,
              current,
              proposed,
              limit: tb.max_calls,
            });
          }
        }
        if (tb.max_amount_usd !== undefined) {
          const amount = action.amountUSD ?? extractPaymentAmount({ tool: action.tool, args: action.args });
          if (amount !== undefined) {
            const current = await this.store.get(`${wk}:tool:${action.tool}:amount_usd`);
            const proposed = current + amount;
            if (proposed > tb.max_amount_usd) {
              violations.push({
                cap,
                reason: `${cap.window} ${action.tool} amount cap $${tb.max_amount_usd.toFixed(2)} exceeded (proposed $${proposed.toFixed(2)})`,
                current,
                proposed,
                limit: tb.max_amount_usd,
              });
            }
          }
        }
      }
    }

    return violations;
  }

  private buildSummary(action: ProposedAction, cap: SpendingCap, v: CapViolation): string {
    if (action.kind === 'llm') {
      return `LLM call (${action.provider}/${action.model}, ~${action.estInputTokens}+${action.estOutputTokens} tokens) would violate ${cap.label || cap.window + ' cap'}: ${v.reason}`;
    }
    const amt = action.amountUSD !== undefined ? ` $${action.amountUSD.toFixed(2)}` : '';
    return `Tool call ${action.tool}${amt} would violate ${cap.label || cap.window + ' cap'}: ${v.reason}`;
  }
}

// ─── helpers ────────────────────────────────────────────────────

/**
 * Best-effort extraction of a USD amount from tool call arguments.
 * Looks for common field names: amount, amount_usd, value, total, price.
 */
function extractPaymentAmount(call: { tool: string; args?: Record<string, unknown> }): number | undefined {
  if (!call.args) return undefined;
  const candidates = ['amount_usd', 'amountUSD', 'amount', 'value', 'total', 'price'];
  for (const c of candidates) {
    const v = call.args[c];
    if (typeof v === 'number' && Number.isFinite(v)) return v;
    if (typeof v === 'string') {
      const parsed = parseFloat(v.replace(/[$,]/g, ''));
      if (Number.isFinite(parsed)) return parsed;
    }
  }
  return undefined;
}

function defaultNotify(e: NotifyEvent): void {
  process.stderr.write(`[witan/spending] notify: ${e.summary}\n`);
}
