/**
 * WARD middleware for the Microsoft Agent Framework.
 *
 * MSAF exposes three middleware types; we provide adapters for two of them:
 *
 *   1. Function middleware — gates individual tool calls. This is the primary
 *      WARD enforcement layer. Use `.functionMiddleware()`.
 *
 *   2. Agent middleware — gates whole agent turns. Wraps the entire run.
 *      Use `.agentMiddleware()`. Less granular than function middleware but
 *      useful for behavioral-limit checks (max iterations, max cost) and
 *      for adding session-scoped logging.
 *
 * The user is responsible for registering the returned function with their
 * MSAF agent / chat client. We don't reach into MSAF's internals.
 *
 * Why we don't ship a direct MSAF SDK dependency:
 *   MSAF's primary surface is .NET. The Node/TS bindings are evolving and
 *   we don't want to pin a specific 1.0.0-rc version. Instead, we expose
 *   middleware FUNCTIONS that match MSAF's documented `pre_invoke` and
 *   `agent_middleware` signatures. The user wires them in.
 */

import { readFileSync, existsSync } from 'node:fs';
import {
  type WardPolicy,
} from '@weave_protocol/ward';
import {
  type MsafToolCall,
  type MsafMiddlewareResult,
  type MiddlewareOptions,
  type ToolMapping,
  WardDeniedError,
} from './types.js';
import { resolveWardForCwd, loadWardFromSource, evaluateCall, type ResolvedWard } from './policy.js';
import { reportEvent } from '@weave_protocol/ward';

// ============================================================================
// WardMiddleware class
// ============================================================================

/**
 * The primary entry point. Construct one, register the returned middleware
 * functions with your MSAF agent.
 *
 * @example
 * ```typescript
 * import { WardMiddleware } from '@weave_protocol/adapter-msaf';
 *
 * const ward = new WardMiddleware({ wardPath: './WARD.md' });
 *
 * // For per-tool gating (primary use):
 * agent.useFunctionMiddleware(ward.functionMiddleware());
 *
 * // For turn-level gating (optional, complementary):
 * agent.useAgentMiddleware(ward.agentMiddleware());
 * ```
 */
export class WardMiddleware {
  private resolved: ResolvedWard | null;
  private readonly failClosed: boolean;
  private readonly toolMappings: Record<string, ToolMapping>;
  private readonly onAllow?: MiddlewareOptions['onAllow'];
  private readonly onDeny?: MiddlewareOptions['onDeny'];
  private readonly cwd?: string;

  constructor(opts: MiddlewareOptions = {}) {
    this.failClosed = opts.failMode === 'closed';
    this.toolMappings = opts.toolMappings || {};
    this.onAllow = opts.onAllow;
    this.onDeny = opts.onDeny;
    this.cwd = opts.cwd;

    // A policy the caller named explicitly must load; never fall back to
    // running without it.
    if (opts.wardSource !== undefined) {
      this.resolved = loadWardFromSource(opts.wardSource, '<inline>');
      return;
    }
    if (opts.wardPath) {
      if (!existsSync(opts.wardPath)) {
        throw new Error(`WARD.md not found at ${opts.wardPath}`);
      }
      this.resolved = loadWardFromSource(readFileSync(opts.wardPath, 'utf8'), opts.wardPath);
      return;
    }

    // An invalid WARD.md throws here whatever the fail mode: a typo must not
    // silently switch enforcement off.
    this.resolved = resolveWardForCwd(opts.cwd);
    if (!this.resolved) {
      if (this.failClosed) {
        throw new Error('No WARD.md found ($WEAVE_WARD_PATH, WARD.md, .weave/WARD.md, .msaf/WARD.md) and failMode is closed');
      }
      // eslint-disable-next-line no-console
      console.warn('[weave-msaf] No WARD.md found. Running without a policy — no enforcement.');
    }
  }

  /**
   * Returns true if a WARD policy is loaded.
   */
  isLoaded(): boolean {
    return this.resolved !== null;
  }

  /**
   * The active WARD policy source path (or '<inline>'), if loaded.
   */
  getPolicySource(): string | null {
    return this.resolved?.source ?? null;
  }

  /**
   * The parsed WARD policy object, if loaded.
   */
  getPolicy(): WardPolicy | null {
    return this.resolved?.policy ?? null;
  }

  /**
   * Evaluate a tool call against the loaded policy. Pure function — does
   * not throw. Useful for testing and for users who want to run the check
   * manually without going through middleware.
   */
  evaluate(call: MsafToolCall): MsafMiddlewareResult {
    if (!this.resolved) {
      return { decision: 'allow', reasons: ['No WARD.md loaded'] };
    }
    const result = evaluateCall(this.resolved.policy, call, this.toolMappings, this.cwd);
    // Dashboard reporting (only when WEAVE_DASHBOARD_URL is set; never blocks)
    void reportEvent({ surface: 'msaf', decision: result.decision, subject: call.toolName, reason: result.reasons[0] });
    return { ...result, policySource: this.resolved.source };
  }

  /**
   * Returns a function middleware compatible with MSAF's function-middleware
   * pre_invoke shape. The returned function:
   *   - calls next() if the call is allowed
   *   - throws WardDeniedError if the call is denied or requires approval
   *
   * Usage:
   *   agent.useFunctionMiddleware(ward.functionMiddleware());
   */
  functionMiddleware(): (call: MsafToolCall, next: () => Promise<unknown>) => Promise<unknown> {
    return async (call: MsafToolCall, next: () => Promise<unknown>): Promise<unknown> => {
      const result = this.evaluate(call);

      if (result.decision === 'allow') {
        if (this.onAllow) await this.onAllow(call, result);
        return next();
      }

      // Denied or requires approval
      if (this.onDeny) {
        const override = await this.onDeny(call, result);
        if (override === true) {
          // User explicitly overrode the WARD decision
          return next();
        }
      }

      throw new WardDeniedError(
        result.decision === 'deny' ? 'deny' : 'require_approval',
        result.reasons,
        call.toolName,
        result.policySource,
      );
    };
  }

  /**
   * Returns an agent middleware compatible with MSAF's agent middleware
   * shape. This fires once per turn before any LLM call.
   *
   * The agent middleware is informational only by default — it doesn't gate
   * individual tool calls (that's what functionMiddleware is for). It exists
   * so users who want a turn-level hook (for logging or session tracking)
   * can register one. To enforce behavioral limits (cost, iterations) at the
   * turn level, subclass or wrap this.
   */
  agentMiddleware(): (ctx: { turnIndex?: number }, next: () => Promise<unknown>) => Promise<unknown> {
    return async (ctx: { turnIndex?: number }, next: () => Promise<unknown>): Promise<unknown> => {
      // For now, agent middleware is pass-through; future versions can add
      // iteration-counter / cost-tracking enforcement here.
      return next();
    };
  }

  /**
   * Backward-compatible: alias for functionMiddleware().
   * MSAF's terminology evolved; we keep both spellings.
   */
  middleware(): ReturnType<WardMiddleware['functionMiddleware']> {
    return this.functionMiddleware();
  }
}
