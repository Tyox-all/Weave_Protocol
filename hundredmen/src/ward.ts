/**
 * WARD.md integration for Hundredmen.
 * @weave_protocol/hundredmen
 *
 * Loads a WARD.md policy and exposes runtime check methods that the
 * Interceptor calls before allowing a tool call to proceed.
 *
 * Auto-detection:
 *   - process.env.WEAVE_WARD_PATH if set
 *   - ./WARD.md in current working directory otherwise
 *
 * No file is required. If no WARD.md is found, the manager simply
 * returns `allow` for every check and Hundredmen behaves as before.
 */

import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  parseWard,
  parseAndValidate,
  checkFilesystem,
  checkNetwork,
  checkCapability,
  checkDataEgress,
  type WardPolicy,
  type CheckResult,
  type HttpMethod,
  type ValidationResult,
} from '@weave_protocol/ward';
import { evaluateWithLedger } from '@weave_protocol/ward/ledger';

// ============================================================================
// Types
// ============================================================================

export interface WardCheckResult {
  /** Overall decision: allow, deny, require_approval. */
  decision: 'allow' | 'deny' | 'require_approval';
  /** Human-readable reason. */
  reason: string;
  /** Which check produced this decision. */
  checks: WardCheckBreakdown[];
  /** Highest severity from the breakdown. */
  severity?: 'low' | 'medium' | 'high' | 'critical';
}

export interface WardCheckBreakdown {
  type: 'capability' | 'filesystem' | 'network' | 'data_egress' | 'payment' | 'limits';
  decision: 'allow' | 'deny' | 'require_approval';
  reason: string;
  matchedRule?: string;
}

export interface WardManagerStatus {
  loaded: boolean;
  source?: string;
  policyName?: string;
  agent?: string;
  validation?: ValidationResult;
}

// ============================================================================
// Manager
// ============================================================================

export class WardPolicyManager {
  private policy: WardPolicy | null = null;
  private source: string | null = null;
  private validation: ValidationResult | null = null;

  constructor() {
    // Auto-load happens explicitly via autoLoad() so callers control timing.
  }

  /**
   * Try to load a WARD.md from env var or CWD. Returns true if loaded.
   */
  autoLoad(): boolean {
    const explicit = process.env.WEAVE_WARD_PATH;
    if (explicit && existsSync(explicit)) {
      this.loadFromPath(explicit);
      return true;
    }
    const cwdWard = resolve(process.cwd(), 'WARD.md');
    if (existsSync(cwdWard)) {
      this.loadFromPath(cwdWard);
      return true;
    }
    return false;
  }

  /** Load a WARD.md file from a specific path. */
  loadFromPath(path: string): void {
    const resolved = resolve(path);
    const source = readFileSync(resolved, 'utf8');
    this.loadFromSource(source, resolved);
  }

  /** Load a WARD.md from raw markdown source. */
  loadFromSource(source: string, sourceLabel?: string): void {
    this.validation = parseAndValidate(source);
    if (!this.validation.valid) {
      const msg = this.validation.errors.map((e) => e.message).join('; ');
      throw new Error(`Invalid WARD.md: ${msg}`);
    }
    this.policy = this.validation.policy ?? parseWard(source);
    this.source = sourceLabel ?? '<inline>';
  }

  /** Remove the loaded policy. Subsequent checks will allow everything. */
  unload(): void {
    this.policy = null;
    this.source = null;
    this.validation = null;
  }

  isLoaded(): boolean {
    return this.policy !== null;
  }

  status(): WardManagerStatus {
    if (!this.policy) return { loaded: false };
    return {
      loaded: true,
      source: this.source ?? undefined,
      policyName: this.policy.name,
      agent: this.policy.agent,
      validation: this.validation ?? undefined,
    };
  }

  getPolicy(): WardPolicy | null {
    return this.policy;
  }

  // ─────────────────────────────────────────────────────────
  // Tool-call gating
  // ─────────────────────────────────────────────────────────

  /**
   * Decide whether to allow an MCP tool call given the loaded WARD policy.
   *
   * If no policy is loaded, returns `allow` (zero-impact mode).
   * Otherwise runs the capability check plus any filesystem/network checks
   * inferable from common argument names (path, url, file, etc.).
   */
  checkCall(tool: string, args: Record<string, unknown> | undefined, sessionId?: string): WardCheckResult {
    if (!this.policy) {
      return { decision: 'allow', reason: 'No WARD.md loaded.', checks: [] };
    }

    // Ward's shared evaluator (1.4.0): every path, URL and command token,
    // self-protection, outbound data, the payment guard, session and spend
    // limits, signed-policy checks and decision receipts, the same as the
    // harness adapters. MCP tool names map to themselves.
    const result = evaluateWithLedger(this.policy, tool, args, { session: sessionId, surface: 'mcp' });
    const checks: WardCheckBreakdown[] = result.checks.map((c) => ({
      type: BREAKDOWN_TYPE[c.type] ?? 'capability',
      decision: c.decision,
      reason: c.subject && c.type !== 'capability' ? `${c.reason} (${c.subject})` : c.reason,
      matchedRule: c.matchedRule,
    }));
    const worst = result.checks.reduce<'low' | 'medium' | 'high' | 'critical' | undefined>(
      (acc, c) => (c.decision !== 'allow' && c.severity && SEVERITY_RANK[c.severity] > SEVERITY_RANK[acc ?? 'low'] ? c.severity : acc),
      undefined,
    );
    return {
      decision: result.decision,
      reason: result.reasons.length ? result.reasons.join(' | ') : 'WARD policy allows.',
      checks,
      ...(worst ? { severity: worst } : {}),
    };
  }

  /** Standalone capability check. */
  checkCapability(tool: string): CheckResult {
    if (!this.policy) return { decision: 'allow', reason: 'No WARD.md loaded.' };
    return checkCapability(this.policy, tool);
  }

  /** Standalone filesystem check. */
  checkFilesystem(op: 'read' | 'write' | 'execute' | 'delete' | 'list', path: string): CheckResult {
    if (!this.policy) return { decision: 'allow', reason: 'No WARD.md loaded.' };
    return checkFilesystem(this.policy, op, path);
  }

  /** Standalone network check. */
  checkNetwork(url: string, method: HttpMethod = 'GET'): CheckResult {
    if (!this.policy) return { decision: 'allow', reason: 'No WARD.md loaded.' };
    return checkNetwork(this.policy, url, method);
  }

  /** Standalone egress check. */
  checkDataEgress(classification: string): CheckResult {
    if (!this.policy) return { decision: 'allow', reason: 'No WARD.md loaded.' };
    return checkDataEgress(this.policy, classification as never);
  }
}

// ============================================================================
// Helpers
// ============================================================================

const BREAKDOWN_TYPE: Record<string, WardCheckBreakdown['type']> = {
  capability: 'capability', filesystem: 'filesystem', command: 'filesystem', network: 'network',
  egress: 'data_egress', payment: 'payment', limits: 'limits',
};
const SEVERITY_RANK = { low: 0, medium: 1, high: 2, critical: 3 } as const;
