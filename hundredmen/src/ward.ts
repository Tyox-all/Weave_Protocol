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
  type: 'capability' | 'filesystem' | 'network' | 'data_egress';
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
  checkCall(tool: string, args: Record<string, unknown> | undefined): WardCheckResult {
    if (!this.policy) {
      return { decision: 'allow', reason: 'No WARD.md loaded.', checks: [] };
    }

    const breakdowns: WardCheckBreakdown[] = [];

    // 1. Capability check (always)
    const capResult = checkCapability(this.policy, tool);
    breakdowns.push({
      type: 'capability',
      decision: capResult.decision,
      reason: capResult.reason,
      matchedRule: capResult.matchedRule,
    });

    // 2. Filesystem check (if the tool args look like a file path)
    const fsArg = pickFirstFsArg(args);
    if (fsArg) {
      const op = inferFsOp(tool);
      const fsResult = checkFilesystem(this.policy, op, fsArg);
      breakdowns.push({
        type: 'filesystem',
        decision: fsResult.decision,
        reason: fsResult.reason,
        matchedRule: fsResult.matchedRule,
      });
    }

    // 3. Network check (if the tool args look like a URL)
    const urlArg = pickFirstUrlArg(args);
    if (urlArg) {
      const method = (args?.method as HttpMethod) || 'GET';
      const netResult = checkNetwork(this.policy, urlArg, method);
      breakdowns.push({
        type: 'network',
        decision: netResult.decision,
        reason: netResult.reason,
        matchedRule: netResult.matchedRule,
      });
    }

    // Aggregate: deny wins over require_approval wins over allow
    return aggregate(breakdowns);
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

function aggregate(breakdowns: WardCheckBreakdown[]): WardCheckResult {
  let decision: 'allow' | 'deny' | 'require_approval' = 'allow';
  let severity: 'low' | 'medium' | 'high' | 'critical' | undefined;
  const reasons: string[] = [];

  for (const b of breakdowns) {
    if (b.decision === 'deny') {
      decision = 'deny';
      reasons.push(b.reason);
    } else if (b.decision === 'require_approval' && decision !== 'deny') {
      decision = 'require_approval';
      reasons.push(b.reason);
    }
  }

  return {
    decision,
    reason: reasons.length > 0 ? reasons.join(' | ') : 'WARD policy allows.',
    checks: breakdowns,
    severity,
  };
}

function pickFirstFsArg(args: Record<string, unknown> | undefined): string | null {
  if (!args) return null;
  const candidates = ['path', 'file', 'filepath', 'filename', 'file_path', 'target', 'src', 'dest', 'destination'];
  for (const k of candidates) {
    const v = args[k];
    if (typeof v === 'string') return v;
  }
  return null;
}

function pickFirstUrlArg(args: Record<string, unknown> | undefined): string | null {
  if (!args) return null;
  const candidates = ['url', 'uri', 'endpoint', 'href', 'target_url'];
  for (const k of candidates) {
    const v = args[k];
    if (typeof v === 'string' && /^https?:\/\//.test(v)) return v;
  }
  return null;
}

function inferFsOp(tool: string): 'read' | 'write' | 'execute' | 'delete' | 'list' {
  const t = tool.toLowerCase();
  if (t.includes('write') || t.includes('create') || t.includes('save')) return 'write';
  if (t.includes('delete') || t.includes('remove') || t.includes('rm')) return 'delete';
  if (t.includes('execute') || t.includes('run') || t.includes('exec')) return 'execute';
  if (t.includes('list') || t.includes('readdir') || t.includes('ls')) return 'list';
  return 'read';
}
