/**
 * Hook handler.
 *
 * This is what Claude Code actually invokes when a tool is about to be used.
 * Reads the hook payload from stdin, looks up the active WARD policy,
 * evaluates the proposed tool call, and writes the decision to stdout.
 *
 * Resolution order for WARD.md:
 *   1. $WEAVE_WARD_PATH if set
 *   2. <cwd>/WARD.md (from the hook payload)
 *   3. <cwd>/.weave/WARD.md
 *   4. ~/.claude/WARD.md (user-global fallback)
 *
 * Failure modes:
 *   - A WARD.md that exists but is invalid always blocks (since 0.3.0): a
 *     typo must not silently switch enforcement off.
 *   - Malformed hook payloads and evaluator errors: fail OPEN by default
 *     (warn on stderr, allow); --fail-closed blocks instead.
 */

import { readFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { parseAndValidate, evaluateToolCall, reportEvent, type WardPolicy } from '@weave_protocol/ward';
import {
  TOOL_MAPPINGS,
  type ClaudeCodeHookInput,
  type ClaudeCodeHookOutput,
} from './types.js';
import { userWardPath } from './config.js';

// ============================================================================
// stdin reader
// ============================================================================

async function readStdin(): Promise<string> {
  if (process.stdin.isTTY) return '';
  return new Promise((resolveStdin) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => (data += chunk));
    process.stdin.on('end', () => resolveStdin(data));
  });
}

// ============================================================================
// WARD resolution
// ============================================================================

export interface ResolvedWard {
  policy: WardPolicy;
  source: string;
}

export function resolveWardForCwd(cwd: string): ResolvedWard | null {
  const candidates: string[] = [];

  if (process.env.WEAVE_WARD_PATH) candidates.push(process.env.WEAVE_WARD_PATH);
  if (cwd) {
    candidates.push(join(cwd, 'WARD.md'));
    candidates.push(join(cwd, '.weave', 'WARD.md'));
  }
  candidates.push(userWardPath());

  for (const path of candidates) {
    const resolved = resolve(path);
    if (existsSync(resolved)) {
      const result = parseAndValidate(readFileSync(resolved, 'utf8'));
      if (!result.valid || !result.policy) {
        throw new Error(`Invalid WARD.md at ${resolved}: ${result.errors.map((e) => e.message).join('; ')}`);
      }
      return { policy: result.policy, source: resolved };
    }
  }
  return null;
}

// ============================================================================
// Decision engine
// ============================================================================

export interface HookDecision {
  decision: 'allow' | 'deny' | 'require_approval';
  reasons: string[];
  policySource?: string;
}

/**
 * Decide a tool call with Ward's shared evaluator: the capability, every
 * path and URL argument, and every URL and path in a shell command.
 * (Before 0.3.0 this checked one field per tool and the first URL of a
 * command; see WARD-2026-001.)
 */
export function evaluateCall(
  policy: WardPolicy,
  toolName: string,
  toolInput: Record<string, unknown> | undefined,
  cwd?: string,
): HookDecision {
  const { decision, reasons } = evaluateToolCall(policy, toolName, toolInput, { mappings: TOOL_MAPPINGS, cwd });
  return { decision, reasons };
}

// ============================================================================
// Hook output helpers
// ============================================================================

function emit(output: ClaudeCodeHookOutput): never {
  process.stdout.write(JSON.stringify(output));
  process.exit(0);
}

// ============================================================================
// Main entry
// ============================================================================

export async function runPreToolUseHook(failClosed: boolean): Promise<never> {
  const raw = await readStdin();

  // No payload → can't do anything useful, pass through silently
  if (!raw.trim()) emit({});

  let payload: ClaudeCodeHookInput;
  try {
    payload = JSON.parse(raw);
  } catch {
    // Malformed payload — fail open (default) or closed
    if (failClosed) emit({ decision: 'block', reason: 'WARD hook: malformed payload from Claude Code' });
    process.stderr.write('weave-claude-code: malformed hook payload, allowing\n');
    emit({});
  }

  if (!payload.tool_name) emit({});

  const cwd = payload.cwd || process.cwd();

  // Resolve WARD policy
  let resolved: ResolvedWard | null = null;
  try {
    resolved = resolveWardForCwd(cwd);
  } catch (err) {
    // A policy exists but can't be used: block rather than run unprotected.
    const msg = err instanceof Error ? err.message : String(err);
    emit({ decision: 'block', reason: `🛡️  WARD policy could not be loaded: ${msg}\n   Fix WARD.md to continue.` });
  }

  if (!resolved) {
    // No WARD.md found — nothing to enforce
    emit({});
  }

  // Evaluate
  let result: HookDecision;
  try {
    result = evaluateCall(resolved.policy, payload.tool_name, payload.tool_input, cwd);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (failClosed) emit({ decision: 'block', reason: `WARD evaluation failed: ${msg}` });
    process.stderr.write(`weave-claude-code: WARD eval failed (${msg}), allowing\n`);
    emit({});
  }

  // Dashboard reporting (only when WEAVE_DASHBOARD_URL is set; at most 250ms)
  await reportEvent({ surface: 'claude-code', decision: result.decision, subject: payload.tool_name, reason: result.reasons[0] });

  if (result.decision === 'deny') {
    emit({
      decision: 'block',
      reason: `🛡️  WARD: ${result.reasons.join(' | ')}\n   Policy: ${resolved.source}`,
    });
  }

  if (result.decision === 'require_approval') {
    // Claude Code's hook protocol doesn't have a "needs approval" decision
    // distinct from "block", so we block with a clear reason. The user can
    // explicitly retry / override after reviewing.
    emit({
      decision: 'block',
      reason: `🛡️  WARD requires approval before this call:\n   ${result.reasons.join('\n   ')}\n   Policy: ${resolved.source}\n   To proceed, explicitly confirm or update WARD.md.`,
    });
  }

  // Allow — silent
  emit({});
}
