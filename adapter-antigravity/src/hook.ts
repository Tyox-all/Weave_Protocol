/**
 * Antigravity hook handler.
 *
 * Reads the hook payload from stdin, looks up the active WARD policy,
 * evaluates the proposed tool call, writes the decision to stdout.
 *
 * Resolution order for WARD.md (workspace = workspacePaths[0] from the payload):
 *   1. $WEAVE_WARD_PATH if set
 *   2. <workspace>/WARD.md
 *   3. <workspace>/.agents/WARD.md (co-located with AGENTS.md)
 *   4. <workspace>/.weave/WARD.md
 *   5. ~/.gemini/config/WARD.md (global, next to hooks.json)
 *   6. ~/.gemini/antigravity-cli/WARD.md (legacy global location)
 *
 * Payload and output follow https://antigravity.google/docs/hooks:
 * stdin { toolCall: { name, args }, workspacePaths, ... }; stdout
 * { decision: "deny" | "ask", reason }, or nothing to leave the call alone.
 *
 * Failure modes:
 *   - A WARD.md that exists but is invalid always denies (since 0.3.0): a
 *     typo must not silently switch enforcement off.
 *   - Malformed payloads and evaluator errors: fail OPEN by default (warn
 *     on stderr, allow); --fail-closed denies instead.
 */

import { readFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { homedir } from 'node:os';
import { parseAndValidate, evaluateToolCall, type WardPolicy } from '@weave_protocol/ward';
import {
  TOOL_MAPPINGS,
  type AntigravityHookInput,
  type AntigravityHookOutput,
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
    candidates.push(join(cwd, '.agents', 'WARD.md'));
    candidates.push(join(cwd, '.weave', 'WARD.md'));
  }
  candidates.push(join(homedir(), '.gemini', 'config', 'WARD.md'));
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
 * Relative paths resolve against the workspace. (Before 0.3.0 this checked
 * one field per tool and the first URL of a command; see WARD-2026-001.)
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

/** Print a decision, or nothing (leave the call to Antigravity), then exit. */
function emit(output?: AntigravityHookOutput): never {
  if (output) process.stdout.write(JSON.stringify(output));
  process.exit(0);
}

/** The tool name, args and workspace from an Antigravity payload (legacy fields as fallback). */
export function parsePayload(payload: AntigravityHookInput): { tool?: string; args?: Record<string, unknown>; cwd: string } {
  return {
    tool: payload.toolCall?.name ?? payload.tool_name,
    args: payload.toolCall?.args ?? payload.tool_input,
    cwd: payload.workspacePaths?.[0] || payload.cwd || process.cwd(),
  };
}

/** WARD decision → Antigravity output. "require_approval" uses Antigravity's native "ask". */
export function toHookOutput(result: HookDecision, source: string): AntigravityHookOutput | undefined {
  if (result.decision === 'deny') {
    return { decision: 'deny', reason: `WARD: ${result.reasons.join(' | ')} (policy: ${source})` };
  }
  if (result.decision === 'require_approval') {
    return { decision: 'ask', reason: `WARD requires approval: ${result.reasons.join(' | ')} (policy: ${source})` };
  }
  return undefined;
}

// ============================================================================
// Main entry
// ============================================================================

export async function runPreToolUseHook(failClosed: boolean): Promise<never> {
  const raw = await readStdin();
  if (!raw.trim()) emit();

  let payload: AntigravityHookInput;
  try {
    payload = JSON.parse(raw);
  } catch {
    if (failClosed) emit({ decision: 'deny', reason: 'WARD hook: malformed payload from Antigravity' });
    process.stderr.write('weave-antigravity: malformed hook payload, allowing\n');
    emit();
  }

  const { tool, args, cwd } = parsePayload(payload);
  if (!tool) emit();

  let resolved: ResolvedWard | null = null;
  try {
    resolved = resolveWardForCwd(cwd);
  } catch (err) {
    // A policy exists but can't be used: deny rather than run unprotected.
    const msg = err instanceof Error ? err.message : String(err);
    emit({ decision: 'deny', reason: `WARD policy could not be loaded: ${msg}. Fix WARD.md to continue.` });
  }
  if (!resolved) emit();

  let result: HookDecision;
  try {
    result = evaluateCall(resolved.policy, tool, args, cwd);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (failClosed) emit({ decision: 'deny', reason: `WARD evaluation failed: ${msg}` });
    process.stderr.write(`weave-antigravity: WARD eval failed (${msg}), allowing\n`);
    emit();
  }

  emit(toHookOutput(result, resolved.source));
}
