/**
 * WARD policy loading + evaluation for MSAF middleware.
 *
 * Unlike the Claude Code / Antigravity adapters which read WARD on every
 * hook invocation (because they're spawned as subprocesses), MSAF middleware
 * runs in-process. We load WARD once at middleware construction time and
 * keep the parsed policy in memory for the lifetime of the agent run.
 */

import { readFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { parseAndValidate, evaluateToolCall, type WardPolicy } from '@weave_protocol/ward';
import {
  TOOL_MAPPINGS,
  type ToolMapping,
  type MsafToolCall,
  type MsafMiddlewareResult,
} from './types.js';

// ============================================================================
// Resolution
// ============================================================================

export interface ResolvedWard {
  policy: WardPolicy;
  source: string;
}

/**
 * Find a WARD.md by walking the resolution order:
 *   1. $WEAVE_WARD_PATH if set
 *   2. <cwd>/WARD.md
 *   3. <cwd>/.weave/WARD.md
 *   4. <cwd>/.msaf/WARD.md (MSAF convention if user puts config in .msaf/)
 */
export function resolveWardForCwd(cwd: string = process.cwd()): ResolvedWard | null {
  const candidates: string[] = [];

  if (process.env.WEAVE_WARD_PATH) candidates.push(process.env.WEAVE_WARD_PATH);
  if (cwd) {
    candidates.push(join(cwd, 'WARD.md'));
    candidates.push(join(cwd, '.weave', 'WARD.md'));
    candidates.push(join(cwd, '.msaf', 'WARD.md'));
  }

  for (const path of candidates) {
    const resolved = resolve(path);
    if (existsSync(resolved)) {
      return loadWardFromSource(readFileSync(resolved, 'utf8'), resolved);
    }
  }
  return null;
}

/** Parse and validate a WARD.md; throws on an invalid policy. */
export function loadWardFromSource(source: string, label = '<inline>'): ResolvedWard {
  const result = parseAndValidate(source);
  if (!result.valid || !result.policy) {
    throw new Error(`Invalid WARD.md (${label}): ${result.errors.map((e) => e.message).join('; ')}`);
  }
  return { policy: result.policy, source: label };
}

// ============================================================================
// Evaluation
// ============================================================================

/**
 * Decide a tool call with Ward's shared evaluator: the capability, every
 * path and URL argument, and every URL and path in a shell command.
 * (Before 0.2.0 this checked one field per tool and the first URL of a
 * command; see WARD-2026-001.)
 */
export function evaluateCall(
  policy: WardPolicy,
  call: MsafToolCall,
  customMappings: Record<string, ToolMapping> = {},
  cwd: string = process.cwd(),
): MsafMiddlewareResult {
  const { decision, reasons } = evaluateToolCall(policy, call.toolName, call.args, {
    // Custom mappings win on conflict.
    mappings: { ...TOOL_MAPPINGS, ...customMappings },
    cwd,
  });
  return { decision, reasons };
}
