/**
 * PreToolUse hook handler: reads Codex's payload from stdin, finds the
 * active WARD.md, decides with Ward's shared evaluator, and prints a deny or
 * nothing.
 *
 * WARD.md resolution (cwd = the payload's cwd):
 *   1. $WEAVE_WARD_PATH
 *   2. <cwd>/WARD.md
 *   3. <cwd>/.codex/WARD.md
 *   4. <cwd>/.weave/WARD.md
 *   5. $CODEX_HOME/WARD.md (default ~/.codex/WARD.md)
 *
 * Failure modes:
 *   - A WARD.md that exists but is invalid always denies: a typo must not
 *     silently switch enforcement off.
 *   - Malformed payloads and evaluator errors allow by default (with a note
 *     on stderr); --fail-closed denies instead.
 */

import { readFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { parseAndValidate, evaluateToolCall, type WardPolicy } from '@weave_protocol/ward';
import { TOOL_MAPPINGS, type CodexHookInput, type CodexHookOutput } from './types.js';
import { patchTargets } from './patch.js';
import { userWardPath } from './config.js';

export interface ResolvedWard {
  policy: WardPolicy;
  source: string;
}

export interface HookDecision {
  decision: 'allow' | 'deny' | 'require_approval';
  reasons: string[];
}

export function resolveWardForCwd(cwd: string): ResolvedWard | null {
  const candidates = [
    process.env.WEAVE_WARD_PATH,
    cwd && join(cwd, 'WARD.md'),
    cwd && join(cwd, '.codex', 'WARD.md'),
    cwd && join(cwd, '.weave', 'WARD.md'),
    userWardPath(),
  ].filter((p): p is string => !!p);

  for (const path of candidates) {
    const full = resolve(path);
    if (!existsSync(full)) continue;
    const result = parseAndValidate(readFileSync(full, 'utf8'));
    if (!result.valid || !result.policy) {
      throw new Error(`Invalid WARD.md at ${full}: ${result.errors.map((e) => e.message).join('; ')}`);
    }
    return { policy: result.policy, source: full };
  }
  return null;
}

const RANK = { allow: 0, require_approval: 1, deny: 2 } as const;

/** Decide a Codex tool call against a WARD policy. */
export function evaluateCall(policy: WardPolicy, toolName: string, toolInput: unknown, cwd: string = process.cwd()): HookDecision {
  const input: Record<string, unknown> =
    toolInput && typeof toolInput === 'object' && !Array.isArray(toolInput)
      ? (toolInput as Record<string, unknown>)
      : { command: toolInput };
  const opts = { mappings: TOOL_MAPPINGS, cwd };

  // apply_patch: the files the patch writes and deletes, not its text
  if (toolName === 'apply_patch') {
    const { writes, deletes } = patchTargets(String(input.command ?? ''));
    const results = [
      evaluateToolCall(policy, 'apply_patch', { target: writes }, {
        ...opts, mappings: { apply_patch: { capability: 'file_write', pathField: 'target', fsOp: 'write' } },
      }),
      ...(deletes.length
        ? [evaluateToolCall(policy, 'apply_patch', { target: deletes }, {
          ...opts, mappings: { apply_patch: { capability: 'file_write', pathField: 'target', fsOp: 'delete' } },
        })]
        : []),
    ];
    const worst = results.reduce((a, b) => (RANK[b.decision] > RANK[a.decision] ? b : a));
    return { decision: worst.decision, reasons: results.flatMap((r) => r.reasons) };
  }

  const { decision, reasons } = evaluateToolCall(policy, toolName, input, opts);
  return { decision, reasons };
}

/** WARD decision → Codex output; undefined means print nothing (continue). */
export function toHookOutput(result: HookDecision, source: string): CodexHookOutput | undefined {
  if (result.decision === 'allow') return undefined;
  const reason = result.decision === 'deny'
    ? `WARD: ${result.reasons.join(' | ')} (policy: ${source})`
    : `WARD requires approval before this call: ${result.reasons.join(' | ')} (policy: ${source}). Ask the user to approve it or update WARD.md.`;
  return { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason } };
}

async function readStdin(): Promise<string> {
  if (process.stdin.isTTY) return '';
  let data = '';
  process.stdin.setEncoding('utf8');
  for await (const chunk of process.stdin) data += chunk;
  return data;
}

function emit(output?: CodexHookOutput): never {
  if (output) process.stdout.write(JSON.stringify(output));
  process.exit(0);
}

const denyWith = (reason: string): CodexHookOutput => ({
  hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason },
});

export async function runPreToolUseHook(failClosed: boolean): Promise<never> {
  const raw = await readStdin();
  if (!raw.trim()) emit();

  let payload: CodexHookInput;
  try {
    payload = JSON.parse(raw);
  } catch {
    if (failClosed) emit(denyWith('WARD hook: malformed payload from Codex'));
    process.stderr.write('weave-ward-codex: malformed hook payload, allowing\n');
    emit();
  }
  if (!payload.tool_name) emit();

  const cwd = payload.cwd || process.cwd();

  let resolved: ResolvedWard | null;
  try {
    resolved = resolveWardForCwd(cwd);
  } catch (err) {
    // A policy exists but can't be used: deny rather than run unprotected.
    emit(denyWith(`WARD policy could not be loaded: ${err instanceof Error ? err.message : String(err)}. Fix WARD.md to continue.`));
  }
  if (!resolved) emit();

  let result: HookDecision;
  try {
    result = evaluateCall(resolved.policy, payload.tool_name, payload.tool_input, cwd);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (failClosed) emit(denyWith(`WARD evaluation failed: ${msg}`));
    process.stderr.write(`weave-ward-codex: WARD evaluation failed (${msg}), allowing\n`);
    emit();
  }

  emit(toHookOutput(result, resolved.source));
}
