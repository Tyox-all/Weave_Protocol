/**
 * PreToolUse hook handler: reads Qoder CLI's payload from stdin, finds the
 * active WARD.md, decides with Ward's shared evaluator, and prints the
 * decision.
 *
 * WARD.md resolution (cwd = the payload's cwd):
 *   1. $WEAVE_WARD_PATH
 *   2. <cwd>/WARD.md
 *   3. <cwd>/.qoder/WARD.md
 *   4. <cwd>/.weave/WARD.md
 *   5. ~/.qoder/WARD.md (user-global)
 *
 * Output: deny prints permissionDecision "deny"; require_approval prints
 * "ask" (the harness asks the user). Anything else prints {} so Qoder CLI's own
 * permission flow still applies: an explicit "allow" is never sent.
 *
 * Qoder CLI lets a call through when a hook crashes, times out or exits
 * with anything but 2. So this handler never throws and always exits 0 with a
 * decision:
 *   - A WARD.md that exists but is invalid always denies: a typo must not
 *     silently switch enforcement off.
 *   - Malformed payloads and evaluator errors allow by default (with a note
 *     on stderr), like Weave's other adapters; --fail-closed denies instead.
 */

import { readFileSync, existsSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';
import { parseAndValidate, reportEvent, type WardPolicy } from '@weave_protocol/ward';
import { evaluateWithLedger } from '@weave_protocol/ward/ledger';
import { TOOL_MAPPINGS, type HookInput, type HookOutput } from './types.js';
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
    cwd && join(cwd, '.qoder', 'WARD.md'),
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

/** The call to decide: the tool and its arguments as the harness sends them. */
export function normalizeInput(toolName: string, input: Record<string, unknown> | undefined, cwd: string) {
  return { name: toolName, args: { ...(input ?? {}) }, commandCwd: cwd };
}

/** Decide a Qoder CLI tool call against a WARD policy. */
export function evaluateCall(
  policy: WardPolicy,
  toolName: string,
  toolInput: Record<string, unknown> | undefined,
  cwd: string = process.cwd(),
  session?: string,
): HookDecision {
  const { name, args, commandCwd } = normalizeInput(toolName, toolInput, cwd);
  // evaluateWithLedger adds WARD.md's session and spend limits, signed-policy
  // checks and receipts
  const { decision, reasons } = evaluateWithLedger(policy, name, args, { mappings: TOOL_MAPPINGS, cwd: commandCwd, session, surface: 'qoder' });
  return { decision, reasons };
}

const decide = (permissionDecision: 'deny' | 'ask', reason: string): HookOutput => ({
  hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision, permissionDecisionReason: reason },
});

/** WARD decision → Qoder CLI output. */
export function toHookOutput(result: HookDecision, source: string): HookOutput {
  if (result.decision === 'deny') return decide('deny', `WARD: ${result.reasons.join(' | ')} (policy: ${source})`);
  if (result.decision === 'require_approval') {
    return decide('ask', `WARD requires approval before this call: ${result.reasons.join(' | ')} (policy: ${source})`);
  }
  return {};
}

async function readStdin(): Promise<string> {
  if (process.stdin.isTTY) return '';
  let data = '';
  process.stdin.setEncoding('utf8');
  for await (const chunk of process.stdin) data += chunk;
  return data;
}

function emit(output: HookOutput): never {
  process.stdout.write(JSON.stringify(output));
  process.exit(0);
}

export async function runPreToolUseHook(failClosed: boolean): Promise<never> {
  try {
    return await handle(failClosed);
  } catch (err) {
    // Never crash: Qoder CLI would let the call through without a word
    const msg = err instanceof Error ? err.message : String(err);
    if (failClosed) emit(decide('deny', `WARD hook failed: ${msg}`));
    process.stderr.write(`weave-qoder: hook failed (${msg}), allowing\n`);
    emit({});
  }
}

async function handle(failClosed: boolean): Promise<never> {
  const raw = await readStdin();
  if (!raw.trim()) emit({});

  let payload: HookInput;
  try {
    payload = JSON.parse(raw);
  } catch {
    if (failClosed) emit(decide('deny', 'WARD hook: malformed payload from Qoder CLI'));
    process.stderr.write('weave-qoder: malformed hook payload, allowing\n');
    emit({});
  }
  if (!payload.tool_name) emit({});

  const cwd = payload.cwd || process.env.QODER_PROJECT_DIR || process.cwd();

  let resolved: ResolvedWard | null;
  try {
    resolved = resolveWardForCwd(cwd);
  } catch (err) {
    // A policy exists but can't be used: deny rather than run unprotected.
    emit(decide('deny', `WARD policy could not be loaded: ${err instanceof Error ? err.message : String(err)}. Fix WARD.md to continue.`));
  }
  if (!resolved) emit({});

  let result: HookDecision;
  try {
    result = evaluateCall(resolved.policy, payload.tool_name, payload.tool_input, cwd, payload.session_id);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (failClosed) emit(decide('deny', `WARD evaluation failed: ${msg}`));
    process.stderr.write(`weave-qoder: WARD evaluation failed (${msg}), allowing\n`);
    emit({});
  }

  // Dashboard reporting (only when WEAVE_DASHBOARD_URL is set; at most 250ms)
  await reportEvent({ surface: 'qoder', decision: result.decision, subject: payload.tool_name, reason: result.reasons[0] });
  emit(toHookOutput(result, resolved.source));
}
