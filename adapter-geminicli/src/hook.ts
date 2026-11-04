/**
 * BeforeTool hook handler: reads Gemini CLI's payload from stdin, finds the
 * active WARD.md, decides with Ward's shared evaluator, and prints the
 * decision.
 *
 * WARD.md resolution (cwd = the payload's cwd):
 *   1. $WEAVE_WARD_PATH
 *   2. <cwd>/WARD.md
 *   3. <cwd>/.gemini/WARD.md
 *   4. <cwd>/.weave/WARD.md
 *   5. ~/.gemini/WARD.md (user-global)
 *
 * Output: a deny prints { decision: "deny", reason }. Anything else prints
 * {} so Gemini CLI's own confirmation flow still applies (an explicit
 * "allow" is never sent). Gemini CLI has no "ask", so require_approval is a
 * deny that says approval is needed.
 *
 * Failure modes:
 *   - A WARD.md that exists but is invalid always denies: a typo must not
 *     silently switch enforcement off.
 *   - Malformed payloads and evaluator errors allow by default (with a note
 *     on stderr); --fail-closed denies instead.
 */

import { readFileSync, existsSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';
import { parseAndValidate, evaluateToolCall, reportEvent, type WardPolicy } from '@weave_protocol/ward';
import { TOOL_MAPPINGS, type GeminiHookInput, type GeminiHookOutput } from './types.js';
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
    cwd && join(cwd, '.gemini', 'WARD.md'),
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

const URL_IN_TEXT = /[a-z][a-z0-9+.-]*:\/\/[^\s'"`<>()]+/gi;

/**
 * Shape Gemini CLI arguments for Ward: web_fetch's URLs live inside its
 * free-text prompt, and a shell command runs in dir_path.
 */
export function normalizeInput(toolName: string, input: Record<string, unknown> | undefined, cwd: string) {
  const args = { ...(input ?? {}) };
  let commandCwd = cwd;
  if (toolName === 'web_fetch' && typeof args.prompt === 'string') {
    args.urls = (args.prompt.match(URL_IN_TEXT) ?? []).map((u) => u.replace(/[.,;:!?]+$/, ''));
  }
  if (toolName === 'run_shell_command' && typeof args.dir_path === 'string' && args.dir_path) {
    commandCwd = isAbsolute(args.dir_path) ? args.dir_path : join(cwd, args.dir_path);
  }
  return { args, commandCwd };
}

/** Decide a Gemini CLI tool call against a WARD policy. */
export function evaluateCall(
  policy: WardPolicy,
  toolName: string,
  toolInput: Record<string, unknown> | undefined,
  cwd: string = process.cwd(),
): HookDecision {
  const { args, commandCwd } = normalizeInput(toolName, toolInput, cwd);
  const { decision, reasons } = evaluateToolCall(policy, toolName, args, { mappings: TOOL_MAPPINGS, cwd: commandCwd });
  return { decision, reasons };
}

/** WARD decision → Gemini CLI output. */
export function toHookOutput(result: HookDecision, source: string): GeminiHookOutput {
  if (result.decision === 'deny') {
    return { decision: 'deny', reason: `WARD: ${result.reasons.join(' | ')} (policy: ${source})` };
  }
  if (result.decision === 'require_approval') {
    return {
      decision: 'deny',
      reason: `WARD requires approval before this call: ${result.reasons.join(' | ')} (policy: ${source}). Ask the user to approve it or update WARD.md.`,
    };
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

function emit(output: GeminiHookOutput): never {
  process.stdout.write(JSON.stringify(output));
  process.exit(0);
}

export async function runBeforeToolHook(failClosed: boolean): Promise<never> {
  const raw = await readStdin();
  if (!raw.trim()) emit({});

  let payload: GeminiHookInput;
  try {
    payload = JSON.parse(raw);
  } catch {
    if (failClosed) emit({ decision: 'deny', reason: 'WARD hook: malformed payload from Gemini CLI' });
    process.stderr.write('weave-gemini: malformed hook payload, allowing\n');
    emit({});
  }
  if (!payload.tool_name) emit({});

  const cwd = payload.cwd || process.env.GEMINI_PROJECT_DIR || process.cwd();

  let resolved: ResolvedWard | null;
  try {
    resolved = resolveWardForCwd(cwd);
  } catch (err) {
    // A policy exists but can't be used: deny rather than run unprotected.
    emit({ decision: 'deny', reason: `WARD policy could not be loaded: ${err instanceof Error ? err.message : String(err)}. Fix WARD.md to continue.` });
  }
  if (!resolved) emit({});

  let result: HookDecision;
  try {
    result = evaluateCall(resolved.policy, payload.tool_name, payload.tool_input, cwd);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (failClosed) emit({ decision: 'deny', reason: `WARD evaluation failed: ${msg}` });
    process.stderr.write(`weave-gemini: WARD evaluation failed (${msg}), allowing\n`);
    emit({});
  }

  // Dashboard reporting (only when WEAVE_DASHBOARD_URL is set; at most 250ms)
  await reportEvent({ surface: 'gemini-cli', decision: result.decision, subject: payload.tool_name, reason: result.reasons[0] });
  emit(toHookOutput(result, resolved.source));
}
