/**
 * Hook handler for Cursor's agent hooks. Reads the payload from stdin, finds
 * the active WARD.md, decides with Ward's shared evaluator, and prints
 * Cursor's permission output.
 *
 * WARD.md resolution (root = the first workspace root, else cwd):
 *   1. $WEAVE_WARD_PATH
 *   2. <root>/WARD.md
 *   3. <root>/.cursor/WARD.md
 *   4. <root>/.weave/WARD.md
 *   5. ~/.cursor/WARD.md (user-global)
 *
 * Output: an allowed call prints nothing, so Cursor's own approval settings
 * still apply. A deny prints permission "deny" with the reason. A WARD
 * require_approval prints "ask" on shell and MCP calls, where Cursor
 * enforces it, and "deny" elsewhere (preToolUse doesn't enforce "ask", and
 * beforeReadFile has none).
 *
 * Failure modes:
 *   - A WARD.md that exists but is invalid always denies.
 *   - Malformed payloads and evaluator errors allow by default (with a note
 *     on stderr); --fail-closed denies instead.
 */

import { readFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { parseAndValidate, evaluateToolCall, type WardPolicy } from '@weave_protocol/ward';
import { TOOL_MAPPINGS, type CursorHookInput, type CursorHookOutput } from './types.js';
import { userWardPath } from './config.js';

export interface ResolvedWard {
  policy: WardPolicy;
  source: string;
}

export interface HookDecision {
  decision: 'allow' | 'deny' | 'require_approval';
  reasons: string[];
}

/** A tool call extracted from one of the four events, or null to skip it. */
export interface ToolCall {
  tool: string;
  args: Record<string, unknown>;
  cwd: string;
  /** Whether Cursor enforces "ask" for this event */
  canAsk: boolean;
}

export function resolveWardForRoot(root: string): ResolvedWard | null {
  const candidates = [
    process.env.WEAVE_WARD_PATH,
    root && join(root, 'WARD.md'),
    root && join(root, '.cursor', 'WARD.md'),
    root && join(root, '.weave', 'WARD.md'),
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

const asObject = (v: unknown): Record<string, unknown> => {
  if (typeof v === 'string') {
    try {
      v = JSON.parse(v);
    } catch {
      return {};
    }
  }
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
};

/** Turn a Cursor hook payload into the tool call Ward should decide. */
export function toToolCall(payload: CursorHookInput, fallbackCwd = process.cwd()): ToolCall | null {
  const root = payload.workspace_roots?.[0] || fallbackCwd;
  const cwd = payload.cwd || root;
  switch (payload.hook_event_name) {
    case 'beforeShellExecution':
      return { tool: 'Shell', args: { command: payload.command ?? '', cwd }, cwd, canAsk: true };
    case 'beforeMCPExecution': {
      const server = (payload.mcp_server_name ?? 'unknown').replace(/[^A-Za-z0-9_-]/g, '_');
      return { tool: `mcp__${server}__${payload.tool_name ?? ''}`, args: asObject(payload.tool_input), cwd, canAsk: true };
    }
    case 'beforeReadFile':
      return { tool: 'Read', args: { file_path: payload.file_path ?? '' }, cwd, canAsk: false };
    case 'preToolUse': {
      const tool = payload.tool_name ?? '';
      // Shell, Read and MCP calls are decided by the dedicated events above
      if (tool === 'Shell' || tool === 'Read' || tool.startsWith('MCP:')) return null;
      return { tool, args: asObject(payload.tool_input), cwd, canAsk: false };
    }
    default:
      return null;
  }
}

/** Decide a Cursor tool call against a WARD policy. */
export function evaluateCall(policy: WardPolicy, call: ToolCall): HookDecision {
  const { decision, reasons } = evaluateToolCall(policy, call.tool, call.args, { mappings: TOOL_MAPPINGS, cwd: call.cwd });
  return { decision, reasons };
}

/** WARD decision → Cursor output; undefined means print nothing. */
export function toHookOutput(result: HookDecision, source: string, canAsk: boolean): CursorHookOutput | undefined {
  if (result.decision === 'allow') return undefined;
  if (result.decision === 'require_approval' && canAsk) {
    const msg = `WARD requires approval: ${result.reasons.join(' | ')} (policy: ${source})`;
    return { permission: 'ask', user_message: msg, agent_message: msg };
  }
  const msg = result.decision === 'deny'
    ? `WARD: ${result.reasons.join(' | ')} (policy: ${source})`
    : `WARD requires approval before this call: ${result.reasons.join(' | ')} (policy: ${source}). Ask the user to approve it or update WARD.md.`;
  return { permission: 'deny', user_message: msg, agent_message: msg };
}

async function readStdin(): Promise<string> {
  if (process.stdin.isTTY) return '';
  let data = '';
  process.stdin.setEncoding('utf8');
  for await (const chunk of process.stdin) data += chunk;
  return data;
}

function emit(output?: CursorHookOutput): never {
  if (output) process.stdout.write(JSON.stringify(output));
  process.exit(0);
}

const denyWith = (msg: string): CursorHookOutput => ({ permission: 'deny', user_message: msg, agent_message: msg });

export async function runHook(failClosed: boolean): Promise<never> {
  const raw = await readStdin();
  if (!raw.trim()) emit();

  let payload: CursorHookInput;
  try {
    payload = JSON.parse(raw);
  } catch {
    if (failClosed) emit(denyWith('WARD hook: malformed payload from Cursor'));
    process.stderr.write('weave-ward-cursor: malformed hook payload, allowing\n');
    emit();
  }

  const call = toToolCall(payload);
  if (!call) emit();

  let resolved: ResolvedWard | null;
  try {
    resolved = resolveWardForRoot(payload.workspace_roots?.[0] || call.cwd);
  } catch (err) {
    // A policy exists but can't be used: deny rather than run unprotected.
    emit(denyWith(`WARD policy could not be loaded: ${err instanceof Error ? err.message : String(err)}. Fix WARD.md to continue.`));
  }
  if (!resolved) emit();

  let result: HookDecision;
  try {
    result = evaluateCall(resolved.policy, call);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (failClosed) emit(denyWith(`WARD evaluation failed: ${msg}`));
    process.stderr.write(`weave-ward-cursor: WARD evaluation failed (${msg}), allowing\n`);
    emit();
  }

  emit(toHookOutput(result, resolved.source, call.canAsk));
}
