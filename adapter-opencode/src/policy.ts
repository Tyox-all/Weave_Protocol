/**
 * WARD decisions for OpenCode tool calls, with Ward's shared evaluator.
 *
 * Tool and argument names are OpenCode 1.19's (packages/opencode/src/tool):
 * bash { command, workdir }, read/write/edit { filePath }, glob/grep
 * { path }, webfetch { url }, apply_patch { patchText }. MCP tools arrive
 * as <server>_<tool>; Ward checks their path and URL arguments by name.
 */

import { readFileSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { parseAndValidate, evaluateToolCall, type ToolMapping, type WardPolicy } from '@weave_protocol/ward';
import { evaluateWithLedger } from '@weave_protocol/ward/ledger';
import { patchTargets } from './patch.js';

export const TOOL_MAPPINGS: Record<string, ToolMapping> = {
  bash: { capability: 'shell_exec', commandField: 'command', pathField: 'workdir', fsOp: 'read' },
  read: { capability: 'file_read', pathField: 'filePath', fsOp: 'read' },
  write: { capability: 'file_write', pathField: 'filePath', fsOp: 'write' },
  edit: { capability: 'file_write', pathField: 'filePath', fsOp: 'write' },
  glob: { capability: 'file_list', pathField: 'path', fsOp: 'list' },
  grep: { capability: 'file_read', pathField: 'path', fsOp: 'read' },
  webfetch: { capability: 'http_request', urlField: 'url' },
  websearch: { capability: 'web_search' },
  task: { capability: 'subagent' },
  skill: { capability: 'skill' },
  todowrite: { capability: 'task_planning' },
  question: { capability: 'task_planning' },
};

export interface ResolvedWard {
  policy: WardPolicy;
  source: string;
}

export interface WardDecision {
  decision: 'allow' | 'deny' | 'require_approval';
  reasons: string[];
}

/** OpenCode's global config directory ($XDG_CONFIG_HOME/opencode, default ~/.config/opencode). */
export function opencodeConfigDir(): string {
  return join(process.env.XDG_CONFIG_HOME || join(homedir(), '.config'), 'opencode');
}

/**
 * WARD.md resolution: $WEAVE_WARD_PATH, then <dir>/WARD.md,
 * <dir>/.opencode/WARD.md, <dir>/.weave/WARD.md, then the global
 * ~/.config/opencode/WARD.md. Throws on an invalid policy.
 */
export function resolveWard(dir: string): ResolvedWard | null {
  const candidates = [
    process.env.WEAVE_WARD_PATH,
    dir && join(dir, 'WARD.md'),
    dir && join(dir, '.opencode', 'WARD.md'),
    dir && join(dir, '.weave', 'WARD.md'),
    join(opencodeConfigDir(), 'WARD.md'),
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

/** Decide an OpenCode tool call. */
export function evaluateCall(policy: WardPolicy, tool: string, args: unknown, dir: string, session?: string): WardDecision {
  const input = args && typeof args === 'object' && !Array.isArray(args) ? (args as Record<string, unknown>) : {};

  // apply_patch: the files the patch writes and deletes, not its text
  if (tool === 'apply_patch') {
    const { writes, deletes } = patchTargets(String(input.patchText ?? ''));
    const check = (target: string[], fsOp: 'write' | 'delete') =>
      evaluateToolCall(policy, tool, { target }, {
        cwd: dir,
        mappings: { apply_patch: { capability: 'file_write', pathField: 'target', fsOp } },
      });
    const results = [check(writes, 'write'), ...(deletes.length ? [check(deletes, 'delete')] : [])];
    // The patch counts once against WARD.md's session and spend limits
    if (results.every((r) => r.decision !== 'deny')) {
      results.push(evaluateWithLedger(policy, tool, {}, { cwd: dir, session, mappings: { apply_patch: { capability: 'file_write' } } }));
    }
    const worst = results.reduce((a, b) => (RANK[b.decision] > RANK[a.decision] ? b : a));
    return { decision: worst.decision, reasons: results.flatMap((r) => r.reasons) };
  }

  // bash runs in workdir when one is given
  const cwd = tool === 'bash' && typeof input.workdir === 'string' && input.workdir
    ? (isAbsolute(input.workdir) ? input.workdir : join(dir, input.workdir))
    : dir;
  // evaluateWithLedger adds WARD.md's session and spend limits (Ward 0.3.6)
  const { decision, reasons } = evaluateWithLedger(policy, tool, input, { mappings: TOOL_MAPPINGS, cwd, session });
  return { decision, reasons };
}

/** The error message the agent sees for a blocked call, or null to let it run. */
export function blockMessage(result: WardDecision, source: string): string | null {
  if (result.decision === 'deny') return `WARD: ${result.reasons.join(' | ')} (policy: ${source})`;
  if (result.decision === 'require_approval') {
    return `WARD requires approval before this call: ${result.reasons.join(' | ')} (policy: ${source}). Ask the user to approve it or update WARD.md.`;
  }
  return null;
}
