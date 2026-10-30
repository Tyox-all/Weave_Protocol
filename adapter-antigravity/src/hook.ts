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
 * Failure mode (when WARD parse fails):
 *   - default: fail OPEN (warn to stderr, allow)
 *   - --fail-closed: fail CLOSED (block with the error reason)
 */

import { readFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { homedir } from 'node:os';
import {
  parseWard,
  checkCapability,
  checkFilesystem,
  checkNetwork,
  type WardPolicy,
  type HttpMethod,
} from '@weave_protocol/ward';
import {
  TOOL_MAPPINGS,
  type AntigravityHookInput,
  type AntigravityHookOutput,
  type ToolMapping,
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
      const source = readFileSync(resolved, 'utf8');
      const policy = parseWard(source);
      return { policy, source: resolved };
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

export function evaluateCall(
  policy: WardPolicy,
  toolName: string,
  toolInput: Record<string, unknown> | undefined,
): HookDecision {
  const reasons: string[] = [];
  let decision: 'allow' | 'deny' | 'require_approval' = 'allow';

  const mapping: ToolMapping = TOOL_MAPPINGS[toolName] || { capability: toolName };

  // 1. Capability check
  const capByMapping = checkCapability(policy, mapping.capability);
  const capByRaw = checkCapability(policy, toolName);
  const cap = mergeCapability(capByMapping, capByRaw);
  if (cap.decision === 'deny') {
    return { decision: 'deny', reasons: [cap.reason] };
  }
  if (cap.decision === 'require_approval') {
    decision = 'require_approval';
    reasons.push(cap.reason);
  }

  // 2. Filesystem check
  if (mapping.pathField && toolInput && typeof toolInput[mapping.pathField] === 'string') {
    const path = toolInput[mapping.pathField] as string;
    const fs = checkFilesystem(policy, mapping.fsOp || 'read', path);
    if (fs.decision === 'deny') {
      return { decision: 'deny', reasons: [fs.reason] };
    }
    if (fs.decision === 'require_approval' && decision !== 'require_approval') {
      decision = 'require_approval';
      reasons.push(fs.reason);
    }
  }

  // 3. Network check
  if (mapping.urlField && toolInput && typeof toolInput[mapping.urlField] === 'string') {
    const url = toolInput[mapping.urlField] as string;
    const method = (toolInput.method as HttpMethod) || 'GET';
    const net = checkNetwork(policy, url, method);
    if (net.decision === 'deny') {
      return { decision: 'deny', reasons: [net.reason] };
    }
    if (net.decision === 'require_approval' && decision !== 'require_approval') {
      decision = 'require_approval';
      reasons.push(net.reason);
    }
  }

  // 4. Bash command heuristic scan
  if (mapping.commandField && toolInput && typeof toolInput[mapping.commandField] === 'string') {
    const command = toolInput[mapping.commandField] as string;
    const bashCheck = scanBashCommand(policy, command);
    if (bashCheck.decision === 'deny') {
      return { decision: 'deny', reasons: [bashCheck.reason] };
    }
    if (bashCheck.decision === 'require_approval' && decision !== 'require_approval') {
      decision = 'require_approval';
      reasons.push(bashCheck.reason);
    }
  }

  return { decision, reasons };
}

function isExplicit(reason: string): boolean {
  return (
    reason.includes('is in the allow list') ||
    reason.includes('is in the deny list') ||
    reason.includes('requires human approval')
  );
}

function mergeCapability(
  a: { decision: 'allow' | 'deny' | 'require_approval'; reason: string },
  b: { decision: 'allow' | 'deny' | 'require_approval'; reason: string },
): { decision: 'allow' | 'deny' | 'require_approval'; reason: string } {
  const aExp = isExplicit(a.reason);
  const bExp = isExplicit(b.reason);

  if (aExp && !bExp) return a;
  if (bExp && !aExp) return b;

  if (a.decision === 'deny' || b.decision === 'deny') {
    return a.decision === 'deny' ? a : b;
  }
  if (a.decision === 'require_approval' || b.decision === 'require_approval') {
    return a.decision === 'require_approval' ? a : b;
  }
  return a;
}

function scanBashCommand(
  policy: WardPolicy,
  command: string,
): { decision: 'allow' | 'deny' | 'require_approval'; reason: string } {
  const urlMatch = command.match(/https?:\/\/[^\s'"`)]+/);
  if (urlMatch) {
    const net = checkNetwork(policy, urlMatch[0], 'GET');
    if (net.decision === 'deny') return { decision: 'deny', reason: `bash command targets ${urlMatch[0]}: ${net.reason}` };
    if (net.decision === 'require_approval') return { decision: 'require_approval', reason: `bash command targets ${urlMatch[0]}: ${net.reason}` };
  }

  const dangerousPaths = ['~/.ssh', '~/.aws', '~/.config/gcloud', '/etc/', '/usr/', '/.env'];
  for (const danger of dangerousPaths) {
    if (command.includes(danger)) {
      let op: 'read' | 'write' | 'delete' = 'read';
      if (/(?:^|[\s;|])rm\s/.test(command)) op = 'delete';
      else if (/>|>>|tee|sed -i/.test(command)) op = 'write';

      const fs = checkFilesystem(policy, op, danger + (danger.endsWith('/') ? '**' : ''));
      if (fs.decision === 'deny') return { decision: 'deny', reason: `bash touches ${danger}: ${fs.reason}` };
      if (fs.decision === 'require_approval') return { decision: 'require_approval', reason: `bash touches ${danger}: ${fs.reason}` };
    }
  }

  return { decision: 'allow', reason: '' };
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
    const msg = err instanceof Error ? err.message : String(err);
    if (failClosed) emit({ decision: 'deny', reason: `WARD policy could not be loaded: ${msg}` });
    process.stderr.write(`weave-antigravity: WARD load failed (${msg}), allowing\n`);
    emit();
  }
  if (!resolved) emit();

  let result: HookDecision;
  try {
    result = evaluateCall(resolved.policy, tool, args);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (failClosed) emit({ decision: 'deny', reason: `WARD evaluation failed: ${msg}` });
    process.stderr.write(`weave-antigravity: WARD eval failed (${msg}), allowing\n`);
    emit();
  }

  emit(toHookOutput(result, resolved.source));
}
