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
      const source = readFileSync(resolved, 'utf8');
      const policy = parseWard(source);
      return { policy, source: resolved };
    }
  }
  return null;
}

export function loadWardFromSource(source: string, label = '<inline>'): ResolvedWard {
  return { policy: parseWard(source), source: label };
}

// ============================================================================
// Evaluation
// ============================================================================

export function evaluateCall(
  policy: WardPolicy,
  call: MsafToolCall,
  customMappings: Record<string, ToolMapping> = {},
): MsafMiddlewareResult {
  const reasons: string[] = [];
  let decision: 'allow' | 'deny' | 'require_approval' = 'allow';

  // Merge built-in + custom mappings; custom wins on conflict.
  const mapping: ToolMapping =
    customMappings[call.toolName] || TOOL_MAPPINGS[call.toolName] || { capability: call.toolName };

  // 1. Capability check (mapped name + raw name, stricter explicit wins)
  const capByMapping = checkCapability(policy, mapping.capability);
  const capByRaw = checkCapability(policy, call.toolName);
  const cap = mergeCapability(capByMapping, capByRaw);
  if (cap.decision === 'deny') {
    return { decision: 'deny', reasons: [cap.reason] };
  }
  if (cap.decision === 'require_approval') {
    decision = 'require_approval';
    reasons.push(cap.reason);
  }

  // 2. Filesystem check
  if (mapping.pathField && call.args && typeof call.args[mapping.pathField] === 'string') {
    const path = call.args[mapping.pathField] as string;
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
  if (mapping.urlField && call.args && typeof call.args[mapping.urlField] === 'string') {
    const url = call.args[mapping.urlField] as string;
    const method = (call.args.method as HttpMethod) || 'GET';
    const net = checkNetwork(policy, url, method);
    if (net.decision === 'deny') {
      return { decision: 'deny', reasons: [net.reason] };
    }
    if (net.decision === 'require_approval' && decision !== 'require_approval') {
      decision = 'require_approval';
      reasons.push(net.reason);
    }
  }

  // 4. Bash command heuristic
  if (mapping.commandField && call.args && typeof call.args[mapping.commandField] === 'string') {
    const command = call.args[mapping.commandField] as string;
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

  const dangerousPaths = [
    '~/.ssh',
    '~/.aws',
    '~/.config/gcloud',
    '~/.azure',                  // Azure credentials (relevant for MSAF users)
    '/etc/',
    '/usr/',
    '/.env',
  ];
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
