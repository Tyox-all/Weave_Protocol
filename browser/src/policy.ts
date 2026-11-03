/**
 * WARD policy loading + evaluation for browser-agent guards.
 *
 * Resolution order:
 *   1. wardPath option (explicit)
 *   2. wardSource option (raw markdown — useful for tests)
 *   3. $WEAVE_WARD_PATH env var
 *   4. <cwd>/WARD.md
 *   5. <cwd>/.weave/WARD.md
 *   6. <cwd>/.browser/WARD.md
 */

import { readFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { parseAndValidate, checkCapability, checkNetwork, type WardPolicy } from '@weave_protocol/ward';
import type { DecisionResult } from './types.js';

export interface ResolvedWard {
  policy: WardPolicy;
  source: string;
}

export function resolveWardForCwd(cwd: string = process.cwd()): ResolvedWard | null {
  const candidates: string[] = [];
  if (process.env.WEAVE_WARD_PATH) candidates.push(process.env.WEAVE_WARD_PATH);
  if (cwd) {
    candidates.push(join(cwd, 'WARD.md'));
    candidates.push(join(cwd, '.weave', 'WARD.md'));
    candidates.push(join(cwd, '.browser', 'WARD.md'));
  }
  for (const path of candidates) {
    const r = resolve(path);
    if (existsSync(r)) return loadWardFromSource(readFileSync(r, 'utf8'), r);
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

export function loadWardFromPath(path: string): ResolvedWard {
  if (!existsSync(path)) throw new Error(`WARD.md not found at ${path}`);
  return loadWardFromSource(readFileSync(path, 'utf8'), path);
}

// ============================================================================
// Browser-specific policy evaluations
// ============================================================================

/**
 * Evaluate a URL navigation against WARD ## Network rules.
 *
 * Browser navigation is fundamentally an HTTP GET to the URL, so we use
 * checkNetwork() with method='GET'. WARD's allow/deny URL patterns apply.
 */
export function evaluateNavigation(policy: WardPolicy, url: string): DecisionResult {
  const result = checkNetwork(policy, url, 'GET');
  return { decision: result.decision, reasons: [result.reason] };
}

/**
 * Evaluate a download against WARD network + filesystem rules.
 *
 * Two checks combined:
 *   1. The URL — same as navigation (## Network)
 *   2. The destination filename — extension/MIME against blocked lists
 */
export function evaluateDownload(
  policy: WardPolicy,
  download: { url: string; filename: string; mimeType?: string },
  blockedExtensions: string[],
  blockedMimeTypes: string[],
): DecisionResult {
  // 1. URL check
  const urlCheck = checkNetwork(policy, download.url, 'GET');
  if (urlCheck.decision === 'deny') {
    return { decision: 'deny', reasons: [`URL: ${urlCheck.reason}`] };
  }

  const reasons: string[] = [];
  let worst: 'allow' | 'deny' | 'require_approval' = urlCheck.decision;
  if (urlCheck.decision === 'require_approval') reasons.push(`URL: ${urlCheck.reason}`);

  // 2. Extension check, on the name the OS will actually use
  const ext = fileExtension(download.filename);
  if (ext && blockedExtensions.some((b) => b.toLowerCase() === ext)) {
    return { decision: 'deny', reasons: [`Extension ${ext} is on the blocked list`] };
  }

  // 3. MIME type check (MIME types are case-insensitive)
  const mime = download.mimeType?.trim().toLowerCase();
  if (mime && blockedMimeTypes.some((m) => mime.startsWith(m.toLowerCase()))) {
    return {
      decision: 'deny',
      reasons: [`MIME type ${download.mimeType} is on the blocked list`],
    };
  }

  return { decision: worst, reasons: reasons.length ? reasons : ['Download permitted by policy'] };
}

/**
 * The extension a filename really has once saved. Windows drops trailing
 * dots and spaces ("a.exe." and "a.exe " save as "a.exe"), and anything
 * after a NUL or a path separator is not part of the extension.
 */
export function fileExtension(filename: string): string {
  const base = filename.split(/[\\/]/).pop()!.split('\0')[0].replace(/[\s.]+$/, '').toLowerCase();
  const dot = base.lastIndexOf('.');
  return dot > 0 || (dot === 0 && base.length > 1) ? base.slice(dot) : '';
}

/**
 * Evaluate a post-IPI action gate. Once content has been ingested and IPI was
 * detected, the agent's subsequent tool calls should be gated. WARD's
 * ## Capabilities section is the source of truth: if a capability requires
 * approval after untrusted ingestion, this returns require_approval.
 *
 * The simplest behaviour: any agent action that touches the network or
 * triggers an outbound communication (send_email, post_message, http_request)
 * should require approval if the session is tainted.
 */
export function evaluateTaintedAction(
  policy: WardPolicy,
  capability: string,
): DecisionResult {
  const result = checkCapability(policy, capability);
  // For tainted sessions, we elevate require_approval to that level minimum,
  // but never demote a deny.
  if (result.decision === 'deny') {
    return { decision: 'deny', reasons: [result.reason] };
  }
  // If the policy says allow but the session is tainted, conservatively
  // require approval — the agent's decision to call this capability may have
  // been induced by IPI content.
  if (result.decision === 'allow') {
    return {
      decision: 'require_approval',
      reasons: [
        `Capability '${capability}' normally allowed, but session has ingested untrusted content with IPI — approval required (2026 SOTA defense pattern)`,
      ],
    };
  }
  return { decision: result.decision, reasons: [result.reason] };
}
