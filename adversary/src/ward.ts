/**
 * WARD policy loading + ward-aware attack selection.
 *
 * The differentiator: when a target has a WARD.md, Adversary reads it and
 * prioritizes attacks that probe the rules the policy claims to enforce.
 * This is what makes Adversary feel like a real red-team tool rather than
 * a generic prompt-injection fuzzer.
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { Attack, WardPolicy } from './types.js';

const EMPTY_POLICY: WardPolicy = {
  loaded: false,
  allowedCapabilities: [],
  deniedCapabilities: [],
  approvalCapabilities: [],
  allowedUrls: [],
  deniedUrls: [],
  defaultDecision: 'deny',
};

/**
 * Load a WARD.md from one of the standard locations. Returns an empty
 * policy if none found.
 */
export function loadWardPolicy(cwd: string = process.cwd()): WardPolicy {
  const candidates = [
    process.env.WEAVE_WARD_PATH,
    join(cwd, 'WARD.md'),
    join(cwd, '.weave', 'WARD.md'),
  ].filter(Boolean) as string[];

  for (const path of candidates) {
    if (existsSync(path)) {
      try {
        const text = readFileSync(path, 'utf8');
        return parseWardPolicy(text, path);
      } catch {
        // continue
      }
    }
  }
  return EMPTY_POLICY;
}

/**
 * Parse the contents of a WARD.md file into a structured policy.
 * Intentionally lenient — we only need enough fidelity for attack selection.
 */
export function parseWardPolicy(text: string, source?: string): WardPolicy {
  const policy: WardPolicy = { ...EMPTY_POLICY, loaded: true, source };

  // Network section
  const netAllow = extractList(text, /## Network/i, /allow:/i, /(?:deny:|require[Aa]pproval:|default:|^##)/m);
  const netDeny = extractList(text, /## Network/i, /deny:/i, /(?:allow:|require[Aa]pproval:|default:|^##)/m);
  for (const item of netAllow) {
    const url = extractQuotedValue(item, 'url');
    if (url) policy.allowedUrls.push(url);
  }
  for (const item of netDeny) {
    const url = extractQuotedValue(item, 'url');
    if (url) policy.deniedUrls.push(url);
  }

  // Capabilities section
  const capAllow = extractList(text, /## Capabilities/i, /allow:/i, /(?:deny:|require[Aa]pproval:|default:|^##)/m);
  const capDeny = extractList(text, /## Capabilities/i, /deny:/i, /(?:allow:|require[Aa]pproval:|default:|^##)/m);
  const capApproval = extractList(text, /## Capabilities/i, /require[Aa]pproval:/i, /(?:allow:|deny:|default:|^##)/m);
  policy.allowedCapabilities = capAllow.map(stripBullet).filter(Boolean);
  policy.deniedCapabilities = capDeny.map(stripBullet).filter(Boolean);
  policy.approvalCapabilities = capApproval.map(stripBullet).filter(Boolean);

  // Default decision
  const def = text.match(/^default:\s*(\w+)/m);
  if (def) {
    const v = def[1].toLowerCase();
    if (v === 'allow' || v === 'deny' || v === 'require_approval') policy.defaultDecision = v;
  }

  return policy;
}

function extractList(text: string, sectionRe: RegExp, startRe: RegExp, endRe: RegExp): string[] {
  const sectionStart = text.search(sectionRe);
  if (sectionStart < 0) return [];
  const section = text.slice(sectionStart);
  const startIdx = section.search(startRe);
  if (startIdx < 0) return [];
  const tail = section.slice(startIdx);
  // Skip first 20 chars so we don't immediately match the start marker itself
  const endIdx = tail.slice(20).search(endRe);
  const block = endIdx < 0 ? tail : tail.slice(0, 20 + endIdx);
  return (block.match(/^\s+-\s+.+$/gm) || []);
}

function extractQuotedValue(line: string, key: string): string | null {
  const m = line.match(new RegExp(`${key}\\s*:\\s*["']([^"']+)["']`));
  return m ? m[1] : null;
}

function stripBullet(line: string): string {
  return line.replace(/^\s*-\s+/, '').trim();
}

/**
 * Score how relevant each attack is to a given WARD policy.
 *
 * Higher score = more relevant to test (attacks the policy claims to
 * enforce). Used by ward-aware selection to prioritize the time budget.
 */
export function scoreAttackForPolicy(attack: Attack, policy: WardPolicy): number {
  if (!policy.loaded) return 1;  // No policy — all attacks equally relevant

  let score = 1;
  for (const probed of attack.wardRulesProbed) {
    // Direct capability match
    const cap = probed.replace(/^capabilities\./, '');
    if (policy.deniedCapabilities.includes(cap)) score += 5;
    if (policy.approvalCapabilities.includes(cap)) score += 3;
    if (policy.allowedCapabilities.includes(cap)) score += 1;

    // Network match
    if (probed.startsWith('network.') && (policy.deniedUrls.length || policy.allowedUrls.length)) {
      score += 3;
    }

    // Filesystem
    if (probed.startsWith('filesystem.') && policy.deniedCapabilities.some((c) => c.includes('file'))) {
      score += 3;
    }

    // Data boundaries
    if (probed.startsWith('data_boundaries.')) score += 2;

    // Behavioral
    if (probed.startsWith('behavioral.')) score += 1;
  }
  return score;
}

/**
 * Sort attacks by their relevance to the policy, highest first.
 * Stable sort: ties preserve original order.
 */
export function wardAwareSort(attacks: Attack[], policy: WardPolicy): Attack[] {
  const scored = attacks.map((a, i) => ({ a, score: scoreAttackForPolicy(a, policy), i }));
  scored.sort((x, y) => {
    if (y.score !== x.score) return y.score - x.score;
    return x.i - y.i;
  });
  return scored.map((s) => s.a);
}
