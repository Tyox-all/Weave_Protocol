/**
 * Mund - The Guardian Protocol
 * Canary Tokens - detect system prompt leakage (OWASP LLM07)
 *
 * Generate a unique marker, place it in your system prompt (or any
 * confidential context), and Mund flags any scanned output that
 * contains it. A model that has been talked into revealing its
 * instructions reveals the canary with them.
 *
 * Matching tolerates the cheap evasions a leaking model or an attacker
 * might apply: case changes, inserted whitespace / zero-width
 * characters / punctuation, base64 encoding, and reversal.
 */

import { randomBytes } from 'crypto';
import { readFileSync } from 'fs';
import type { DetectionRule, IAnalyzer, SecurityIssue } from './types.js';

export interface Canary {
  token: string;
  label: string;
  createdAt: string;
}

export type CanaryMatchKind = 'exact' | 'obfuscated' | 'base64' | 'reversed';

const TOKEN_PREFIX = 'MUND-CANARY-';
const MIN_TOKEN_LENGTH = 12;
const ZERO_WIDTH = /[​-‍⁠﻿]/g;

/** Lowercase and keep only letters and digits. */
function squash(text: string): string {
  return text.replace(ZERO_WIDTH, '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

export class CanaryRegistry {
  private canaries = new Map<string, Canary>();

  /** Create a new random canary token. */
  create(label = 'system-prompt'): Canary {
    const canary: Canary = {
      token: TOKEN_PREFIX + randomBytes(8).toString('hex').toUpperCase(),
      label,
      createdAt: new Date().toISOString(),
    };
    this.canaries.set(canary.token, canary);
    return canary;
  }

  /** Register an existing token (e.g. one already deployed in a prompt). */
  register(token: string, label = 'system-prompt'): Canary {
    if (squash(token).length < MIN_TOKEN_LENGTH) {
      throw new Error(`Canary token must contain at least ${MIN_TOKEN_LENGTH} letters/digits to avoid false positives`);
    }
    const canary: Canary = { token, label, createdAt: new Date().toISOString() };
    this.canaries.set(token, canary);
    return canary;
  }

  remove(token: string): boolean {
    return this.canaries.delete(token);
  }

  list(): Canary[] {
    return [...this.canaries.values()];
  }

  get size(): number {
    return this.canaries.size;
  }

  /** Find every registered canary that appears in the content. */
  find(content: string): Array<{ canary: Canary; kind: CanaryMatchKind; index: number }> {
    const hits: Array<{ canary: Canary; kind: CanaryMatchKind; index: number }> = [];
    if (this.canaries.size === 0 || !content) return hits;

    const lower = content.toLowerCase();
    const squashed = squash(content);
    const decoded = decodeBase64Runs(content).map(squash);

    for (const canary of this.canaries.values()) {
      const needle = squash(canary.token);
      const exactAt = lower.indexOf(canary.token.toLowerCase());

      if (exactAt !== -1) {
        hits.push({ canary, kind: 'exact', index: exactAt });
      } else if (squashed.includes(needle)) {
        hits.push({ canary, kind: 'obfuscated', index: -1 });
      } else if (decoded.some(d => d.includes(needle))) {
        hits.push({ canary, kind: 'base64', index: -1 });
      } else if (squashed.includes([...needle].reverse().join(''))) {
        hits.push({ canary, kind: 'reversed', index: -1 });
      }
    }
    return hits;
  }
}

/** Decode every plausible base64 run in the text (best effort). */
function decodeBase64Runs(content: string): string[] {
  const runs = content.match(/[A-Za-z0-9+/]{16,}={0,2}/g) ?? [];
  const out: string[] = [];
  for (const run of runs) {
    try {
      const text = Buffer.from(run, 'base64').toString('utf8');
      if (/^[\x20-\x7E\s]+$/.test(text)) out.push(text);
    } catch {
      // not base64
    }
  }
  return out;
}

/** Shared registry used by the MCP tools and the default analyzer set. */
export const canaries = new CanaryRegistry();

/** Load canaries from MUND_CANARIES (comma-separated) or MUND_CANARY_FILE (one per line). */
export function loadCanariesFromEnv(registry: CanaryRegistry = canaries): number {
  const tokens: string[] = [];
  if (process.env.MUND_CANARIES) tokens.push(...process.env.MUND_CANARIES.split(','));
  if (process.env.MUND_CANARY_FILE) {
    try {
      tokens.push(...readFileSync(process.env.MUND_CANARY_FILE, 'utf8').split('\n'));
    } catch {
      // missing file: nothing to load
    }
  }
  let loaded = 0;
  for (const t of tokens.map(t => t.trim()).filter(Boolean)) {
    try {
      registry.register(t, 'env');
      loaded++;
    } catch {
      // too short; skip
    }
  }
  return loaded;
}

export class CanaryDetector implements IAnalyzer {
  name = 'CanaryDetector';
  type = 'exfiltration';

  constructor(private registry: CanaryRegistry = canaries) {}

  async analyze(content: string, _rules: DetectionRule[]): Promise<SecurityIssue[]> {
    return this.registry.find(content).map(({ canary, kind, index }) => {
      const before = index >= 0 ? content.slice(0, index).split('\n') : null;
      return {
        rule_id: 'canary_leak',
        rule_name: `Canary token leaked (${kind})`,
        type: 'exfiltration',
        severity: 'critical',
        action: 'block',
        match: `${canary.token.slice(0, TOKEN_PREFIX.length + 4)}…`,
        ...(before
          ? { location: { start: index, end: index + canary.token.length, line: before.length, column: before[before.length - 1].length + 1 } }
          : {}),
        suggestion:
          `Content contains the "${canary.label}" canary, so confidential instructions or context are leaking. ` +
          'Block this output and review the prompt that produced it.',
      };
    });
  }
}
