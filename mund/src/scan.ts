/**
 * Library scan: the same analyzers and default rules as the mund_scan_content
 * tool, returning issues plus a 0–100 risk score.
 */

import { AnalyzerEngine, getAnalyzers } from './analyzers/index.js';
import { DEFAULT_RULES } from './constants.js';
import { computeRiskScore, type RiskScore } from './scoring.js';
import type { DetectionRule, SecurityIssue } from './types.js';

/** Friendly scan types → analyzer types. */
export const SCAN_TYPES = {
  secrets: ['secret'],
  pii: ['pii'],
  injection: ['injection'],
  exfiltration: ['exfiltration'],
  code: ['code_pattern'],
} as const;

export type ScanType = keyof typeof SCAN_TYPES;

export interface ScanOptions {
  /** Limit to these scan types; default: all analyzers. */
  types?: ScanType[];
  /** Rules to apply; default: Mund's built-in rules. */
  rules?: DetectionRule[];
}

export interface ScanResult {
  issues: SecurityIssue[];
  risk: RiskScore;
}

export async function scan(content: string, options: ScanOptions = {}): Promise<ScanResult> {
  let analyzers = getAnalyzers();
  if (options.types?.length) {
    const wanted = new Set<string>(options.types.flatMap((t) => SCAN_TYPES[t] ?? []));
    analyzers = analyzers.filter((a) => wanted.has(a.type));
  }
  const issues = await new AnalyzerEngine(analyzers).analyzeAll(content, options.rules ?? DEFAULT_RULES);
  return { issues, risk: computeRiskScore(issues) };
}
