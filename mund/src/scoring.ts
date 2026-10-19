/**
 * Mund - The Guardian Protocol
 * Risk Scoring - collapse a set of findings into a 0-100 score + label
 *
 * Each finding independently "consumes" a fraction of the remaining
 * headroom, so the score rises quickly with severe findings, has
 * diminishing returns for many minor ones, and never exceeds 100:
 *
 *   score = 100 * (1 - Π (1 - weight_i))
 *
 * One critical finding alone lands in the critical band; one high in the
 * high band; it takes many low findings to escalate past "low".
 */

import type { SecurityIssue, Severity } from './types.js';

export type RiskLabel = 'none' | 'low' | 'medium' | 'high' | 'critical';

export interface RiskScore {
  score: number;
  label: RiskLabel;
  counts: Record<Severity, number>;
}

export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 0.8,
  high: 0.4,
  medium: 0.15,
  low: 0.05,
  info: 0,
};

/** Lower bound (inclusive) of each label band. */
export const RISK_BANDS: Array<[RiskLabel, number]> = [
  ['critical', 80],
  ['high', 40],
  ['medium', 15],
  ['low', 1],
];

export function labelForScore(score: number): RiskLabel {
  for (const [label, min] of RISK_BANDS) {
    if (score >= min) return label;
  }
  return 'none';
}

export function computeRiskScore(issues: Array<Pick<SecurityIssue, 'severity'>>): RiskScore {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let headroom = 1;

  for (const issue of issues) {
    const severity = issue.severity in SEVERITY_WEIGHTS ? issue.severity : 'info';
    counts[severity]++;
    headroom *= 1 - SEVERITY_WEIGHTS[severity];
  }

  // Any non-info finding scores at least 1 so it never reads as "none".
  const raw = Math.round(100 * (1 - headroom));
  const hasFinding = counts.critical + counts.high + counts.medium + counts.low > 0;
  const score = hasFinding ? Math.max(1, raw) : 0;

  return { score, label: labelForScore(score), counts };
}
