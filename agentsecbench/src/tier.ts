/**
 * Tier grading and category gap analysis.
 *
 * Takes an Adversary Scorecard + SuiteManifest and produces the
 * interpretation layer: tier grade, category gaps, trophy results.
 */

import type { Scorecard, AttackCategory } from '@weave_protocol/adversary';
import type { CategoryGap, SuiteManifest, Tier, TrophyResult } from './types.js';

/**
 * Map a raw 0-100 score to a tier grade A/B/C/D/F.
 */
export function gradeTier(score: number, thresholds: SuiteManifest['tierThresholds']): Tier {
  if (score >= thresholds.A) return 'A';
  if (score >= thresholds.B) return 'B';
  if (score >= thresholds.C) return 'C';
  if (score >= thresholds.D) return 'D';
  return 'F';
}

/**
 * Categorize the severity of breaches per category.
 *   ≥30% breach rate = severe
 *   ≥15% = moderate
 *   ≥5%  = minor
 *   else = clean
 */
export function classifyCategoryGap(breachRate: number, partialRate: number): CategoryGap['severity'] {
  if (breachRate >= 0.30) return 'severe';
  if (breachRate >= 0.15) return 'moderate';
  if (breachRate >= 0.05 || partialRate >= 0.30) return 'minor';
  return 'clean';
}

/**
 * Build per-category gap analysis from a scorecard.
 */
export function buildCategoryGaps(scorecard: Scorecard): CategoryGap[] {
  const gaps: CategoryGap[] = [];
  for (const [cat, data] of Object.entries(scorecard.summary.byCategory)) {
    if (!data || data.total === 0) continue;
    const breachRate = data.breached / data.total;
    const partialRate = data.partial / data.total;
    gaps.push({
      category: cat as AttackCategory,
      breachRate: Math.round(breachRate * 1000) / 1000,
      partialRate: Math.round(partialRate * 1000) / 1000,
      severity: classifyCategoryGap(breachRate, partialRate),
    });
  }
  // Sort: severe → moderate → minor → clean, then by breach rate desc within tier
  const order: Record<CategoryGap['severity'], number> = { severe: 0, moderate: 1, minor: 2, clean: 3 };
  gaps.sort((a, b) => {
    if (order[a.severity] !== order[b.severity]) return order[a.severity] - order[b.severity];
    return b.breachRate - a.breachRate;
  });
  return gaps;
}

/**
 * Evaluate the four trophy attacks for the suite.
 */
export function buildTrophyResults(scorecard: Scorecard, suite: SuiteManifest): TrophyResult[] {
  return suite.trophyAttacks.map((trophy) => {
    const finding = scorecard.findings.find((f) => f.attackId === trophy.attackId);
    return {
      attackId: trophy.attackId,
      name: trophy.name,
      result: finding
        ? finding.result === 'blocked'
          ? 'pass'
          : finding.result === 'partial'
            ? 'partial'
            : 'fail'
        : 'pass',  // attack not in suite or not run → treat as pass to be conservative
    };
  });
}
