/**
 * Compare two reports.
 *
 * Use cases:
 *   - Before / after a code change
 *   - Vendor A vs Vendor B
 *   - Last week vs this week (regression detection)
 *   - WARD policy A vs WARD policy B
 *
 * Both reports must be from the same suite — otherwise scores aren't
 * comparable.
 */

import type { AttackCategory } from '@weave_protocol/adversary';
import type { ComparisonReport, Report } from '../types.js';
import { gradeTier } from '../tier.js';
import { getSuite } from '../suites/index.js';

export function compareReports(a: Report, b: Report): ComparisonReport {
  if (a.suite.id !== b.suite.id || a.suite.version !== b.suite.version) {
    throw new Error(
      `Cannot compare reports from different suites: ${a.suite.id}/${a.suite.version} vs ` +
        `${b.suite.id}/${b.suite.version}. Both reports must use the same locked suite.`,
    );
  }

  const suite = getSuite(a.suite.id);
  if (!suite) {
    throw new Error(`Unknown suite: ${a.suite.id}`);
  }

  // Per-category deltas
  const allCategories = new Set<AttackCategory>([
    ...a.categoryGaps.map((g) => g.category),
    ...b.categoryGaps.map((g) => g.category),
  ]);
  const categoryDeltas = Array.from(allCategories)
    .map((cat) => {
      const aGap = a.categoryGaps.find((g) => g.category === cat);
      const bGap = b.categoryGaps.find((g) => g.category === cat);
      const aRate = aGap?.breachRate ?? 0;
      const bRate = bGap?.breachRate ?? 0;
      return {
        category: cat,
        aBreachRate: aRate,
        bBreachRate: bRate,
        delta: Math.round((aRate - bRate) * 1000) / 1000,
      };
    })
    .sort((x, y) => Math.abs(y.delta) - Math.abs(x.delta));

  // Trophy deltas
  const trophyDeltas = a.trophyPerformance.map((aTrophy) => {
    const bTrophy = b.trophyPerformance.find((t) => t.attackId === aTrophy.attackId);
    const order: Record<string, number> = { fail: 0, partial: 1, pass: 2 };
    const aScore = order[aTrophy.result] ?? 0;
    const bScore = bTrophy ? order[bTrophy.result] ?? 0 : 0;
    const direction: 'improved' | 'regressed' | 'unchanged' =
      bScore > aScore ? 'improved' : bScore < aScore ? 'regressed' : 'unchanged';
    return {
      attackId: aTrophy.attackId,
      name: aTrophy.name,
      aResult: aTrophy.result,
      bResult: bTrophy?.result ?? aTrophy.result,
      direction,
    };
  });

  // Per-attack regressions and improvements
  const regressions: ComparisonReport['regressions'] = [];
  const improvements: ComparisonReport['improvements'] = [];
  const order: Record<string, number> = { breached: 0, partial: 1, blocked: 2 };
  for (const aFinding of a.scorecard.findings) {
    const bFinding = b.scorecard.findings.find((f) => f.attackId === aFinding.attackId);
    if (!bFinding) continue;
    const aScore = order[aFinding.result] ?? 0;
    const bScore = order[bFinding.result] ?? 0;
    if (bScore < aScore) {
      regressions.push({
        attackId: aFinding.attackId,
        severity: aFinding.severity,
        aResult: aFinding.result,
        bResult: bFinding.result,
      });
    } else if (bScore > aScore) {
      improvements.push({
        attackId: aFinding.attackId,
        severity: aFinding.severity,
        aResult: aFinding.result,
        bResult: bFinding.result,
      });
    }
  }

  return {
    schemaVersion: '1.0',
    date: new Date().toISOString(),
    suite: { id: a.suite.id, version: a.suite.version },
    a: {
      name: a.target.name,
      score: a.result.score,
      tier: a.result.tier,
      breached: a.result.breached,
    },
    b: {
      name: b.target.name,
      score: b.result.score,
      tier: b.result.tier,
      breached: b.result.breached,
    },
    scoreDelta: Math.round((b.result.score - a.result.score) * 10) / 10,
    categoryDeltas,
    trophyDeltas,
    regressions,
    improvements,
  };
}

const TIER_BANNER: Record<string, string> = {
  A: '🟢 A', B: '🟡 B', C: '🟠 C', D: '🔴 D', F: '⚫ F',
};

export function renderMarkdownComparison(cmp: ComparisonReport): string {
  const lines: string[] = [];
  const sign = (n: number) => (n >= 0 ? `+${n}` : `${n}`);
  const pctSign = (n: number) => sign(Math.round(n * 1000) / 10);
  const directionIcon: Record<string, string> = {
    improved: '⬆️ improved',
    regressed: '⬇️ regressed',
    unchanged: '→ unchanged',
  };

  lines.push(`# 🔀 AgentSecBench Comparison`);
  lines.push('');
  lines.push(`**Suite:** \`${cmp.suite.id}\` v${cmp.suite.version}`);
  lines.push(`**Date:** ${cmp.date}`);
  lines.push('');

  // ─── Headline ───────────────────────────────────────────
  const trend = cmp.scoreDelta > 0 ? '⬆️ improved' : cmp.scoreDelta < 0 ? '⬇️ regressed' : '→ unchanged';
  lines.push(`## ${trend} by ${Math.abs(cmp.scoreDelta).toFixed(1)} points`);
  lines.push('');
  lines.push(`| | ${cmp.a.name} (A) | ${cmp.b.name} (B) | Δ |`);
  lines.push(`|---|---|---|---|`);
  lines.push(`| **Score** | ${cmp.a.score} | ${cmp.b.score} | **${sign(cmp.scoreDelta)}** |`);
  lines.push(`| **Tier**  | ${TIER_BANNER[cmp.a.tier]} | ${TIER_BANNER[cmp.b.tier]} | ${cmp.a.tier === cmp.b.tier ? '—' : `${cmp.a.tier} → ${cmp.b.tier}`} |`);
  lines.push(`| **Breaches** | ${cmp.a.breached} | ${cmp.b.breached} | ${sign(cmp.b.breached - cmp.a.breached)} |`);
  lines.push('');

  // ─── Category deltas ────────────────────────────────────
  lines.push(`## Category-level deltas`);
  lines.push('');
  lines.push(`| Category | A breach rate | B breach rate | Δ |`);
  lines.push(`|---|--:|--:|--:|`);
  for (const cd of cmp.categoryDeltas) {
    const dir = cd.delta > 0 ? '⬆️' : cd.delta < 0 ? '⬇️' : '→';
    lines.push(
      `| \`${cd.category}\` | ${(cd.aBreachRate * 100).toFixed(1)}% | ${(cd.bBreachRate * 100).toFixed(1)}% | ${dir} ${pctSign(cd.delta)}% |`,
    );
  }
  lines.push('');

  // ─── Trophy deltas ─────────────────────────────────────
  lines.push(`## Trophy attack performance`);
  lines.push('');
  lines.push(`| Attack | A | B | |`);
  lines.push(`|---|---|---|---|`);
  for (const td of cmp.trophyDeltas) {
    lines.push(`| **${td.name}** | ${td.aResult} | ${td.bResult} | ${directionIcon[td.direction]} |`);
  }
  lines.push('');

  // ─── Regressions ────────────────────────────────────────
  if (cmp.regressions.length > 0) {
    lines.push(`## ⬇️ Regressions (${cmp.regressions.length})`);
    lines.push('');
    lines.push(`Attacks that A handled but B did not. Top priority for triage.`);
    lines.push('');
    lines.push('| Attack | Severity | A | B |');
    lines.push('|---|---|---|---|');
    for (const r of cmp.regressions.slice(0, 15)) {
      lines.push(`| \`${r.attackId}\` | ${r.severity} | ${r.aResult} | ${r.bResult} |`);
    }
    if (cmp.regressions.length > 15) {
      lines.push(`| _...and ${cmp.regressions.length - 15} more_ | | | |`);
    }
    lines.push('');
  }

  // ─── Improvements ──────────────────────────────────────
  if (cmp.improvements.length > 0) {
    lines.push(`## ⬆️ Improvements (${cmp.improvements.length})`);
    lines.push('');
    lines.push('| Attack | Severity | A | B |');
    lines.push('|---|---|---|---|');
    for (const i of cmp.improvements.slice(0, 15)) {
      lines.push(`| \`${i.attackId}\` | ${i.severity} | ${i.aResult} | ${i.bResult} |`);
    }
    if (cmp.improvements.length > 15) {
      lines.push(`| _...and ${cmp.improvements.length - 15} more_ | | | |`);
    }
    lines.push('');
  }

  lines.push('---');
  lines.push(`*Generated by [\`@weave_protocol/agentsecbench\`](https://www.npmjs.com/package/@weave_protocol/agentsecbench)*`);

  return lines.join('\n');
}

export function renderJsonComparison(cmp: ComparisonReport): string {
  return JSON.stringify(cmp, null, 2);
}
