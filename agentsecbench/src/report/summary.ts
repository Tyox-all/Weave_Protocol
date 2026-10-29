/**
 * Public-safe report summaries for the results page.
 *
 * A full Report embeds the Adversary scorecard, including what the target
 * said or did for every attack (evidence, tool-call arguments, attempt
 * payloads). None of that belongs on a public page. A summary keeps the
 * headline numbers, category gaps and trophy results only.
 */

import type { CategoryGap, Report, TrophyResult } from '../types.js';

export interface ReportSummary {
  summaryVersion: '1';
  schemaVersion: Report['schemaVersion'];
  suite: Report['suite'];
  target: { name: string; vendor?: string; type: string; model?: string; anonymized: boolean };
  run: {
    date: string;
    adversaryVersion: string;
    agentsecbenchVersion: string;
    attacksRun: number;
    dynamic?: Report['run']['dynamic'];
  };
  result: Report['result'];
  categoryGaps: CategoryGap[];
  trophyPerformance: TrophyResult[];
  wardDelta?: Report['wardDelta'];
  interpretation?: string;
}

export function summarizeReport(report: Report): ReportSummary {
  const anonymized = report.target.anonymized;
  return {
    summaryVersion: '1',
    schemaVersion: report.schemaVersion,
    suite: { ...report.suite },
    target: {
      name: report.target.name,
      // An anonymized report never carries the vendor into public output.
      ...(!anonymized && report.target.vendor ? { vendor: report.target.vendor } : {}),
      type: report.target.type,
      ...(report.target.model ? { model: report.target.model } : {}),
      anonymized,
    },
    run: {
      date: report.run.date,
      adversaryVersion: report.run.adversaryVersion,
      agentsecbenchVersion: report.run.agentsecbenchVersion,
      attacksRun: report.run.attacksRun,
      ...(report.run.dynamic ? { dynamic: report.run.dynamic } : {}),
    },
    result: { ...report.result },
    categoryGaps: report.categoryGaps.map((g) => ({ ...g })),
    trophyPerformance: report.trophyPerformance.map((t) => ({ ...t })),
    ...(report.wardDelta ? { wardDelta: { ...report.wardDelta } } : {}),
    ...(report.interpretation ? { interpretation: report.interpretation } : {}),
  };
}
