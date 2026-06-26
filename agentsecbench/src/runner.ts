/**
 * AgentSecBench Runner.
 *
 * Thin wrapper around AdversarialAgent that constrains the attack set to
 * a suite manifest's locked attack IDs. The point: a suite run is
 * comparable across targets and across time because the inputs are
 * locked.
 */

import {
  AdversarialAgent,
  loadWardPolicy,
  type Scorecard,
  type Target,
  type WardPolicy,
} from '@weave_protocol/adversary';
import type { Report, SuiteManifest } from './types.js';
import { buildCategoryGaps, buildTrophyResults, gradeTier } from './tier.js';
import { generateInterpretation } from './report/interpret.js';

const AGENTSECBENCH_VERSION = '0.1.0';

export interface RunSuiteOptions {
  /** Target to attack */
  target: Target;
  /** Suite manifest (locked attack set) */
  suite: SuiteManifest;
  /** Target metadata for the report */
  targetMeta: {
    name: string;
    vendor?: string;
    type: string;
    configuration?: Record<string, string>;
    anonymized?: boolean;
  };
  /** Optional WARD policy (loaded automatically from cwd if omitted) */
  ward?: WardPolicy;
  /** If provided, also runs the suite without WARD for delta analysis */
  measureWardDelta?: boolean;
}

/**
 * Run an entire suite against a target and produce a Report.
 */
export async function runSuite(opts: RunSuiteOptions): Promise<Report> {
  const ward = opts.ward ?? loadWardPolicy();
  const agent = new AdversarialAgent(opts.target, { ward });

  // Run the locked attack set
  const scorecard = await agent.run({
    attackIds: opts.suite.attackIds,
  });

  // Validate: did all suite attacks actually run?
  if (scorecard.findings.length !== opts.suite.attackIds.length) {
    console.warn(
      `[agentsecbench] Suite ${opts.suite.id} expects ${opts.suite.attackIds.length} attacks; ` +
        `${scorecard.findings.length} ran. This usually means the Adversary corpus changed; ` +
        `pin @weave_protocol/adversary@${opts.suite.adversaryCompatVersion} to ensure suite ` +
        `reproducibility.`,
    );
  }

  // Optional: measure WARD delta by re-running without WARD
  let wardDelta: Report['wardDelta'] | undefined;
  if (opts.measureWardDelta && ward.loaded) {
    const noWardAgent = new AdversarialAgent(opts.target, {
      ward: { ...ward, loaded: false },
    });
    const noWardScorecard = await noWardAgent.run({
      attackIds: opts.suite.attackIds,
    });
    wardDelta = {
      withWard: scorecard.summary.score,
      withoutWard: noWardScorecard.summary.score,
      delta: Math.round((scorecard.summary.score - noWardScorecard.summary.score) * 10) / 10,
    };
  }

  return buildReport(scorecard, opts.suite, opts.targetMeta, wardDelta);
}

/**
 * Build a Report from an existing Adversary Scorecard.
 * Useful when the run is driven externally and we want to interpret
 * the result through the ASB lens.
 */
export function buildReport(
  scorecard: Scorecard,
  suite: SuiteManifest,
  targetMeta: RunSuiteOptions['targetMeta'],
  wardDelta?: Report['wardDelta'],
): Report {
  const categoryGaps = buildCategoryGaps(scorecard);
  const trophyPerformance = buildTrophyResults(scorecard, suite);
  const tier = gradeTier(scorecard.summary.score, suite.tierThresholds);

  const report: Report = {
    schemaVersion: '1.0',
    suite: { id: suite.id, version: suite.version, name: suite.name },
    target: {
      name: targetMeta.name,
      vendor: targetMeta.vendor,
      type: targetMeta.type,
      configuration: targetMeta.configuration,
      anonymized: targetMeta.anonymized ?? false,
    },
    run: {
      date: new Date(scorecard.startedAt).toISOString(),
      durationMs: scorecard.durationMs,
      adversaryVersion: scorecard.adversaryVersion,
      agentsecbenchVersion: AGENTSECBENCH_VERSION,
      attacksRun: scorecard.findings.length,
    },
    result: {
      score: scorecard.summary.score,
      tier,
      blocked: scorecard.summary.blocked,
      partial: scorecard.summary.partial,
      breached: scorecard.summary.breached,
    },
    categoryGaps,
    trophyPerformance,
    wardDelta,
    scorecard,
  };

  report.interpretation = generateInterpretation(report);
  return report;
}
