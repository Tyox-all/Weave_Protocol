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
import { CURRENT_SCHEMA_VERSION, type Report, type SuiteManifest } from './types.js';
import { assertValidSuite, suiteManifestHash } from './suites/validate.js';
import { buildCategoryGaps, buildTrophyResults, gradeTier } from './tier.js';
import { generateInterpretation } from './report/interpret.js';

const AGENTSECBENCH_VERSION = '0.3.0';

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
    /** Model under test, for LLM-backed targets */
    model?: string;
    /** Provider serving the model */
    provider?: string;
  };
  /** Optional WARD policy (loaded automatically from cwd if omitted) */
  ward?: WardPolicy;
  /** If provided, also runs the suite without WARD for delta analysis */
  measureWardDelta?: boolean;
}

/**
 * The run did not cover the whole suite (for example, a free tier's
 * daily quota ran out). A tier grade for it would not be comparable, so
 * no report is produced.
 */
export class IncompleteRunError extends Error {
  constructor(
    message: string,
    readonly completed: number,
    readonly planned: number,
  ) {
    super(message);
    this.name = 'IncompleteRunError';
  }
}

function assertComplete(scorecard: Scorecard, suite: SuiteManifest): void {
  const stopped = scorecard.stoppedEarly;
  if (stopped) {
    throw new IncompleteRunError(
      `Suite ${suite.id} stopped after ${stopped.completed} of ${stopped.planned} attacks: ${stopped.reason.slice(0, 200)}. ` +
        'AgentSecBench grades complete runs only. Re-run when the provider quota resets, or use a key with a higher quota.',
      stopped.completed,
      stopped.planned,
    );
  }
}

/**
 * Run an entire suite against a target and produce a Report.
 * Throws IncompleteRunError if the target stopped the run early.
 */
export async function runSuite(opts: RunSuiteOptions): Promise<Report> {
  // Refuse to run a suite whose attacks aren't all in the installed corpus:
  // a partial run would produce a score that isn't comparable.
  assertValidSuite(opts.suite);

  const ward = opts.ward ?? loadWardPolicy();
  const agent = new AdversarialAgent(opts.target, { ward });

  // Run the locked attack set
  const scorecard = await agent.run({
    attackIds: opts.suite.attackIds,
  });
  assertComplete(scorecard, opts.suite);

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
    assertComplete(noWardScorecard, opts.suite);
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
  assertComplete(scorecard, suite);
  const categoryGaps = buildCategoryGaps(scorecard);
  const trophyPerformance = buildTrophyResults(scorecard, suite);
  const tier = gradeTier(scorecard.summary.score, suite.tierThresholds);

  const variantOnly = scorecard.dynamic
    ? scorecard.findings.filter(
        (f) => f.result !== 'blocked' && f.attempts && f.attempts.length > 1 && f.attempts[0].result !== f.result,
      ).length
    : undefined;

  const report: Report = {
    schemaVersion: CURRENT_SCHEMA_VERSION,
    suite: { id: suite.id, version: suite.version, name: suite.name, manifestHash: suiteManifestHash(suite) },
    target: {
      name: targetMeta.name,
      vendor: targetMeta.vendor,
      type: targetMeta.type,
      configuration: targetMeta.configuration,
      anonymized: targetMeta.anonymized ?? false,
      ...(targetMeta.model ? { model: targetMeta.model } : {}),
      ...(targetMeta.provider ? { provider: targetMeta.provider } : {}),
    },
    run: {
      date: new Date(scorecard.startedAt).toISOString(),
      durationMs: scorecard.durationMs,
      adversaryVersion: scorecard.adversaryVersion,
      agentsecbenchVersion: AGENTSECBENCH_VERSION,
      attacksRun: scorecard.findings.length,
      ...(scorecard.dynamic
        ? {
            dynamic: {
              ...(scorecard.dynamic.provider ? { provider: scorecard.dynamic.provider } : {}),
              model: scorecard.dynamic.model,
              maxRetries: scorecard.dynamic.maxRetries,
              variantsGenerated: scorecard.dynamic.variantsGenerated,
              mutationCostUSD: scorecard.dynamic.mutationCostUSD,
            },
          }
        : {}),
    },
    result: {
      score: scorecard.summary.score,
      tier,
      blocked: scorecard.summary.blocked,
      partial: scorecard.summary.partial,
      breached: scorecard.summary.breached,
      ...(variantOnly !== undefined ? { variantOnly } : {}),
    },
    categoryGaps,
    trophyPerformance,
    wardDelta,
    scorecard,
  };

  report.interpretation = generateInterpretation(report);
  return report;
}
