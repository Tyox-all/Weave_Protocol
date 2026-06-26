import type { Scorecard } from '../types.js';

/**
 * Render the scorecard as machine-readable JSON.
 *
 * Pretty-printed for diffability in CI. Schema is locked at v1.0 —
 * AgentSecBench depends on this exact shape.
 */
export function renderJsonScorecard(scorecard: Scorecard): string {
  return JSON.stringify(scorecard, null, 2);
}
