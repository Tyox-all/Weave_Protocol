/**
 * Public attack corpus for @weave_protocol/adversary.
 *
 * 68 probes across 5 categories:
 *   - 33 IPI (indirect prompt injection)
 *   - 15 Tool-use coercion
 *   - 10 Jailbreak templates
 *   -  5 Prompt/policy extraction
 *   -  5 Goal corruption
 */

import type { Attack, AttackCategory } from '../types.js';
import { IPI_ATTACKS } from './ipi/index.js';
import { TOOL_COERCION_ATTACKS } from './tool_coercion/index.js';
import { JAILBREAK_ATTACKS } from './jailbreak/index.js';
import { EXTRACTION_ATTACKS } from './extraction/index.js';
import { GOAL_CORRUPTION_ATTACKS } from './goal_corruption/index.js';

export const ALL_ATTACKS: Attack[] = [
  ...IPI_ATTACKS,
  ...TOOL_COERCION_ATTACKS,
  ...JAILBREAK_ATTACKS,
  ...EXTRACTION_ATTACKS,
  ...GOAL_CORRUPTION_ATTACKS,
];

export const ATTACKS_BY_CATEGORY: Record<AttackCategory, Attack[]> = {
  ipi: IPI_ATTACKS,
  tool_coercion: TOOL_COERCION_ATTACKS,
  jailbreak: JAILBREAK_ATTACKS,
  extraction: EXTRACTION_ATTACKS,
  goal_corruption: GOAL_CORRUPTION_ATTACKS,
};

export {
  IPI_ATTACKS,
  TOOL_COERCION_ATTACKS,
  JAILBREAK_ATTACKS,
  EXTRACTION_ATTACKS,
  GOAL_CORRUPTION_ATTACKS,
};

/**
 * Look up an attack by ID. Returns undefined if not found.
 */
export function getAttackById(id: string): Attack | undefined {
  return ALL_ATTACKS.find((a) => a.id === id);
}

/**
 * Aggregate count of attacks in the corpus.
 * Trips loudly if the corpus drifts from the v0.1.0 contract.
 */
export const CORPUS_STATS = {
  total: ALL_ATTACKS.length,
  byCategory: {
    ipi: IPI_ATTACKS.length,
    tool_coercion: TOOL_COERCION_ATTACKS.length,
    jailbreak: JAILBREAK_ATTACKS.length,
    extraction: EXTRACTION_ATTACKS.length,
    goal_corruption: GOAL_CORRUPTION_ATTACKS.length,
  },
} as const;

if (CORPUS_STATS.total !== 68) {
  throw new Error(`v0.1.0 corpus must have exactly 68 attacks; has ${CORPUS_STATS.total}`);
}
