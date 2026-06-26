/**
 * @weave_protocol/adversary — Offensive engine for AI agent security testing.
 *
 * Public API:
 *   - AdversarialAgent: the orchestrator
 *   - Targets: DemoTarget, BrowserTarget
 *   - Attack corpus: ALL_ATTACKS, ATTACKS_BY_CATEGORY
 *   - Scorecard renderers: renderMarkdownScorecard, renderJsonScorecard
 *   - WARD: loadWardPolicy, parseWardPolicy
 *   - Types: Attack, Target, Scorecard, Finding, WardPolicy, RunOptions, etc.
 */

export { AdversarialAgent } from './agent.js';
export {
  ALL_ATTACKS,
  ATTACKS_BY_CATEGORY,
  CORPUS_STATS,
  getAttackById,
  IPI_ATTACKS,
  TOOL_COERCION_ATTACKS,
  JAILBREAK_ATTACKS,
  EXTRACTION_ATTACKS,
  GOAL_CORRUPTION_ATTACKS,
} from './attacks/index.js';
export { DemoTarget, BrowserTarget, type BrowserTargetOptions } from './targets/index.js';
export {
  buildScorecard,
  computeSummary,
  classifyResult,
  renderMarkdownScorecard,
  renderJsonScorecard,
} from './scorecard/index.js';
export { loadWardPolicy, parseWardPolicy, scoreAttackForPolicy, wardAwareSort } from './ward.js';
export type {
  Attack,
  AttackCategory,
  AttackDelivery,
  AttackResult,
  AttackSeverity,
  Finding,
  RunOptions,
  Scorecard,
  ScorecardSummary,
  Target,
  TargetKind,
  TargetResponse,
  WardPolicy,
} from './types.js';
