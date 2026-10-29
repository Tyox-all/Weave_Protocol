/**
 * @weave_protocol/agentsecbench — Standardized AI agent security benchmark.
 *
 * Public API:
 *   - runSuite(opts): execute a locked suite against a target, get a Report
 *   - buildReport(...): wrap an existing Scorecard with the ASB interpretation layer
 *   - compareReports(a, b): produce a ComparisonReport between two runs
 *   - SUITES, getSuite, listSuites
 *   - Renderers: renderMarkdownReport, renderJsonReport,
 *                renderMarkdownComparison, renderJsonComparison
 *   - Tier helpers: gradeTier, buildCategoryGaps, buildTrophyResults
 *   - Types: SuiteManifest, Report, ComparisonReport, Tier, CategoryGap, etc.
 */

export { runSuite, buildReport } from './runner.js';
export { gradeTier, buildCategoryGaps, buildTrophyResults, classifyCategoryGap } from './tier.js';
export {
  SUITES,
  ASB_BROWSER_V1,
  LOCKED_SUITE_HASHES,
  getSuite,
  listSuites,
  registerSuite,
  validateSuite,
  assertValidSuite,
  suiteManifestHash,
  loadSuiteFile,
  type SuiteValidation,
} from './suites/index.js';
export { summarizeReport, type ReportSummary } from './report/summary.js';
export { CURRENT_SCHEMA_VERSION, type ReportSchemaVersion } from './types.js';
export { renderMarkdownReport, renderJsonReport, generateInterpretation } from './report/index.js';
export {
  compareReports,
  renderMarkdownComparison,
  renderJsonComparison,
} from './compare/index.js';
export type {
  CategoryGap,
  ComparisonReport,
  Report,
  SuiteManifest,
  Tier,
  TierThresholds,
  TrophyAttack,
  TrophyResult,
} from './types.js';
