/**
 * @weave_protocol/ward - Public API
 *
 * WARD.md is an infrastructure-as-code standard for declaring AI agent
 * security policies. It pairs with AGENTS.md (Google's agent definition
 * format) and SKILL.md (Anthropic's skill format) to give every agent in
 * a repo a version-controlled, machine-readable set of guardrails.
 *
 * @example
 * ```ts
 * import { parseWard, checkFilesystem } from '@weave_protocol/ward';
 * import { readFileSync } from 'node:fs';
 *
 * const policy = parseWard(readFileSync('./WARD.md', 'utf8'));
 * const result = checkFilesystem(policy, 'read', '/workspace/secrets/keys.txt');
 * if (result.decision === 'deny') {
 *   throw new Error(result.reason);
 * }
 * ```
 */

// Types
export type * from "./types.js";

// Parser
export { parseWard, parseAndValidate } from "./parser/index.js";
export { splitFrontmatter, parseYAML } from "./parser/yaml.js";
export { splitSections, normalizeKey } from "./parser/markdown.js";

// Enforcer
export {
  checkFilesystem,
  checkNetwork,
  checkCapability,
  checkDataEgress,
  checkBehavioral,
  matchGlob,
  normalizePath,
  canonicalUrl,
} from "./enforcer/index.js";
export type { Decision, CheckResult, RuntimeState } from "./enforcer/index.js";
export { evaluateToolCall, protectedConfig } from "./enforcer/toolcall.js";
export { checkOutboundData, classifyData, classifyCommandReferences, isModelEndpoint, destinationsOf } from "./enforcer/egress.js";
export { detectPayment, explicitlyAllowed, checkSessionLimits, needsLedger } from "./enforcer/limits.js";
export type { PaymentCall, LedgerEvent, LedgerSnapshot, PendingCall, LimitCheck } from "./enforcer/limits.js";
export { parseSpendingLimits } from "./parser/spending.js";
export type { DataFinding, DataClassifier, OutboundCheck, OutboundOptions } from "./enforcer/egress.js";
export { reportEvent, dashboardUrl, reportTimeoutMs } from "./report.js";
export type { EnforcementEvent, ReportOptions, ReportSurface, ReportDecision } from "./report.js";
export type { ToolMapping, ToolCallCheck, ToolCallEvaluation, EvaluateOptions } from "./enforcer/toolcall.js";
