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
} from "./enforcer/index.js";
export type { Decision, CheckResult, RuntimeState } from "./enforcer/index.js";
