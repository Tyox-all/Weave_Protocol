/**
 * @weave_protocol/tollere
 * Supply chain security for AI-generated code
 *
 * Catches typosquats, compromised maintainers, CVEs, and suspicious version
 * diffs BEFORE `npm install` completes. Built for the era of AI coding agents
 * that install dependencies at machine speed with zero human review.
 */

export * from "./types.js";
export {
  detectTyposquat,
  getPopularPackages,
} from "./typosquat.js";
export {
  fetchPackageMetadata,
  computeReputationScore,
  getMaintainerReputation,
} from "./reputation.js";
export { queryCVEs, queryCVEsBatch } from "./cve.js";
export { diffVersions } from "./diff.js";
export { scanPackage, scanPackageJson } from "./scanner.js";
