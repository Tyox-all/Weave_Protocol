/**
 * @weave_protocol/tollere
 * Supply chain security for AI-generated code
 *
 * v0.2: Now covers npm/PyPI/Cargo/Go/Maven packages, Docker images,
 * and IDE extensions (VS Code, Cursor, Windsurf, Open VSX, JetBrains).
 *
 * Catches typosquats, compromised maintainers, CVEs, suspicious version
 * diffs, sandwich-pattern compromises, and Docker tag overwriting BEFORE
 * the install completes.
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

// v0.2 additions
export { detectSandwichPattern } from "./sandwich.js";
export { scanDockerImage, parseImageRef, fetchDockerHubTags } from "./docker.js";
export {
  scanExtension,
  scanVSCodeExtension,
  scanOpenVSXExtension,
  scanJetBrainsExtension,
  type IDEEcosystem,
} from "./extensions/index.js";
