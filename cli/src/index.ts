/**
 * @weave_protocol/cli — programmatic API
 *
 * The primary use of this package is as a CLI (`npx @weave_protocol/cli`),
 * but the same routines are exported here for users who want to build
 * tooling on top of them.
 */

export { detectFramework, frameworkLabel } from "./detect/framework.js";
export type { Framework, FrameworkDetection } from "./detect/framework.js";

export { detectPackageManager, installCommand, devInstallCommand, runCommand } from "./utils/package-manager.js";
export type { PackageManager } from "./utils/package-manager.js";

export { getScaffold } from "./scaffolds/index.js";
export type { ScaffoldOutput, ScaffoldOptions, ScaffoldFile, WeavePackage } from "./scaffolds/types.js";

export { runInit } from "./commands/init.js";
export { runAudit, runDashboard, runDoctor, runVersion } from "./commands/index.js";
