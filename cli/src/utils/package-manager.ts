/**
 * Detect which package manager the user is using.
 *
 * Priority: explicit lockfile > npm_config_user_agent > default to npm.
 */

import { existsSync } from "node:fs";
import { join } from "node:path";

export type PackageManager = "npm" | "pnpm" | "yarn" | "bun";

export function detectPackageManager(cwd: string = process.cwd()): PackageManager {
  // Lockfile-based detection (most reliable)
  if (existsSync(join(cwd, "bun.lockb")) || existsSync(join(cwd, "bun.lock"))) return "bun";
  if (existsSync(join(cwd, "pnpm-lock.yaml"))) return "pnpm";
  if (existsSync(join(cwd, "yarn.lock"))) return "yarn";
  if (existsSync(join(cwd, "package-lock.json"))) return "npm";

  // Fall back to user agent (when running through corepack)
  const ua = process.env.npm_config_user_agent || "";
  if (ua.startsWith("bun")) return "bun";
  if (ua.startsWith("pnpm")) return "pnpm";
  if (ua.startsWith("yarn")) return "yarn";

  return "npm";
}

export function installCommand(packages: string[], pm: PackageManager): string {
  const list = packages.join(" ");
  switch (pm) {
    case "npm":
      return `npm install ${list}`;
    case "pnpm":
      return `pnpm add ${list}`;
    case "yarn":
      return `yarn add ${list}`;
    case "bun":
      return `bun add ${list}`;
  }
}

export function devInstallCommand(packages: string[], pm: PackageManager): string {
  const list = packages.join(" ");
  switch (pm) {
    case "npm":
      return `npm install --save-dev ${list}`;
    case "pnpm":
      return `pnpm add -D ${list}`;
    case "yarn":
      return `yarn add --dev ${list}`;
    case "bun":
      return `bun add -d ${list}`;
  }
}

export function runCommand(script: string, pm: PackageManager): string {
  switch (pm) {
    case "npm":
      return `npm run ${script}`;
    case "pnpm":
      return `pnpm ${script}`;
    case "yarn":
      return `yarn ${script}`;
    case "bun":
      return `bun run ${script}`;
  }
}
