#!/usr/bin/env node
/**
 * @weave_protocol/tollere - CLI
 *
 * Usage:
 *   weave-tollere scan                       # Scan current package.json
 *   weave-tollere scan ./path/to/pkg.json    # Scan specific package.json
 *   weave-tollere check <package>            # Check single package
 *   weave-tollere diff <package> <v1> <v2>   # Diff two versions
 *   weave-tollere typosquat <name>           # Check for typosquat
 *
 * Exit codes:
 *   0 = no issues
 *   1 = warnings found
 *   2 = critical issues / blocked
 */

import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

import { scanPackage, scanPackageJson } from "./scanner.js";
import { detectTyposquat } from "./typosquat.js";
import { diffVersions } from "./diff.js";
import { DEFAULT_CONFIG } from "./types.js";
import type { ScanReport, PackageRisk, Severity } from "./types.js";

const COLORS = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  green: "\x1b[32m",
  blue: "\x1b[34m",
  gray: "\x1b[90m",
  cyan: "\x1b[36m",
};

function severityColor(sev: Severity): string {
  if (sev === "critical") return COLORS.red;
  if (sev === "high") return COLORS.red;
  if (sev === "medium") return COLORS.yellow;
  return COLORS.gray;
}

function severityIcon(sev: Severity): string {
  if (sev === "critical") return "🔴";
  if (sev === "high") return "🟠";
  if (sev === "medium") return "🟡";
  if (sev === "low") return "🔵";
  return "⚪";
}

function printPackageRisk(pkg: PackageRisk): void {
  const levelColor =
    pkg.riskLevel === "block"
      ? COLORS.red
      : pkg.riskLevel === "warn"
        ? COLORS.yellow
        : COLORS.green;
  const levelIcon =
    pkg.riskLevel === "block" ? "❌" : pkg.riskLevel === "warn" ? "⚠️ " : "✅";

  console.log(
    `${levelIcon} ${COLORS.bold}${pkg.name}@${pkg.version}${COLORS.reset} ` +
      `${levelColor}[${pkg.riskLevel.toUpperCase()}]${COLORS.reset} ` +
      `${COLORS.gray}(risk: ${pkg.riskScore}/100)${COLORS.reset}`,
  );

  for (const issue of pkg.issues) {
    const color = severityColor(issue.severity);
    console.log(
      `   ${severityIcon(issue.severity)} ${color}${issue.severity}${COLORS.reset} ` +
        `${COLORS.bold}${issue.type}${COLORS.reset}: ${issue.description}`,
    );
    if (issue.remediation) {
      console.log(`      ${COLORS.cyan}→ ${issue.remediation}${COLORS.reset}`);
    }
  }
}

function printReport(report: ScanReport): void {
  console.log("");
  console.log(
    `${COLORS.bold}🛡️  Weave Tollere — Supply Chain Scan${COLORS.reset}`,
  );
  console.log(COLORS.gray + "─".repeat(60) + COLORS.reset);
  console.log(
    `Scanned ${COLORS.bold}${report.totalPackages}${COLORS.reset} packages ` +
      `in ${report.scanDurationMs}ms`,
  );
  console.log("");

  if (report.blockedPackages.length > 0) {
    console.log(
      `${COLORS.red}${COLORS.bold}❌ BLOCKED (${report.blockedPackages.length})${COLORS.reset}`,
    );
    console.log(COLORS.gray + "─".repeat(60) + COLORS.reset);
    for (const pkg of report.blockedPackages) printPackageRisk(pkg);
    console.log("");
  }

  if (report.warnedPackages.length > 0) {
    console.log(
      `${COLORS.yellow}${COLORS.bold}⚠️  WARNINGS (${report.warnedPackages.length})${COLORS.reset}`,
    );
    console.log(COLORS.gray + "─".repeat(60) + COLORS.reset);
    for (const pkg of report.warnedPackages) printPackageRisk(pkg);
    console.log("");
  }

  console.log(`${COLORS.bold}Summary:${COLORS.reset}`);
  console.log(`  🔴 Critical: ${report.summary.critical}`);
  console.log(`  🟠 High:     ${report.summary.high}`);
  console.log(`  🟡 Medium:   ${report.summary.medium}`);
  console.log(`  🔵 Low:      ${report.summary.low}`);
  console.log("");

  const recColor =
    report.recommendation === "BLOCK_INSTALL"
      ? COLORS.red
      : report.recommendation === "REVIEW_REQUIRED"
        ? COLORS.yellow
        : COLORS.green;
  console.log(
    `${COLORS.bold}Recommendation: ${recColor}${report.recommendation}${COLORS.reset}`,
  );
  console.log("");
}

async function cmdScan(path?: string): Promise<number> {
  const pkgJsonPath = resolve(path || "./package.json");
  if (!existsSync(pkgJsonPath)) {
    console.error(`${COLORS.red}package.json not found at ${pkgJsonPath}${COLORS.reset}`);
    return 2;
  }

  const contents = readFileSync(pkgJsonPath, "utf8");
  const report = await scanPackageJson(contents, DEFAULT_CONFIG);
  printReport(report);

  if (report.recommendation === "BLOCK_INSTALL") return 2;
  if (report.recommendation === "REVIEW_REQUIRED") return 1;
  return 0;
}

async function cmdCheck(name: string, version?: string): Promise<number> {
  const result = await scanPackage(name, version || "latest", "npm", DEFAULT_CONFIG);
  console.log("");
  printPackageRisk(result);
  console.log("");
  return result.riskLevel === "block" ? 2 : result.riskLevel === "warn" ? 1 : 0;
}

async function cmdTyposquat(name: string): Promise<number> {
  const matches = detectTyposquat(name);
  if (matches.length === 0) {
    console.log(`${COLORS.green}✅ No typosquat patterns detected for "${name}"${COLORS.reset}`);
    return 0;
  }
  console.log(`${COLORS.yellow}⚠️  Possible typosquat patterns for "${name}":${COLORS.reset}`);
  for (const m of matches) {
    console.log(
      `   → ${COLORS.bold}${m.suspectedTarget}${COLORS.reset} ` +
        `(distance: ${m.editDistance}, similarity: ${(m.similarity * 100).toFixed(1)}%)`,
    );
  }
  return 1;
}

async function cmdDiff(name: string, v1: string, v2: string): Promise<number> {
  const diff = await diffVersions(name, v1, v2);
  if (!diff) {
    console.error(`${COLORS.red}Could not compute diff${COLORS.reset}`);
    return 2;
  }

  console.log("");
  console.log(`${COLORS.bold}📦 ${name}: ${v1} → ${v2}${COLORS.reset}`);
  console.log(COLORS.gray + "─".repeat(60) + COLORS.reset);
  console.log(`Type: ${diff.changeType}`);
  console.log(`Publish gap: ${diff.publishGap.toFixed(1)} hours`);
  console.log(`Risk score: ${diff.riskScore}/100`);
  console.log("");

  if (diff.newInstallScript) {
    console.log(`${COLORS.red}🚨 NEW INSTALL SCRIPT INTRODUCED${COLORS.reset}`);
  }
  if (diff.newDependencies.length > 0) {
    console.log(
      `${COLORS.yellow}+ New deps: ${diff.newDependencies.join(", ")}${COLORS.reset}`,
    );
  }
  if (diff.suspiciousPatterns.length > 0) {
    console.log(`${COLORS.red}🚩 Suspicious patterns:${COLORS.reset}`);
    for (const p of diff.suspiciousPatterns) console.log(`   - ${p}`);
  }
  console.log("");

  return diff.riskScore >= 50 ? 2 : diff.riskScore >= 25 ? 1 : 0;
}

function printHelp(): void {
  console.log(`
${COLORS.bold}🛡️  Weave Tollere${COLORS.reset} - Supply chain security for AI-generated code

${COLORS.bold}Usage:${COLORS.reset}
  weave-tollere scan [path]                Scan a package.json (default: ./package.json)
  weave-tollere check <pkg> [version]      Check a single package
  weave-tollere typosquat <name>           Check for typosquat patterns
  weave-tollere diff <pkg> <v1> <v2>       Compare two versions for suspicious changes
  weave-tollere help                       Show this help

${COLORS.bold}Examples:${COLORS.reset}
  weave-tollere scan
  weave-tollere check axios 1.7.2
  weave-tollere typosquat raect
  weave-tollere diff axios 1.7.0 1.7.1

${COLORS.bold}Exit codes:${COLORS.reset}
  0 = no issues
  1 = warnings (review recommended)
  2 = critical (install blocked)
`);
}

async function main(): Promise<void> {
  const [, , cmd, ...rest] = process.argv;

  let exitCode = 0;
  try {
    switch (cmd) {
      case "scan":
        exitCode = await cmdScan(rest[0]);
        break;
      case "check":
        if (!rest[0]) {
          console.error("Usage: weave-tollere check <package> [version]");
          exitCode = 2;
        } else {
          exitCode = await cmdCheck(rest[0], rest[1]);
        }
        break;
      case "typosquat":
        if (!rest[0]) {
          console.error("Usage: weave-tollere typosquat <name>");
          exitCode = 2;
        } else {
          exitCode = await cmdTyposquat(rest[0]);
        }
        break;
      case "diff":
        if (rest.length < 3) {
          console.error("Usage: weave-tollere diff <package> <v1> <v2>");
          exitCode = 2;
        } else {
          exitCode = await cmdDiff(rest[0], rest[1], rest[2]);
        }
        break;
      case "help":
      case "--help":
      case "-h":
      case undefined:
        printHelp();
        exitCode = 0;
        break;
      default:
        console.error(`Unknown command: ${cmd}`);
        printHelp();
        exitCode = 2;
    }
  } catch (err) {
    console.error(`${COLORS.red}Error: ${err instanceof Error ? err.message : err}${COLORS.reset}`);
    exitCode = 2;
  }

  process.exit(exitCode);
}

main();
