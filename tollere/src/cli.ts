#!/usr/bin/env node
/**
 * @weave_protocol/tollere - CLI (v0.2)
 *
 * Commands:
 *   weave-tollere scan [path]                   Scan current package.json
 *   weave-tollere check <pkg> [version]         Check single package
 *   weave-tollere typosquat <name>              Check for typosquat
 *   weave-tollere diff <pkg> <v1> <v2>          Diff two versions
 *   weave-tollere sandwich <pkg> [N]            Detect sandwich pattern
 *   weave-tollere docker <image>                Scan Docker image
 *   weave-tollere ext <id> [ecosystem]          Scan IDE extension
 *
 * Exit codes: 0 = no issues, 1 = warnings, 2 = critical
 */

import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

import { scanPackage, scanPackageJson } from "./scanner.js";
import { detectTyposquat } from "./typosquat.js";
import { diffVersions } from "./diff.js";
import { detectSandwichPattern } from "./sandwich.js";
import { scanDockerImage } from "./docker.js";
import { scanExtension, type IDEEcosystem } from "./extensions/index.js";
import { DEFAULT_CONFIG } from "./types.js";
import type { ScanReport, PackageRisk, Severity, RiskIssue } from "./types.js";

const C = {
  reset: "\x1b[0m", bold: "\x1b[1m", red: "\x1b[31m", yellow: "\x1b[33m",
  green: "\x1b[32m", blue: "\x1b[34m", gray: "\x1b[90m", cyan: "\x1b[36m",
};

function sevColor(s: Severity): string {
  if (s === "critical" || s === "high") return C.red;
  if (s === "medium") return C.yellow;
  return C.gray;
}

function sevIcon(s: Severity): string {
  return s === "critical" ? "🔴" : s === "high" ? "🟠" : s === "medium" ? "🟡" : s === "low" ? "🔵" : "⚪";
}

function levelBadge(level: string): string {
  const color = level === "block" ? C.red : level === "warn" ? C.yellow : C.green;
  const icon = level === "block" ? "❌" : level === "warn" ? "⚠️ " : "✅";
  return `${icon} ${color}[${level.toUpperCase()}]${C.reset}`;
}

function printIssue(issue: RiskIssue): void {
  const color = sevColor(issue.severity);
  console.log(`   ${sevIcon(issue.severity)} ${color}${issue.severity}${C.reset} ${C.bold}${issue.type}${C.reset}: ${issue.description}`);
  if (issue.evidence) console.log(`      ${C.gray}${issue.evidence}${C.reset}`);
  if (issue.remediation) console.log(`      ${C.cyan}→ ${issue.remediation}${C.reset}`);
}

function printPackageRisk(pkg: PackageRisk): void {
  console.log(`${levelBadge(pkg.riskLevel)} ${C.bold}${pkg.name}@${pkg.version}${C.reset} ${C.gray}(risk: ${pkg.riskScore}/100)${C.reset}`);
  for (const issue of pkg.issues) printIssue(issue);
}

function printReport(report: ScanReport): void {
  console.log("");
  console.log(`${C.bold}🛂  Weave Tollere — Supply Chain Scan${C.reset}`);
  console.log(C.gray + "─".repeat(60) + C.reset);
  console.log(`Scanned ${C.bold}${report.totalPackages}${C.reset} packages in ${report.scanDurationMs}ms`);
  console.log("");

  if (report.blockedPackages.length > 0) {
    console.log(`${C.red}${C.bold}❌ BLOCKED (${report.blockedPackages.length})${C.reset}`);
    console.log(C.gray + "─".repeat(60) + C.reset);
    for (const pkg of report.blockedPackages) printPackageRisk(pkg);
    console.log("");
  }
  if (report.warnedPackages.length > 0) {
    console.log(`${C.yellow}${C.bold}⚠️  WARNINGS (${report.warnedPackages.length})${C.reset}`);
    console.log(C.gray + "─".repeat(60) + C.reset);
    for (const pkg of report.warnedPackages) printPackageRisk(pkg);
    console.log("");
  }

  console.log(`${C.bold}Summary:${C.reset}`);
  console.log(`  🔴 Critical: ${report.summary.critical}`);
  console.log(`  🟠 High:     ${report.summary.high}`);
  console.log(`  🟡 Medium:   ${report.summary.medium}`);
  console.log(`  🔵 Low:      ${report.summary.low}\n`);

  const recColor = report.recommendation === "BLOCK_INSTALL" ? C.red : report.recommendation === "REVIEW_REQUIRED" ? C.yellow : C.green;
  console.log(`${C.bold}Recommendation: ${recColor}${report.recommendation}${C.reset}\n`);
}

async function cmdScan(path?: string): Promise<number> {
  const pkgJsonPath = resolve(path || "./package.json");
  if (!existsSync(pkgJsonPath)) {
    console.error(`${C.red}package.json not found at ${pkgJsonPath}${C.reset}`);
    return 2;
  }
  const contents = readFileSync(pkgJsonPath, "utf8");
  const report = await scanPackageJson(contents, DEFAULT_CONFIG);
  printReport(report);
  return report.recommendation === "BLOCK_INSTALL" ? 2 : report.recommendation === "REVIEW_REQUIRED" ? 1 : 0;
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
    console.log(`${C.green}✅ No typosquat patterns detected for "${name}"${C.reset}`);
    return 0;
  }
  console.log(`${C.yellow}⚠️  Possible typosquat patterns for "${name}":${C.reset}`);
  for (const m of matches) {
    console.log(`   → ${C.bold}${m.suspectedTarget}${C.reset} (distance: ${m.editDistance}, similarity: ${(m.similarity * 100).toFixed(1)}%)`);
  }
  return 1;
}

async function cmdDiff(name: string, v1: string, v2: string): Promise<number> {
  const diff = await diffVersions(name, v1, v2);
  if (!diff) {
    console.error(`${C.red}Could not compute diff${C.reset}`);
    return 2;
  }
  console.log(`\n${C.bold}📦 ${name}: ${v1} → ${v2}${C.reset}`);
  console.log(C.gray + "─".repeat(60) + C.reset);
  console.log(`Type: ${diff.changeType}`);
  console.log(`Publish gap: ${diff.publishGap.toFixed(1)} hours`);
  console.log(`Risk score: ${diff.riskScore}/100\n`);
  if (diff.newInstallScript) console.log(`${C.red}🚨 NEW INSTALL SCRIPT INTRODUCED${C.reset}`);
  if (diff.newDependencies.length > 0) console.log(`${C.yellow}+ New deps: ${diff.newDependencies.join(", ")}${C.reset}`);
  if (diff.suspiciousPatterns.length > 0) {
    console.log(`${C.red}🚩 Suspicious patterns:${C.reset}`);
    for (const p of diff.suspiciousPatterns) console.log(`   - ${p}`);
  }
  console.log("");
  return diff.riskScore >= 50 ? 2 : diff.riskScore >= 25 ? 1 : 0;
}

async function cmdSandwich(name: string, lastN?: string): Promise<number> {
  const n = lastN ? parseInt(lastN, 10) : 15;
  console.log(`\n${C.bold}🥪 Scanning ${name} for sandwich patterns (last ${n} versions)...${C.reset}\n`);
  const result = await detectSandwichPattern(name, { lastN: n });
  console.log(`Versions analyzed: ${result.versionsAnalyzed}`);
  if (!result.patternDetected || !result.pattern) {
    console.log(`${C.green}✅ No sandwich pattern detected${C.reset}\n`);
    return 0;
  }
  const p = result.pattern;
  console.log(`${C.red}🚨 SANDWICH PATTERN DETECTED${C.reset}`);
  console.log(`${C.gray}─${C.reset}`.repeat(60));
  console.log(`Pattern type:   ${C.bold}${p.patternType}${C.reset}`);
  console.log(`Risk score:     ${result.riskScore}/100`);
  console.log(`${C.red}Introduced in:${C.reset} ${p.introducedIn}`);
  console.log(`${C.yellow}Removed in:   ${C.reset} ${p.removedIn} (sandwich filling)`);
  console.log(`${C.red}Reappeared in:${C.reset} ${p.reappearedIn}`);
  console.log(`\nEvidence: ${p.evidence}\n`);
  return result.riskScore >= 70 ? 2 : 1;
}

async function cmdDocker(image: string): Promise<number> {
  console.log(`\n${C.bold}🐳 Scanning Docker image: ${image}${C.reset}\n`);
  const result = await scanDockerImage(image);
  console.log(`${levelBadge(result.riskLevel)} ${C.bold}${result.image}${C.reset} ${C.gray}(risk: ${result.riskScore}/100)${C.reset}`);
  if (result.manifest) {
    console.log(`${C.gray}Digest: ${result.manifest.digest.substring(0, 30)}...${C.reset}`);
    console.log(`${C.gray}Last updated: ${result.manifest.lastUpdated}${C.reset}`);
    console.log(`${C.gray}Size: ${(result.manifest.size / 1024 / 1024).toFixed(1)} MB, ${result.manifest.layers} layer(s)${C.reset}`);
  }
  console.log("");
  for (const issue of result.issues) printIssue(issue);
  console.log("");
  return result.riskLevel === "block" ? 2 : result.riskLevel === "warn" ? 1 : 0;
}

async function cmdExt(fullId: string, ecosystem?: string): Promise<number> {
  const eco = (ecosystem || "vscode") as IDEEcosystem;
  console.log(`\n${C.bold}🧩 Scanning ${eco} extension: ${fullId}${C.reset}\n`);
  const result = await scanExtension(fullId, eco);
  console.log(`${levelBadge(result.riskLevel)} ${C.bold}${result.fullId}${C.reset} ${C.gray}(risk: ${result.riskScore}/100)${C.reset}`);
  if (result.metadata.publisher) console.log(`${C.gray}Publisher: ${result.metadata.publisher}${result.metadata.publisherVerified ? " ✓" : ""}${C.reset}`);
  if (result.metadata.installs) console.log(`${C.gray}Installs: ${result.metadata.installs.toLocaleString()}${C.reset}`);
  if (result.metadata.downloads) console.log(`${C.gray}Downloads: ${result.metadata.downloads.toLocaleString()}${C.reset}`);
  if (result.metadata.rating) console.log(`${C.gray}Rating: ${result.metadata.rating.toFixed(1)} (${result.metadata.ratingCount || 0} reviews)${C.reset}`);
  console.log("");
  for (const issue of result.issues) printIssue(issue);
  console.log("");
  return result.riskLevel === "block" ? 2 : result.riskLevel === "warn" ? 1 : 0;
}

function help(): void {
  console.log(`
${C.bold}🛂  Weave Tollere v0.2${C.reset} - Supply chain security for AI-generated code

${C.bold}Package commands:${C.reset}
  weave-tollere scan [path]              Scan a package.json
  weave-tollere check <pkg> [version]    Check a single package
  weave-tollere typosquat <name>         Check for typosquat patterns
  weave-tollere diff <pkg> <v1> <v2>     Compare two versions
  weave-tollere sandwich <pkg> [N]       🆕 Detect sandwich-pattern attacks

${C.bold}Docker commands:${C.reset}
  weave-tollere docker <image>           🆕 Scan Docker image (Docker Hub)

${C.bold}IDE Extension commands:${C.reset}
  weave-tollere ext <id> [ecosystem]     🆕 Scan IDE extension
                                         ecosystems: vscode, cursor, windsurf, openvsx, jetbrains

${C.bold}Examples:${C.reset}
  weave-tollere scan
  weave-tollere check axios 1.7.2
  weave-tollere typosquat raect
  weave-tollere diff axios 1.7.0 1.7.1
  weave-tollere sandwich some-package 20
  weave-tollere docker checkmarx/kics:v2.1.20
  weave-tollere ext ms-python.python vscode
  weave-tollere ext rust-lang.rust openvsx
  weave-tollere ext "Python" jetbrains

${C.bold}Exit codes:${C.reset}
  0 = no issues, 1 = warnings, 2 = critical (install blocked)
`);
}

async function main(): Promise<void> {
  const [, , cmd, ...rest] = process.argv;
  let exitCode = 0;
  try {
    switch (cmd) {
      case "scan": exitCode = await cmdScan(rest[0]); break;
      case "check":
        if (!rest[0]) { console.error("Usage: weave-tollere check <package> [version]"); exitCode = 2; }
        else exitCode = await cmdCheck(rest[0], rest[1]);
        break;
      case "typosquat":
        if (!rest[0]) { console.error("Usage: weave-tollere typosquat <name>"); exitCode = 2; }
        else exitCode = await cmdTyposquat(rest[0]);
        break;
      case "diff":
        if (rest.length < 3) { console.error("Usage: weave-tollere diff <package> <v1> <v2>"); exitCode = 2; }
        else exitCode = await cmdDiff(rest[0], rest[1], rest[2]);
        break;
      case "sandwich":
        if (!rest[0]) { console.error("Usage: weave-tollere sandwich <package> [N]"); exitCode = 2; }
        else exitCode = await cmdSandwich(rest[0], rest[1]);
        break;
      case "docker":
        if (!rest[0]) { console.error("Usage: weave-tollere docker <image>"); exitCode = 2; }
        else exitCode = await cmdDocker(rest[0]);
        break;
      case "ext":
        if (!rest[0]) { console.error("Usage: weave-tollere ext <id> [vscode|cursor|windsurf|openvsx|jetbrains]"); exitCode = 2; }
        else exitCode = await cmdExt(rest[0], rest[1]);
        break;
      case "help": case "--help": case "-h": case undefined:
        help(); exitCode = 0; break;
      default:
        console.error(`Unknown command: ${cmd}`); help(); exitCode = 2;
    }
  } catch (err) {
    console.error(`${C.red}Error: ${err instanceof Error ? err.message : err}${C.reset}`);
    exitCode = 2;
  }
  process.exit(exitCode);
}

main();
