/**
 * Main scanner - orchestrates all checks and produces a risk report
 */

import type {
  PackageRisk,
  RiskIssue,
  ScanReport,
  TollereConfig,
  Ecosystem,
  Severity,
} from "./types.js";
import { DEFAULT_CONFIG } from "./types.js";
import { detectTyposquat } from "./typosquat.js";
import { fetchPackageMetadata, computeReputationScore } from "./reputation.js";
import { queryCVEs } from "./cve.js";

interface PackageJson {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

/**
 * Strip semver range characters (^, ~, >=, etc.) to get clean version
 */
function cleanVersion(version: string): string {
  return version.replace(/^[\^~>=<\s]+/, "").trim();
}

/**
 * Compute severity-based risk score contribution
 */
function severityWeight(severity: Severity): number {
  const weights: Record<Severity, number> = {
    critical: 50,
    high: 30,
    medium: 15,
    low: 5,
    info: 1,
  };
  return weights[severity];
}

/**
 * Scan a single package and produce a risk profile
 */
export async function scanPackage(
  name: string,
  version: string,
  ecosystem: Ecosystem = "npm",
  config: TollereConfig = DEFAULT_CONFIG,
): Promise<PackageRisk> {
  const issues: RiskIssue[] = [];
  let riskScore = 0;

  // Allowlist short-circuit
  if (config.allowedPackages.includes(name)) {
    return {
      name,
      version,
      ecosystem,
      riskScore: 0,
      riskLevel: "allow",
      issues: [],
      metadata: {},
    };
  }

  // Blocklist short-circuit
  if (config.blockedPackages.includes(name)) {
    return {
      name,
      version,
      ecosystem,
      riskScore: 100,
      riskLevel: "block",
      issues: [
        {
          type: "malicious_maintainer",
          severity: "critical",
          description: "Package is on configured blocklist",
        },
      ],
      metadata: {},
    };
  }

  // Typosquat check
  if (config.checkTyposquats) {
    const typosquats = detectTyposquat(name);
    if (typosquats.length > 0) {
      const top = typosquats[0];
      const severity: Severity =
        top.editDistance <= 1 ? "critical" : top.editDistance <= 2 ? "high" : "medium";
      issues.push({
        type: "typosquat",
        severity,
        description: `Possible typosquat of "${top.suspectedTarget}" (edit distance: ${top.editDistance})`,
        evidence: `Similarity: ${(top.similarity * 100).toFixed(1)}%`,
        remediation: `Did you mean to install "${top.suspectedTarget}"?`,
      });
      riskScore += severityWeight(severity);
    }
  }

  // Fetch metadata once for both reputation and freshness check
  const metadata = (await fetchPackageMetadata(name)) || {};

  // Maintainer/reputation check
  if (config.checkMaintainers && Object.keys(metadata).length > 0) {
    const reputation = computeReputationScore(metadata);

    if (reputation.score < config.minMaintainerScore) {
      const severity: Severity = reputation.score < 20 ? "high" : "medium";
      issues.push({
        type: "low_reputation",
        severity,
        description: `Low maintainer reputation score: ${reputation.score}/100`,
        evidence: reputation.signals
          .filter((s) => !s.positive)
          .map((s) => `- ${s.description}`)
          .join("\n"),
      });
      riskScore += severityWeight(severity);
    }

    // Package age check
    if (metadata.publishedAt) {
      const ageHours =
        (Date.now() - new Date(metadata.publishedAt).getTime()) / (1000 * 60 * 60);
      if (ageHours < config.minPackageAgeHours) {
        issues.push({
          type: "version_anomaly",
          severity: "medium",
          description: `Package is very new (published ${Math.floor(ageHours)} hours ago)`,
          remediation: `Consider waiting at least ${config.minPackageAgeHours} hours before adopting`,
        });
        riskScore += severityWeight("medium");
      }
    }
  }

  // CVE check
  if (config.checkCVEs && version && version !== "unknown") {
    const cleanVer = cleanVersion(version);
    const cves = await queryCVEs(name, cleanVer, ecosystem);

    for (const cve of cves) {
      issues.push({
        type: "cve",
        severity: cve.severity,
        description: `${cve.id}: ${cve.summary}`,
        evidence: cve.cvssScore ? `CVSS: ${cve.cvssScore}` : undefined,
        remediation: cve.patchedVersions
          ? `Upgrade to ${cve.patchedVersions}`
          : "No patch available - consider alternatives",
        references: cve.references,
      });
      riskScore += severityWeight(cve.severity);
    }
  }

  // Determine overall risk level
  let riskLevel: PackageRisk["riskLevel"] = "allow";
  const hasCritical = issues.some((i) => i.severity === "critical");
  const hasHigh = issues.some((i) => i.severity === "high");
  const hasMedium = issues.some((i) => i.severity === "medium");

  if (hasCritical && config.blockOnCritical) riskLevel = "block";
  else if (hasHigh && config.blockOnHigh) riskLevel = "block";
  else if (hasHigh) riskLevel = "warn";
  else if (hasMedium && config.warnOnMedium) riskLevel = "warn";

  // Strict mode = block on any high or above
  if (config.mode === "strict" && (hasCritical || hasHigh)) {
    riskLevel = "block";
  }

  return {
    name,
    version,
    ecosystem,
    riskScore: Math.min(100, riskScore),
    riskLevel,
    issues,
    metadata,
  };
}

/**
 * Scan a package.json and produce a full report
 */
export async function scanPackageJson(
  packageJson: PackageJson | string,
  config: TollereConfig = DEFAULT_CONFIG,
): Promise<ScanReport> {
  const startTime = Date.now();

  const pkg: PackageJson =
    typeof packageJson === "string" ? JSON.parse(packageJson) : packageJson;

  const allDeps: Array<{ name: string; version: string }> = [
    ...Object.entries(pkg.dependencies || {}).map(([name, version]) => ({
      name,
      version,
    })),
    ...Object.entries(pkg.devDependencies || {}).map(([name, version]) => ({
      name,
      version,
    })),
    ...Object.entries(pkg.peerDependencies || {}).map(([name, version]) => ({
      name,
      version,
    })),
    ...Object.entries(pkg.optionalDependencies || {}).map(([name, version]) => ({
      name,
      version,
    })),
  ];

  // Deduplicate
  const seen = new Set<string>();
  const uniqueDeps = allDeps.filter((d) => {
    const key = `${d.name}@${d.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Scan all packages in parallel (with reasonable concurrency limit)
  const CONCURRENCY = 10;
  const results: PackageRisk[] = [];
  for (let i = 0; i < uniqueDeps.length; i += CONCURRENCY) {
    const batch = uniqueDeps.slice(i, i + CONCURRENCY);
    const batchResults = await Promise.all(
      batch.map((d) => scanPackage(d.name, cleanVersion(d.version), "npm", config)),
    );
    results.push(...batchResults);
  }

  const blockedPackages = results.filter((r) => r.riskLevel === "block");
  const warnedPackages = results.filter((r) => r.riskLevel === "warn");
  const allowedPackages = results.filter((r) => r.riskLevel === "allow");

  // Aggregate severity counts
  const summary = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const r of results) {
    for (const issue of r.issues) {
      if (issue.severity === "critical") summary.critical++;
      else if (issue.severity === "high") summary.high++;
      else if (issue.severity === "medium") summary.medium++;
      else if (issue.severity === "low") summary.low++;
    }
  }

  // Overall recommendation
  let recommendation: ScanReport["recommendation"] = "PROCEED";
  if (blockedPackages.length > 0) recommendation = "BLOCK_INSTALL";
  else if (warnedPackages.length > 0) recommendation = "REVIEW_REQUIRED";

  return {
    scannedAt: new Date().toISOString(),
    ecosystem: "npm",
    totalPackages: uniqueDeps.length,
    blockedPackages,
    warnedPackages,
    allowedPackages,
    summary,
    scanDurationMs: Date.now() - startTime,
    recommendation,
  };
}
