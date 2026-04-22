/**
 * @weave_protocol/tollere - Type definitions
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type RiskLevel = "block" | "warn" | "allow";

export type Ecosystem = "npm" | "pypi" | "cargo" | "go" | "maven";

export interface PackageRisk {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  riskScore: number; // 0-100, higher = more risky
  riskLevel: RiskLevel;
  issues: RiskIssue[];
  metadata: PackageMetadata;
}

export interface RiskIssue {
  type: IssueType;
  severity: Severity;
  description: string;
  evidence?: string;
  remediation?: string;
  references?: string[];
}

export type IssueType =
  | "typosquat"
  | "cve"
  | "malicious_maintainer"
  | "ownership_change"
  | "suspicious_install_script"
  | "obfuscated_code"
  | "data_exfiltration"
  | "unmaintained"
  | "low_reputation"
  | "version_anomaly"
  | "dependency_confusion"
  | "license_issue";

export interface PackageMetadata {
  description?: string;
  author?: string;
  maintainers?: Maintainer[];
  weeklyDownloads?: number;
  publishedAt?: string;
  lastUpdated?: string;
  homepage?: string;
  repository?: string;
  license?: string;
  hasInstallScript?: boolean;
  hasPostinstall?: boolean;
}

export interface Maintainer {
  name: string;
  email?: string;
  joinedAt?: string;
  reputationScore?: number;
}

export interface ReputationScore {
  score: number; // 0-100, higher = more trustworthy
  signals: ReputationSignal[];
}

export interface ReputationSignal {
  type:
    | "account_age"
    | "package_count"
    | "recent_activity"
    | "ownership_history"
    | "verified_publisher"
    | "github_activity";
  positive: boolean;
  weight: number;
  description: string;
}

export interface TyposquatMatch {
  suspectedTarget: string;
  similarity: number; // 0-1
  editDistance: number;
  popularPackageDownloads?: number;
}

export interface CVE {
  id: string; // e.g., CVE-2024-12345 or GHSA-xxxx-xxxx-xxxx
  severity: Severity;
  cvssScore?: number;
  summary: string;
  affectedVersions: string;
  patchedVersions?: string;
  publishedAt?: string;
  references?: string[];
}

export interface VersionDiff {
  fromVersion: string;
  toVersion: string;
  changeType: "patch" | "minor" | "major";
  publishGap: number; // hours between publishes
  filesChanged: number;
  linesAdded: number;
  linesRemoved: number;
  newDependencies: string[];
  removedDependencies: string[];
  newScripts: string[];
  newInstallScript: boolean;
  suspiciousPatterns: string[];
  riskScore: number;
}

export interface ScanReport {
  scannedAt: string;
  packageJsonPath?: string;
  ecosystem: Ecosystem;
  totalPackages: number;
  blockedPackages: PackageRisk[];
  warnedPackages: PackageRisk[];
  allowedPackages: PackageRisk[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  scanDurationMs: number;
  recommendation: "BLOCK_INSTALL" | "REVIEW_REQUIRED" | "PROCEED";
}

export interface TollereConfig {
  mode: "strict" | "balanced" | "permissive";
  blockOnCritical: boolean;
  blockOnHigh: boolean;
  warnOnMedium: boolean;
  checkTyposquats: boolean;
  checkCVEs: boolean;
  checkMaintainers: boolean;
  checkVersionDiffs: boolean;
  minMaintainerScore: number;
  minPackageAgeHours: number;
  cveDataSource: "osv" | "ghsa" | "both";
  trustedPublishers: string[];
  blockedPackages: string[];
  allowedPackages: string[];
}

export const DEFAULT_CONFIG: TollereConfig = {
  mode: "balanced",
  blockOnCritical: true,
  blockOnHigh: false,
  warnOnMedium: true,
  checkTyposquats: true,
  checkCVEs: true,
  checkMaintainers: true,
  checkVersionDiffs: true,
  minMaintainerScore: 30,
  minPackageAgeHours: 72,
  cveDataSource: "both",
  trustedPublishers: [],
  blockedPackages: [],
  allowedPackages: [],
};
