/**
 * Version diff scanner
 *
 * Detects suspicious changes between package versions:
 * - Sudden install scripts where there were none
 * - Network calls injected
 * - Obfuscated code blobs
 * - New dependencies (especially low-reputation ones)
 * - Unusual file changes (e.g. images that contain code)
 *
 * This is the "Axios case" detector - catches social engineering after
 * a maintainer is compromised.
 */

import type { VersionDiff } from "./types.js";

interface NpmVersionData {
  name?: string;
  version?: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  bin?: Record<string, string> | string;
  main?: string;
  files?: string[];
  _hasShrinkwrap?: boolean;
  dist?: {
    tarball?: string;
    shasum?: string;
    integrity?: string;
    fileCount?: number;
    unpackedSize?: number;
  };
}

interface NpmFullData {
  name: string;
  versions?: Record<string, NpmVersionData>;
  time?: Record<string, string>;
}

/**
 * Suspicious script patterns
 */
const SUSPICIOUS_SCRIPT_PATTERNS = [
  { pattern: /curl\s+/i, description: "curl command in script" },
  { pattern: /wget\s+/i, description: "wget command in script" },
  { pattern: /eval\s*\(/i, description: "eval() in script" },
  { pattern: /base64\s*-d/i, description: "base64 decoding in script" },
  { pattern: /\|\s*sh/i, description: "piping to shell" },
  { pattern: /\|\s*bash/i, description: "piping to bash" },
  { pattern: /node\s+-e/i, description: "node -e inline execution" },
  { pattern: /python\s+-c/i, description: "python -c inline execution" },
  { pattern: /\/dev\/tcp/i, description: "TCP connection via /dev/tcp" },
  { pattern: /nc\s+-/i, description: "netcat in script" },
  { pattern: /\.onion/i, description: "Tor hidden service URL" },
  { pattern: /[a-zA-Z0-9+/]{100,}={0,2}/, description: "Long base64 blob" },
  { pattern: /\\x[0-9a-f]{2}/i, description: "Hex-encoded characters" },
];

/**
 * Fetch package data from npm registry
 */
async function fetchPackageData(packageName: string): Promise<NpmFullData | null> {
  try {
    const res = await fetch(
      `https://registry.npmjs.org/${encodeURIComponent(packageName)}`,
    );
    if (!res.ok) return null;
    return (await res.json()) as NpmFullData;
  } catch {
    return null;
  }
}

/**
 * Determine semver bump type
 */
function bumpType(from: string, to: string): "patch" | "minor" | "major" {
  const fromParts = from.split(".").map((n) => parseInt(n, 10));
  const toParts = to.split(".").map((n) => parseInt(n, 10));

  if (toParts[0] > fromParts[0]) return "major";
  if (toParts[1] > fromParts[1]) return "minor";
  return "patch";
}

/**
 * Compute diff between two versions of a package
 */
export async function diffVersions(
  packageName: string,
  fromVersion: string,
  toVersion: string,
): Promise<VersionDiff | null> {
  const data = await fetchPackageData(packageName);
  if (!data || !data.versions) return null;

  const fromData = data.versions[fromVersion];
  const toData = data.versions[toVersion];
  if (!fromData || !toData) return null;

  // Time gap between publishes
  const fromTime = data.time?.[fromVersion];
  const toTime = data.time?.[toVersion];
  let publishGap = 0;
  if (fromTime && toTime) {
    publishGap = (new Date(toTime).getTime() - new Date(fromTime).getTime()) /
      (1000 * 60 * 60);
  }

  // Dependency changes
  const fromDeps = new Set(Object.keys(fromData.dependencies || {}));
  const toDeps = new Set(Object.keys(toData.dependencies || {}));

  const newDependencies = [...toDeps].filter((d) => !fromDeps.has(d));
  const removedDependencies = [...fromDeps].filter((d) => !toDeps.has(d));

  // Script changes
  const fromScripts = fromData.scripts || {};
  const toScripts = toData.scripts || {};
  const fromScriptNames = new Set(Object.keys(fromScripts));
  const newScripts: string[] = [];

  for (const scriptName of Object.keys(toScripts)) {
    if (!fromScriptNames.has(scriptName)) {
      newScripts.push(scriptName);
    }
  }

  // Install script appeared?
  const hadInstallScript = !!(
    fromScripts.install ||
    fromScripts.preinstall ||
    fromScripts.postinstall
  );
  const hasInstallScript = !!(
    toScripts.install ||
    toScripts.preinstall ||
    toScripts.postinstall
  );
  const newInstallScript = !hadInstallScript && hasInstallScript;

  // Suspicious patterns in scripts
  const suspiciousPatterns: string[] = [];
  for (const [name, script] of Object.entries(toScripts)) {
    for (const { pattern, description } of SUSPICIOUS_SCRIPT_PATTERNS) {
      if (pattern.test(script) && !pattern.test(fromScripts[name] || "")) {
        suspiciousPatterns.push(`${name}: ${description}`);
      }
    }
  }

  // File size delta as proxy for "files changed"
  const fromSize = fromData.dist?.unpackedSize || 0;
  const toSize = toData.dist?.unpackedSize || 0;
  const sizeDelta = toSize - fromSize;
  const fromFileCount = fromData.dist?.fileCount || 0;
  const toFileCount = toData.dist?.fileCount || 0;

  // Compute risk score (0-100)
  let riskScore = 0;

  // Patch release with major changes is suspicious
  const bump = bumpType(fromVersion, toVersion);
  if (bump === "patch" && Math.abs(sizeDelta) > 50000) riskScore += 25;
  if (bump === "patch" && newDependencies.length > 0) riskScore += 15;
  if (bump === "patch" && newInstallScript) riskScore += 40;

  // Any new install script is concerning
  if (newInstallScript) riskScore += 30;

  // Suspicious patterns are always concerning
  riskScore += suspiciousPatterns.length * 20;

  // Many new deps in a single release
  if (newDependencies.length > 5) riskScore += 15;

  // Very fast release (under 1 hour) might indicate compromised account
  if (publishGap > 0 && publishGap < 1) riskScore += 10;

  // Very large file count change
  const fileCountDelta = Math.abs(toFileCount - fromFileCount);
  if (fileCountDelta > 50 && bump === "patch") riskScore += 15;

  riskScore = Math.min(100, riskScore);

  return {
    fromVersion,
    toVersion,
    changeType: bump,
    publishGap,
    filesChanged: fileCountDelta,
    linesAdded: Math.max(0, sizeDelta), // approximation via byte delta
    linesRemoved: Math.max(0, -sizeDelta),
    newDependencies,
    removedDependencies,
    newScripts,
    newInstallScript,
    suspiciousPatterns,
    riskScore,
  };
}
