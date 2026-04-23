/**
 * VS Code Marketplace scanner
 *
 * Covers: VS Code, Cursor, Windsurf, and any IDE that uses
 * the Visual Studio Marketplace API.
 *
 * API: https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery
 *
 * Triggered by attacks like the Checkmarx VS Code extension compromise (April 2026)
 * where versions 1.17.0 and 1.19.0 contained code that fetched and executed
 * remote JavaScript via the Bun runtime, with 1.18.0 sandwiched as a clean version.
 */

import type { ExtensionScanResult, ExtensionMetadata, RiskIssue } from "../types.js";

const MARKETPLACE_API =
  "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery";

interface ExtensionQueryResponse {
  results: Array<{
    extensions: Array<{
      publisher: {
        publisherId: string;
        publisherName: string;
        displayName: string;
        flags: string;
        domain?: string;
        isDomainVerified?: boolean;
      };
      extensionId: string;
      extensionName: string;
      displayName: string;
      shortDescription?: string;
      versions: Array<{
        version: string;
        lastUpdated: string;
        files?: Array<{ assetType: string; source: string }>;
      }>;
      categories?: string[];
      tags?: string[];
      flags?: string;
      lastUpdated: string;
      publishedDate?: string;
      releaseDate?: string;
      statistics?: Array<{ statisticName: string; value: number }>;
    }>;
  }>;
}

interface QueryFilter {
  filterType: number;
  value: string;
}

/**
 * Query the VS Code Marketplace for an extension by full ID
 * Format: "publisher.name" (e.g. "ms-python.python")
 */
async function queryMarketplace(
  fullId: string,
): Promise<ExtensionQueryResponse["results"][0]["extensions"][0] | null> {
  try {
    const body = {
      filters: [
        {
          criteria: [
            { filterType: 7, value: fullId } as QueryFilter, // ExtensionName
          ],
          pageNumber: 1,
          pageSize: 1,
          sortBy: 0,
          sortOrder: 0,
        },
      ],
      assetTypes: [],
      flags: 914, // include statistics, versions, files
    };

    const res = await fetch(MARKETPLACE_API, {
      method: "POST",
      headers: {
        Accept: "application/json;api-version=3.0-preview.1",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });

    if (!res.ok) return null;
    const data = (await res.json()) as ExtensionQueryResponse;
    return data.results[0]?.extensions[0] || null;
  } catch {
    return null;
  }
}

/**
 * Get a stat value by name
 */
function getStat(
  ext: ExtensionQueryResponse["results"][0]["extensions"][0],
  name: string,
): number | undefined {
  return ext.statistics?.find((s) => s.statisticName === name)?.value;
}

/**
 * Detect typosquats specific to extension names
 * (e.g., ms-python.python vs ms-pythοn.python with Greek omicron)
 */
function detectExtensionTyposquat(fullId: string): RiskIssue[] {
  const issues: RiskIssue[] = [];
  const popular = [
    "ms-python.python",
    "ms-vscode.cpptools",
    "esbenp.prettier-vscode",
    "dbaeumer.vscode-eslint",
    "ms-azuretools.vscode-docker",
    "github.copilot",
    "github.vscode-pull-request-github",
    "ms-toolsai.jupyter",
    "vscodevim.vim",
    "ritwickdey.liveserver",
    "rust-lang.rust-analyzer",
    "golang.go",
    "redhat.java",
    "ms-dotnettools.csharp",
  ];

  // Unicode lookalike check
  const ascii = fullId.replace(/[^\x00-\x7F]/g, "?");
  const hasNonAscii = ascii !== fullId;
  if (hasNonAscii) {
    issues.push({
      type: "typosquat",
      severity: "critical",
      description: `Extension ID contains non-ASCII characters (possible Unicode homoglyph attack)`,
      evidence: `Original: ${fullId}, ASCII-only: ${ascii}`,
      remediation: "Verify the publisher and extension name against the official source",
    });
  }

  // Edit distance check
  for (const target of popular) {
    if (target === fullId.toLowerCase()) continue;
    if (target.length < 4) continue;

    // Quick rough check: same length, ~1 char different
    if (Math.abs(target.length - fullId.length) <= 1) {
      let diffs = 0;
      const minLen = Math.min(target.length, fullId.length);
      for (let i = 0; i < minLen; i++) {
        if (target[i] !== fullId.toLowerCase()[i]) diffs++;
      }
      diffs += Math.abs(target.length - fullId.length);
      if (diffs >= 1 && diffs <= 2) {
        issues.push({
          type: "typosquat",
          severity: diffs === 1 ? "critical" : "high",
          description: `Extension ID "${fullId}" is suspiciously similar to popular extension "${target}"`,
          evidence: `Character difference: ${diffs}`,
          remediation: `Did you mean to install "${target}"?`,
        });
        break;
      }
    }
  }

  return issues;
}

/**
 * Scan a VS Code Marketplace extension
 */
export async function scanVSCodeExtension(fullId: string): Promise<ExtensionScanResult> {
  const issues: RiskIssue[] = [];
  const [publisherId, ...rest] = fullId.split(".");
  const extensionName = rest.join(".");

  // Typosquat check (doesn't need API call)
  issues.push(...detectExtensionTyposquat(fullId));

  const ext = await queryMarketplace(fullId);

  if (!ext) {
    return {
      ecosystem: "vscode",
      publisherId,
      extensionName,
      fullId,
      version: "unknown",
      riskScore: issues.length > 0 ? 50 : 0,
      riskLevel: issues.some((i) => i.severity === "critical") ? "block" : issues.length > 0 ? "warn" : "allow",
      issues: [
        ...issues,
        {
          type: "version_anomaly",
          severity: "medium",
          description: `Extension "${fullId}" not found on the Visual Studio Marketplace`,
        },
      ],
      metadata: {},
    };
  }

  const installs = getStat(ext, "install") || 0;
  const trendingDaily = getStat(ext, "trendingdaily") || 0;
  const downloadCount = getStat(ext, "downloadCount") || 0;
  const rating = getStat(ext, "averagerating") || 0;
  const ratingCount = getStat(ext, "ratingcount") || 0;

  const latestVersion = ext.versions[0]?.version || "unknown";

  const metadata: ExtensionMetadata = {
    displayName: ext.displayName,
    description: ext.shortDescription,
    publisher: ext.publisher.displayName,
    publisherVerified: ext.publisher.isDomainVerified,
    downloads: downloadCount,
    installs,
    rating,
    ratingCount,
    publishedAt: ext.publishedDate,
    lastUpdated: ext.lastUpdated,
    category: ext.categories,
  };

  // Check 1: Unverified publisher with low installs
  if (!ext.publisher.isDomainVerified && installs < 1000) {
    issues.push({
      type: "unverified_publisher",
      severity: "medium",
      description: `Publisher "${ext.publisher.displayName}" is not domain-verified and has only ${installs} installs`,
      remediation: "Verify publisher legitimacy via their official website or repository",
    });
  }

  // Check 2: Brand new extension
  if (ext.publishedDate) {
    const ageDays = (Date.now() - new Date(ext.publishedDate).getTime()) / (1000 * 60 * 60 * 24);
    if (ageDays < 7) {
      issues.push({
        type: "version_anomaly",
        severity: "medium",
        description: `Extension was published only ${Math.floor(ageDays)} days ago`,
        remediation: "Brand-new extensions warrant additional scrutiny",
      });
    }
  }

  // Check 3: Trending extension that's brand new (potential pump-and-dump)
  if (trendingDaily > 50 && installs < 5000) {
    issues.push({
      type: "version_anomaly",
      severity: "medium",
      description: `Extension has unusually high trending score (${trendingDaily}) for its install count (${installs})`,
      evidence: "May indicate artificial promotion or compromised popular extension",
    });
  }

  // Compute risk
  let riskScore = 0;
  for (const issue of issues) {
    if (issue.severity === "critical") riskScore += 50;
    else if (issue.severity === "high") riskScore += 30;
    else if (issue.severity === "medium") riskScore += 15;
    else if (issue.severity === "low") riskScore += 5;
  }
  riskScore = Math.min(100, riskScore);

  let riskLevel: ExtensionScanResult["riskLevel"] = "allow";
  if (issues.some((i) => i.severity === "critical")) riskLevel = "block";
  else if (issues.some((i) => i.severity === "high" || i.severity === "medium")) riskLevel = "warn";

  return {
    ecosystem: "vscode",
    publisherId,
    extensionName,
    fullId,
    version: latestVersion,
    riskScore,
    riskLevel,
    issues,
    metadata,
  };
}
