/**
 * Open VSX Registry scanner
 *
 * Covers: VSCodium, Gitpod, Theia, and other open-source IDE forks
 * that use the Open VSX registry instead of the proprietary VS Code Marketplace.
 *
 * API: https://open-vsx.org/api/{namespace}/{extension}
 *
 * Open VSX has historically had less rigorous publisher verification than
 * the official Marketplace, making it a higher-risk distribution channel.
 */

import type { ExtensionScanResult, ExtensionMetadata, RiskIssue } from "../types.js";

interface OpenVSXResponse {
  namespace: string;
  name: string;
  version?: string;
  versions?: Record<string, string>;
  publishedBy?: {
    loginName: string;
    fullName?: string;
    avatarUrl?: string;
    homepage?: string;
    provider?: string;
  };
  verified?: boolean;
  unrelatedPublisher?: boolean;
  namespaceAccess?: string;
  displayName?: string;
  description?: string;
  categories?: string[];
  tags?: string[];
  license?: string;
  homepage?: string;
  repository?: string;
  bugs?: string;
  timestamp?: string;
  averageRating?: number;
  reviewCount?: number;
  downloadCount?: number;
}

async function fetchExtension(
  namespace: string,
  name: string,
): Promise<OpenVSXResponse | null> {
  try {
    const url = `https://open-vsx.org/api/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}`;
    const res = await fetch(url, { headers: { Accept: "application/json" } });
    if (!res.ok) return null;
    return (await res.json()) as OpenVSXResponse;
  } catch {
    return null;
  }
}

/**
 * Scan an Open VSX extension by full ID (namespace.name)
 */
export async function scanOpenVSXExtension(fullId: string): Promise<ExtensionScanResult> {
  const issues: RiskIssue[] = [];
  const dotIdx = fullId.indexOf(".");
  if (dotIdx === -1) {
    return {
      ecosystem: "openvsx",
      publisherId: "",
      extensionName: fullId,
      fullId,
      version: "unknown",
      riskScore: 50,
      riskLevel: "warn",
      issues: [
        {
          type: "version_anomaly",
          severity: "medium",
          description: `Invalid extension ID format - expected "namespace.name"`,
        },
      ],
      metadata: {},
    };
  }

  const namespace = fullId.substring(0, dotIdx);
  const name = fullId.substring(dotIdx + 1);

  const ext = await fetchExtension(namespace, name);

  if (!ext) {
    return {
      ecosystem: "openvsx",
      publisherId: namespace,
      extensionName: name,
      fullId,
      version: "unknown",
      riskScore: 0,
      riskLevel: "allow",
      issues: [
        {
          type: "version_anomaly",
          severity: "low",
          description: `Extension "${fullId}" not found on Open VSX`,
        },
      ],
      metadata: {},
    };
  }

  // Check 1: Unverified namespace
  if (ext.verified === false) {
    issues.push({
      type: "unverified_publisher",
      severity: "medium",
      description: `Namespace "${namespace}" is not verified on Open VSX`,
      remediation: "Verify publisher legitimacy via their official repository",
    });
  }

  // Check 2: Unrelated publisher (someone else uploaded an extension to a namespace)
  if (ext.unrelatedPublisher) {
    issues.push({
      type: "publisher_takeover",
      severity: "high",
      description: `Extension was published by an account unrelated to the namespace`,
      remediation: "This is a strong indicator of impersonation - do not install",
    });
  }

  // Check 3: Brand new
  if (ext.timestamp) {
    const ageDays = (Date.now() - new Date(ext.timestamp).getTime()) / (1000 * 60 * 60 * 24);
    if (ageDays < 7) {
      issues.push({
        type: "version_anomaly",
        severity: "medium",
        description: `Extension version published only ${Math.floor(ageDays)} days ago`,
      });
    }
  }

  // Check 4: No repository link
  if (!ext.repository) {
    issues.push({
      type: "low_reputation",
      severity: "medium",
      description: "Extension has no source repository linked",
      remediation: "Without a repository, the source code cannot be audited",
    });
  }

  const metadata: ExtensionMetadata = {
    displayName: ext.displayName,
    description: ext.description,
    publisher: ext.publishedBy?.fullName || ext.publishedBy?.loginName,
    publisherVerified: ext.verified,
    downloads: ext.downloadCount,
    rating: ext.averageRating,
    ratingCount: ext.reviewCount,
    publishedAt: ext.timestamp,
    lastUpdated: ext.timestamp,
    repository: ext.repository,
    homepage: ext.homepage,
    category: ext.categories,
  };

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
  else if (issues.some((i) => i.severity === "high")) riskLevel = "block";
  else if (issues.some((i) => i.severity === "medium")) riskLevel = "warn";

  return {
    ecosystem: "openvsx",
    publisherId: namespace,
    extensionName: name,
    fullId,
    version: ext.version || "unknown",
    riskScore,
    riskLevel,
    issues,
    metadata,
  };
}
