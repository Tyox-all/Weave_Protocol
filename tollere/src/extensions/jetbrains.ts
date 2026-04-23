/**
 * JetBrains Marketplace scanner
 *
 * Covers: IntelliJ IDEA, PyCharm, WebStorm, GoLand, RubyMine, PhpStorm,
 * CLion, DataGrip, Rider, AppCode, and any other JetBrains IDE.
 *
 * API: https://plugins.jetbrains.com/api
 *
 * Plugin URLs follow: https://plugins.jetbrains.com/plugin/{id}-{slug}
 */

import type { ExtensionScanResult, ExtensionMetadata, RiskIssue } from "../types.js";

interface JetBrainsSearchResult {
  id: number;
  name: string;
  preview?: string;
  link: string;
  pricingModel?: string;
  organization?: string;
  rating?: number;
  downloads?: number;
  vendor?: { name: string; isVerified?: boolean };
  cdate?: number; // creation date (unix ms)
}

interface JetBrainsPluginDetail {
  id: number;
  name: string;
  description?: string;
  vendor?: {
    name: string;
    isVerified?: boolean;
    link?: string;
    email?: string;
    type?: string;
  };
  link?: string;
  urls?: { url?: string; sourceCodeUrl?: string; bugtrackerUrl?: string };
  rating?: number;
  downloads?: number;
  cdate?: number;
  date?: number;
  approve?: boolean;
  organization?: string;
  family?: string;
  copyright?: string;
}

async function searchPlugin(query: string): Promise<JetBrainsSearchResult[]> {
  try {
    const url = `https://plugins.jetbrains.com/api/searchPlugins?max=10&search=${encodeURIComponent(query)}`;
    const res = await fetch(url, { headers: { Accept: "application/json" } });
    if (!res.ok) return [];
    const data = (await res.json()) as { plugins?: JetBrainsSearchResult[] };
    return data.plugins || [];
  } catch {
    return [];
  }
}

async function fetchPluginDetail(id: number): Promise<JetBrainsPluginDetail | null> {
  try {
    const url = `https://plugins.jetbrains.com/api/plugins/${id}`;
    const res = await fetch(url, { headers: { Accept: "application/json" } });
    if (!res.ok) return null;
    return (await res.json()) as JetBrainsPluginDetail;
  } catch {
    return null;
  }
}

/**
 * Scan a JetBrains Marketplace plugin
 *
 * Accepts either:
 *   - Plugin ID (number): "12345"
 *   - Plugin name (string): "Python", "Rust"
 */
export async function scanJetBrainsExtension(query: string): Promise<ExtensionScanResult> {
  const issues: RiskIssue[] = [];

  let pluginId: number | null = null;
  if (/^\d+$/.test(query)) {
    pluginId = parseInt(query, 10);
  } else {
    const results = await searchPlugin(query);
    if (results.length > 0) {
      pluginId = results[0].id;
    }
  }

  if (!pluginId) {
    return {
      ecosystem: "jetbrains",
      publisherId: "",
      extensionName: query,
      fullId: query,
      version: "unknown",
      riskScore: 0,
      riskLevel: "allow",
      issues: [
        {
          type: "version_anomaly",
          severity: "low",
          description: `Plugin "${query}" not found on JetBrains Marketplace`,
        },
      ],
      metadata: {},
    };
  }

  const detail = await fetchPluginDetail(pluginId);
  if (!detail) {
    return {
      ecosystem: "jetbrains",
      publisherId: "",
      extensionName: query,
      fullId: String(pluginId),
      version: "unknown",
      riskScore: 0,
      riskLevel: "allow",
      issues: [
        {
          type: "version_anomaly",
          severity: "medium",
          description: `Could not fetch plugin details for ID ${pluginId}`,
        },
      ],
      metadata: {},
    };
  }

  // Check 1: Unverified vendor
  if (detail.vendor?.isVerified === false) {
    issues.push({
      type: "unverified_publisher",
      severity: "medium",
      description: `Vendor "${detail.vendor.name}" is not verified by JetBrains`,
      remediation: "Verify vendor legitimacy via their website",
    });
  }

  // Check 2: Brand new plugin
  // Only flag if low-download AND not verified (JetBrains' cdate field
  // doesn't reliably mean creation date for popular plugins)
  if (detail.cdate && (detail.downloads || 0) < 5000 && !detail.vendor?.isVerified) {
    const ageDays = (Date.now() - detail.cdate) / (1000 * 60 * 60 * 24);
    if (ageDays < 14) {
      issues.push({
        type: "version_anomaly",
        severity: "medium",
        description: `Plugin was created only ${Math.floor(ageDays)} days ago and has low downloads`,
      });
    }
  }

  // Check 3: Not approved
  if (detail.approve === false) {
    issues.push({
      type: "version_anomaly",
      severity: "high",
      description: "Plugin is not yet approved for the JetBrains Marketplace",
      remediation: "Wait for official approval before installing",
    });
  }

  // Check 4: No source code URL (only flag if also unverified)
  if (!detail.urls?.sourceCodeUrl && !detail.vendor?.isVerified) {
    issues.push({
      type: "low_reputation",
      severity: "low",
      description: "Plugin has no public source code URL and vendor is not verified",
    });
  }

  // Check 5: Very low downloads
  if ((detail.downloads || 0) < 100) {
    issues.push({
      type: "low_reputation",
      severity: "low",
      description: `Plugin has very few downloads (${detail.downloads || 0})`,
    });
  }

  const metadata: ExtensionMetadata = {
    displayName: detail.name,
    description: detail.description?.replace(/<[^>]*>/g, "").substring(0, 200),
    publisher: detail.vendor?.name,
    publisherVerified: detail.vendor?.isVerified,
    downloads: detail.downloads,
    rating: detail.rating,
    publishedAt: detail.cdate ? new Date(detail.cdate).toISOString() : undefined,
    lastUpdated: detail.date ? new Date(detail.date).toISOString() : undefined,
    repository: detail.urls?.sourceCodeUrl,
    homepage: detail.vendor?.link,
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
  else if (issues.some((i) => i.severity === "high")) riskLevel = "warn";
  else if (issues.some((i) => i.severity === "medium")) riskLevel = "warn";

  return {
    ecosystem: "jetbrains",
    publisherId: detail.vendor?.name || "",
    extensionName: detail.name,
    fullId: String(detail.id),
    version: "latest",
    riskScore,
    riskLevel,
    issues,
    metadata,
  };
}
