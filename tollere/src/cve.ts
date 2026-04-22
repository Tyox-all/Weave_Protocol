/**
 * CVE checking via OSV.dev (Open Source Vulnerabilities)
 *
 * OSV.dev aggregates vulnerabilities from:
 * - GitHub Advisory Database (GHSA)
 * - PyPA Advisory Database
 * - RustSec Advisory Database
 * - Go Vulnerability Database
 * - npm advisories
 * - And many more
 *
 * Free, no API key required. https://osv.dev/docs/
 */

import type { CVE, Severity, Ecosystem } from "./types.js";

interface OSVQueryRequest {
  package: {
    name: string;
    ecosystem: string;
  };
  version?: string;
}

interface OSVVulnerability {
  id: string;
  summary?: string;
  details?: string;
  severity?: Array<{ type: string; score: string }>;
  database_specific?: {
    severity?: string;
    cwe_ids?: string[];
  };
  affected?: Array<{
    package?: { name: string; ecosystem: string };
    ranges?: Array<{
      type: string;
      events: Array<{ introduced?: string; fixed?: string }>;
    }>;
    versions?: string[];
  }>;
  references?: Array<{ type: string; url: string }>;
  published?: string;
  modified?: string;
  aliases?: string[];
}

interface OSVResponse {
  vulns?: OSVVulnerability[];
}

/**
 * Map ecosystem to OSV.dev format
 */
function ecosystemToOSV(ecosystem: Ecosystem): string {
  const map: Record<Ecosystem, string> = {
    npm: "npm",
    pypi: "PyPI",
    cargo: "crates.io",
    go: "Go",
    maven: "Maven",
  };
  return map[ecosystem];
}

/**
 * Parse CVSS or severity string into our Severity type
 */
function parseSeverity(vuln: OSVVulnerability): { severity: Severity; cvssScore?: number } {
  // Try CVSS first
  const cvssScore = vuln.severity?.find((s) => s.type.startsWith("CVSS"));
  if (cvssScore) {
    const score = parseFloat(cvssScore.score);
    if (!isNaN(score)) {
      let severity: Severity;
      if (score >= 9.0) severity = "critical";
      else if (score >= 7.0) severity = "high";
      else if (score >= 4.0) severity = "medium";
      else if (score > 0) severity = "low";
      else severity = "info";
      return { severity, cvssScore: score };
    }
  }

  // Try database_specific severity
  const dbSev = vuln.database_specific?.severity?.toLowerCase();
  if (dbSev === "critical") return { severity: "critical" };
  if (dbSev === "high") return { severity: "high" };
  if (dbSev === "moderate" || dbSev === "medium") return { severity: "medium" };
  if (dbSev === "low") return { severity: "low" };

  return { severity: "medium" };
}

/**
 * Extract affected/patched version ranges
 */
function extractVersionInfo(vuln: OSVVulnerability): {
  affected: string;
  patched?: string;
} {
  const affectedRanges: string[] = [];
  const patchedVersions: string[] = [];

  for (const aff of vuln.affected || []) {
    for (const range of aff.ranges || []) {
      for (const event of range.events) {
        if (event.introduced) affectedRanges.push(`>=${event.introduced}`);
        if (event.fixed) {
          affectedRanges.push(`<${event.fixed}`);
          patchedVersions.push(`>=${event.fixed}`);
        }
      }
    }
    if (aff.versions && aff.versions.length > 0) {
      affectedRanges.push(...aff.versions);
    }
  }

  return {
    affected: affectedRanges.length > 0 ? affectedRanges.join(", ") : "unknown",
    patched: patchedVersions.length > 0 ? patchedVersions.join(", ") : undefined,
  };
}

/**
 * Query OSV.dev for vulnerabilities affecting a specific package version
 */
export async function queryCVEs(
  packageName: string,
  version: string,
  ecosystem: Ecosystem = "npm",
): Promise<CVE[]> {
  try {
    const body: OSVQueryRequest = {
      package: {
        name: packageName,
        ecosystem: ecosystemToOSV(ecosystem),
      },
      version,
    };

    const res = await fetch("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (!res.ok) return [];

    const data = (await res.json()) as OSVResponse;
    if (!data.vulns) return [];

    return data.vulns.map((vuln) => {
      const { severity, cvssScore } = parseSeverity(vuln);
      const { affected, patched } = extractVersionInfo(vuln);

      return {
        id: vuln.id,
        severity,
        cvssScore,
        summary: vuln.summary || vuln.details?.substring(0, 200) || "No summary available",
        affectedVersions: affected,
        patchedVersions: patched,
        publishedAt: vuln.published,
        references: vuln.references?.map((r) => r.url) || [],
      };
    });
  } catch {
    return [];
  }
}

/**
 * Batch query for multiple packages (efficient for full dependency scans)
 */
export async function queryCVEsBatch(
  packages: Array<{ name: string; version: string; ecosystem?: Ecosystem }>,
): Promise<Map<string, CVE[]>> {
  const results = new Map<string, CVE[]>();

  // OSV.dev batch endpoint
  try {
    const queries = packages.map((p) => ({
      package: {
        name: p.name,
        ecosystem: ecosystemToOSV(p.ecosystem || "npm"),
      },
      version: p.version,
    }));

    const res = await fetch("https://api.osv.dev/v1/querybatch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ queries }),
    });

    if (!res.ok) {
      // Fall back to individual queries
      for (const pkg of packages) {
        const cves = await queryCVEs(pkg.name, pkg.version, pkg.ecosystem || "npm");
        results.set(`${pkg.name}@${pkg.version}`, cves);
      }
      return results;
    }

    const data = (await res.json()) as { results: Array<{ vulns?: Array<{ id: string }> }> };

    // Batch endpoint returns IDs only - need to fetch details for each
    for (let i = 0; i < packages.length; i++) {
      const pkg = packages[i];
      const vulnIds = data.results[i]?.vulns || [];

      if (vulnIds.length === 0) {
        results.set(`${pkg.name}@${pkg.version}`, []);
        continue;
      }

      // For batch results, do a follow-up individual query
      const cves = await queryCVEs(pkg.name, pkg.version, pkg.ecosystem || "npm");
      results.set(`${pkg.name}@${pkg.version}`, cves);
    }

    return results;
  } catch {
    return results;
  }
}
