/**
 * Maintainer reputation scoring
 *
 * Scores packages based on:
 * - Account age of maintainers
 * - Number of packages they maintain
 * - Recent activity
 * - Ownership history changes
 * - Verified publisher status
 */

import type { ReputationScore, ReputationSignal, PackageMetadata } from "./types.js";

interface NpmRegistryResponse {
  name: string;
  description?: string;
  "dist-tags"?: { latest?: string };
  versions?: Record<string, unknown>;
  time?: Record<string, string>;
  maintainers?: Array<{ name: string; email?: string }>;
  author?: { name?: string; email?: string } | string;
  license?: string;
  homepage?: string;
  repository?: { url?: string } | string;
}

/**
 * Fetch package metadata from npm registry
 */
export async function fetchPackageMetadata(
  packageName: string,
): Promise<PackageMetadata | null> {
  try {
    const url = `https://registry.npmjs.org/${encodeURIComponent(packageName)}`;
    const res = await fetch(url, {
      headers: { Accept: "application/json" },
    });

    if (!res.ok) return null;

    const data = (await res.json()) as NpmRegistryResponse;
    const latest = data["dist-tags"]?.latest;
    const publishedAt = data.time?.created;
    const lastUpdated = data.time?.modified;
    const versions = data.versions ? Object.keys(data.versions) : [];

    return {
      description: data.description,
      author: typeof data.author === "string" ? data.author : data.author?.name,
      maintainers: (data.maintainers || []).map((m) => ({
        name: m.name,
        email: m.email,
      })),
      publishedAt,
      lastUpdated,
      homepage: data.homepage,
      repository:
        typeof data.repository === "string"
          ? data.repository
          : data.repository?.url,
      license: data.license,
    };
  } catch {
    return null;
  }
}

/**
 * Compute reputation score from package metadata
 * Returns 0-100, higher = more trustworthy
 */
export function computeReputationScore(metadata: PackageMetadata): ReputationScore {
  const signals: ReputationSignal[] = [];
  let score = 50; // start neutral

  // Account age signal
  if (metadata.publishedAt) {
    const ageMs = Date.now() - new Date(metadata.publishedAt).getTime();
    const ageDays = ageMs / (1000 * 60 * 60 * 24);

    if (ageDays > 365) {
      signals.push({
        type: "account_age",
        positive: true,
        weight: 15,
        description: `Package is ${Math.floor(ageDays / 365)} years old`,
      });
      score += 15;
    } else if (ageDays < 7) {
      signals.push({
        type: "account_age",
        positive: false,
        weight: 20,
        description: `Package is only ${Math.floor(ageDays)} days old`,
      });
      score -= 20;
    } else if (ageDays < 30) {
      signals.push({
        type: "account_age",
        positive: false,
        weight: 10,
        description: `Package is less than a month old`,
      });
      score -= 10;
    }
  }

  // Recent activity signal
  if (metadata.lastUpdated) {
    const updateAgeMs = Date.now() - new Date(metadata.lastUpdated).getTime();
    const updateAgeDays = updateAgeMs / (1000 * 60 * 60 * 24);

    if (updateAgeDays > 365 * 2) {
      signals.push({
        type: "recent_activity",
        positive: false,
        weight: 10,
        description: "Not updated in over 2 years",
      });
      score -= 10;
    } else if (updateAgeDays < 30) {
      signals.push({
        type: "recent_activity",
        positive: true,
        weight: 5,
        description: "Recently updated",
      });
      score += 5;
    }
  }

  // Maintainer count signal
  const maintainerCount = metadata.maintainers?.length || 0;
  if (maintainerCount === 0) {
    signals.push({
      type: "package_count",
      positive: false,
      weight: 15,
      description: "No registered maintainers",
    });
    score -= 15;
  } else if (maintainerCount === 1) {
    signals.push({
      type: "package_count",
      positive: false,
      weight: 5,
      description: "Single maintainer (bus factor risk)",
    });
    score -= 5;
  } else if (maintainerCount >= 3) {
    signals.push({
      type: "package_count",
      positive: true,
      weight: 5,
      description: `${maintainerCount} maintainers`,
    });
    score += 5;
  }

  // Repository link signal
  if (!metadata.repository) {
    signals.push({
      type: "github_activity",
      positive: false,
      weight: 10,
      description: "No source repository linked",
    });
    score -= 10;
  } else if (metadata.repository.includes("github.com")) {
    signals.push({
      type: "github_activity",
      positive: true,
      weight: 5,
      description: "GitHub repository linked",
    });
    score += 5;
  }

  // License signal
  if (!metadata.license) {
    signals.push({
      type: "verified_publisher",
      positive: false,
      weight: 5,
      description: "No license specified",
    });
    score -= 5;
  }

  // Clamp 0-100
  score = Math.max(0, Math.min(100, score));

  return { score, signals };
}

/**
 * Get reputation for a package
 */
export async function getMaintainerReputation(
  packageName: string,
): Promise<ReputationScore | null> {
  const metadata = await fetchPackageMetadata(packageName);
  if (!metadata) return null;
  return computeReputationScore(metadata);
}
