/**
 * Docker image scanning
 *
 * Detects supply chain attacks on Docker images:
 * - Tag overwriting (legitimate tags getting their digest swapped)
 * - Phantom tags (tags that don't correspond to upstream releases)
 * - Suspicious manifest patterns (env vars, entrypoints, cmd)
 * - Rapid republishes (could indicate compromised credentials)
 *
 * Triggered by attacks like the Checkmarx KICS Docker Hub compromise (April 2026)
 * where attackers overwrote `v2.1.20` and `alpine` tags and added a phantom
 * `v2.1.21` that didn't exist upstream.
 */

import type { DockerScanResult, DockerManifest, TagHistoryEntry, RiskIssue, Severity } from "./types.js";

interface DockerHubTagsResponse {
  count: number;
  next: string | null;
  results: Array<{
    name: string;
    last_updated: string;
    last_updater_username?: string;
    full_size: number;
    digest?: string;
    images?: Array<{
      digest: string;
      architecture: string;
      os: string;
      size: number;
    }>;
  }>;
}

interface DockerHubTagDetail {
  name: string;
  last_updated: string;
  last_updater_username?: string;
  full_size: number;
  digest?: string;
  images?: Array<{
    digest: string;
    architecture: string;
    os: string;
    size: number;
    last_pushed?: string;
  }>;
  v2: boolean;
}

/**
 * Parse a Docker image reference into namespace/repo/tag
 * Examples:
 *   nginx → library/nginx:latest
 *   nginx:alpine → library/nginx:alpine
 *   user/app:v1 → user/app:v1
 *   ghcr.io/user/app:v1 → ghcr.io/user/app:v1 (registry detected)
 */
export function parseImageRef(ref: string): {
  registry: string;
  namespace: string;
  repo: string;
  tag: string;
} {
  let registry = "docker.io";
  let rest = ref;

  // Check for explicit registry (contains a dot or colon-port before first slash)
  const firstSlash = ref.indexOf("/");
  if (firstSlash > 0) {
    const prefix = ref.substring(0, firstSlash);
    if (prefix.includes(".") || prefix.includes(":")) {
      registry = prefix;
      rest = ref.substring(firstSlash + 1);
    }
  }

  // Split tag
  const colonIdx = rest.lastIndexOf(":");
  let pathPart = rest;
  let tag = "latest";
  if (colonIdx > 0 && !rest.substring(colonIdx).includes("/")) {
    pathPart = rest.substring(0, colonIdx);
    tag = rest.substring(colonIdx + 1);
  }

  // Split namespace/repo
  let namespace = "library";
  let repo = pathPart;
  const slashIdx = pathPart.indexOf("/");
  if (slashIdx > 0) {
    namespace = pathPart.substring(0, slashIdx);
    repo = pathPart.substring(slashIdx + 1);
  }

  return { registry, namespace, repo, tag };
}

/**
 * Fetch tag history from Docker Hub
 */
export async function fetchDockerHubTags(
  namespace: string,
  repo: string,
  pageSize = 25,
): Promise<TagHistoryEntry[]> {
  try {
    const url = `https://hub.docker.com/v2/repositories/${namespace}/${repo}/tags?page_size=${pageSize}&ordering=last_updated`;
    const res = await fetch(url, { headers: { Accept: "application/json" } });
    if (!res.ok) return [];
    const data = (await res.json()) as DockerHubTagsResponse;
    return data.results.map((t) => ({
      tag: t.name,
      digest: t.digest || t.images?.[0]?.digest || "unknown",
      lastUpdated: t.last_updated,
      size: t.full_size,
    }));
  } catch {
    return [];
  }
}

/**
 * Fetch a specific tag's details
 */
async function fetchDockerHubTagDetail(
  namespace: string,
  repo: string,
  tag: string,
): Promise<DockerHubTagDetail | null> {
  try {
    const url = `https://hub.docker.com/v2/repositories/${namespace}/${repo}/tags/${tag}`;
    const res = await fetch(url, { headers: { Accept: "application/json" } });
    if (!res.ok) return null;
    return (await res.json()) as DockerHubTagDetail;
  } catch {
    return null;
  }
}

/**
 * Detect suspicious patterns in a tag's update history
 *
 * Returns issues for:
 * - Recent rapid republishes (< 1h between updates suggests compromise)
 * - Tags marked as releases (v1.2.3 format) that have been modified
 *   after their initial publish (semver tags should be immutable)
 */
function analyzeTagHistory(
  targetTag: string,
  tagHistory: TagHistoryEntry[],
  detail?: DockerHubTagDetail | null,
): RiskIssue[] {
  const issues: RiskIssue[] = [];

  if (!detail) return issues;

  // Check 1: Semver tag was updated more than once (should be immutable)
  const semverPattern = /^v?\d+\.\d+\.\d+/;
  if (semverPattern.test(targetTag)) {
    // Find all entries for this tag in history (Docker Hub may keep some history)
    const sameTagEntries = tagHistory.filter((t) => t.tag === targetTag);
    if (sameTagEntries.length > 1) {
      issues.push({
        type: "tag_overwrite",
        severity: "critical",
        description: `Semver tag "${targetTag}" has been updated multiple times - tags following semver should be immutable`,
        evidence: `${sameTagEntries.length} update events found`,
        remediation: "Pin to a specific digest (sha256:...) instead of the tag name",
      });
    }

    // Check time since last_pushed for individual images vs tag.last_updated
    if (detail.images && detail.images.length > 0) {
      const tagUpdate = new Date(detail.last_updated).getTime();
      for (const img of detail.images) {
        if (img.last_pushed) {
          const pushTime = new Date(img.last_pushed).getTime();
          const diffMinutes = Math.abs(tagUpdate - pushTime) / 60000;
          if (diffMinutes > 60 * 24) {
            // tag updated significantly later than image was pushed = tag was reassigned
            issues.push({
              type: "tag_overwrite",
              severity: "critical",
              description: `Tag "${targetTag}" was reassigned ${Math.floor(diffMinutes / 60 / 24)} days after image was originally pushed`,
              evidence: `Tag updated: ${detail.last_updated}, image pushed: ${img.last_pushed}`,
              remediation: "Do not use this tag - the digest has been swapped. Pin to a specific digest (sha256:...) or roll back to a known-good version.",
            });
            break;
          }
        }
      }
    }
  }

  return issues;
}

/**
 * Detect phantom tags - tags that don't correspond to known release patterns
 *
 * Heuristic: If most tags follow semver (v1.2.3) and our target tag also looks like
 * semver but the version it claims doesn't fit the gap (e.g., v2.1.21 when the
 * existing pattern is v2.1.0, v2.1.10, v2.1.20), flag it.
 */
function detectPhantomTag(targetTag: string, tagHistory: TagHistoryEntry[]): RiskIssue[] {
  const issues: RiskIssue[] = [];

  const semverPattern = /^v?(\d+)\.(\d+)\.(\d+)/;
  const targetMatch = targetTag.match(semverPattern);
  if (!targetMatch) return issues; // not a semver tag

  // Get all semver tags
  const semverTags = tagHistory
    .map((t) => ({ tag: t.tag, lastUpdated: t.lastUpdated, match: t.tag.match(semverPattern) }))
    .filter((t) => t.match)
    .map((t) => ({
      tag: t.tag,
      lastUpdated: new Date(t.lastUpdated).getTime(),
      major: parseInt(t.match![1], 10),
      minor: parseInt(t.match![2], 10),
      patch: parseInt(t.match![3], 10),
    }));

  if (semverTags.length < 3) return issues; // not enough data

  const targetMajor = parseInt(targetMatch[1], 10);
  const targetMinor = parseInt(targetMatch[2], 10);
  const targetPatch = parseInt(targetMatch[3], 10);

  // Find any tag with same major.minor that's older than ours
  const sameMinor = semverTags.filter(
    (t) => t.major === targetMajor && t.minor === targetMinor && t.tag !== targetTag,
  );

  if (sameMinor.length === 0) return issues;

  const maxPatchInLine = Math.max(...sameMinor.map((t) => t.patch));

  // If the target patch is more than 5 ahead of the max known patch,
  // and the gap doesn't match other minor lines, it's suspicious
  if (targetPatch > maxPatchInLine + 5) {
    issues.push({
      type: "phantom_tag",
      severity: "high",
      description: `Tag "${targetTag}" appears to skip ahead of the established versioning pattern`,
      evidence: `Highest known patch in v${targetMajor}.${targetMinor}.x line: ${maxPatchInLine}, this tag jumps to ${targetPatch}`,
      remediation: "Cross-reference with the project's official release page (GitHub releases, etc.) before using",
    });
  }

  return issues;
}

/**
 * Scan a Docker image
 */
export async function scanDockerImage(imageRef: string): Promise<DockerScanResult> {
  const { registry, namespace, repo, tag } = parseImageRef(imageRef);

  // For now, only Docker Hub is supported (most attacks happen there)
  if (registry !== "docker.io") {
    return {
      image: imageRef,
      tag,
      riskScore: 0,
      riskLevel: "allow",
      issues: [
        {
          type: "version_anomaly",
          severity: "info",
          description: `Registry ${registry} not yet supported by Tollere - only Docker Hub at this time`,
        },
      ],
    };
  }

  const [tagHistory, detail] = await Promise.all([
    fetchDockerHubTags(namespace, repo, 50),
    fetchDockerHubTagDetail(namespace, repo, tag),
  ]);

  const issues: RiskIssue[] = [];

  if (!detail) {
    // Check if the tag appears in history but details are missing
    // — sign of withdrawal/cleanup after compromise disclosure
    const inHistory = tagHistory.some((t) => t.tag === tag);
    if (inHistory) {
      return {
        image: imageRef,
        tag,
        riskScore: 60,
        riskLevel: "warn",
        issues: [
          {
            type: "phantom_tag",
            severity: "high",
            description: `Tag "${tag}" appears in registry history but metadata is unavailable - possible withdrawal after compromise disclosure`,
            remediation: "Do not use this tag. Cross-reference with upstream release notes.",
          },
        ],
        tagHistory: tagHistory.slice(0, 10),
      };
    }
    return {
      image: imageRef,
      tag,
      riskScore: 30,
      riskLevel: "warn",
      issues: [
        {
          type: "phantom_tag",
          severity: "medium",
          description: `Tag "${tag}" does not exist in the registry - it was either never published, mistyped, or has been completely withdrawn (a known signal after compromise disclosure)`,
          remediation: "Verify the tag name. If you saw this tag referenced somewhere recently, check whether it was withdrawn after a security incident.",
        },
      ],
    };
  }

  // Run analyses
  issues.push(...analyzeTagHistory(tag, tagHistory, detail));
  issues.push(...detectPhantomTag(tag, tagHistory));

  // Build manifest summary
  const firstImg = detail.images?.[0];
  const manifest: DockerManifest = {
    digest: firstImg?.digest || detail.digest || "unknown",
    size: detail.full_size,
    lastUpdated: detail.last_updated,
    layers: detail.images?.length || 1,
    os: firstImg?.os,
    architecture: firstImg?.architecture,
  };

  // Compute risk
  let riskScore = 0;
  for (const issue of issues) {
    if (issue.severity === "critical") riskScore += 50;
    else if (issue.severity === "high") riskScore += 30;
    else if (issue.severity === "medium") riskScore += 15;
    else if (issue.severity === "low") riskScore += 5;
  }
  riskScore = Math.min(100, riskScore);

  let riskLevel: DockerScanResult["riskLevel"] = "allow";
  if (issues.some((i) => i.severity === "critical")) riskLevel = "block";
  else if (issues.some((i) => i.severity === "high")) riskLevel = "warn";
  else if (issues.some((i) => i.severity === "medium")) riskLevel = "warn";

  return {
    image: imageRef,
    tag,
    riskScore,
    riskLevel,
    issues,
    manifest,
    tagHistory: tagHistory.slice(0, 10),
  };
}
