/**
 * Sandwich pattern detection
 *
 * Detects malicious code that appears in version N, is removed in N+1
 * (the "sandwich filling" / clean version), and reappears in N+2 or later.
 *
 * This pattern is used to evade simple "check the latest version" defenses
 * and was seen in the Checkmarx KICS VS Code extension compromise (April 2026):
 *   - 1.17.0: malicious
 *   - 1.18.0: clean (sandwich filling)
 *   - 1.19.0: malicious returns
 */

import type { SandwichResult, SandwichPattern } from "./types.js";

interface NpmFullData {
  name: string;
  versions?: Record<string, NpmVersionData>;
  time?: Record<string, string>;
  "dist-tags"?: { latest?: string };
}

interface NpmVersionData {
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  bin?: Record<string, string> | string;
}

/**
 * Patterns we look for that, when introduced/removed/reintroduced,
 * indicate a sandwich attack.
 */
interface PatternProbe {
  type: string;
  test: (data: NpmVersionData) => string | null; // returns evidence string or null
}

const PROBES: PatternProbe[] = [
  {
    type: "install_script",
    test: (d) => {
      const scripts = d.scripts || {};
      const installScripts = ["preinstall", "install", "postinstall"]
        .map((k) => scripts[k])
        .filter(Boolean);
      return installScripts.length > 0 ? installScripts.join(" | ") : null;
    },
  },
  {
    type: "remote_url_in_script",
    test: (d) => {
      const scripts = d.scripts || {};
      for (const [name, val] of Object.entries(scripts)) {
        if (/(https?:\/\/[^\s"']+)/.test(val) && /(curl|wget|fetch|node\s+-e)/.test(val)) {
          return `${name}: ${val.substring(0, 120)}`;
        }
      }
      return null;
    },
  },
  {
    type: "eval_or_exec",
    test: (d) => {
      const scripts = d.scripts || {};
      for (const [name, val] of Object.entries(scripts)) {
        if (/(eval\s*\(|node\s+-e|python\s+-c|sh\s+-c)/.test(val)) {
          return `${name}: ${val.substring(0, 120)}`;
        }
      }
      return null;
    },
  },
  {
    type: "base64_blob",
    test: (d) => {
      const scripts = d.scripts || {};
      for (const [name, val] of Object.entries(scripts)) {
        if (/[A-Za-z0-9+/]{100,}={0,2}/.test(val)) {
          return `${name}: long base64 blob detected`;
        }
      }
      return null;
    },
  },
  {
    type: "suspicious_dependency",
    test: (d) => {
      const allDeps = { ...(d.dependencies || {}), ...(d.devDependencies || {}) };
      // Common red-flag dependency names used in supply chain attacks
      const suspicious = [
        "plain-crypto-js",     // used in Axios attack
        "node-ipc",            // RIAEvangelist incident
        "event-source-polyfill-extra",
      ];
      for (const dep of Object.keys(allDeps)) {
        if (suspicious.includes(dep)) {
          return `Suspicious dependency: ${dep}`;
        }
      }
      return null;
    },
  },
];

/**
 * Sort versions semver-like (newest last). Best-effort.
 */
function sortVersions(versions: string[]): string[] {
  return [...versions].sort((a, b) => {
    const pa = a.split(/[.\-+]/).map((x) => parseInt(x, 10));
    const pb = b.split(/[.\-+]/).map((x) => parseInt(x, 10));
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const av = pa[i] || 0;
      const bv = pb[i] || 0;
      if (isNaN(av) || isNaN(bv)) return a.localeCompare(b);
      if (av !== bv) return av - bv;
    }
    return 0;
  });
}

async function fetchNpmData(packageName: string): Promise<NpmFullData | null> {
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
 * Detect sandwich patterns across the last N versions of a package.
 *
 * Algorithm:
 *   1. Fetch all versions
 *   2. For each probe type, build a presence array (true/false per version)
 *   3. A sandwich = pattern present at index i, absent at i+k (k>=1), present at i+k+m (m>=1)
 *   4. Return strongest sandwich found (most recent reappearance)
 */
export async function detectSandwichPattern(
  packageName: string,
  opts: { lastN?: number } = {},
): Promise<SandwichResult> {
  const lastN = opts.lastN ?? 15;
  const data = await fetchNpmData(packageName);

  if (!data || !data.versions) {
    return {
      packageName,
      versionsAnalyzed: 0,
      patternDetected: false,
      riskScore: 0,
    };
  }

  const allVersions = sortVersions(Object.keys(data.versions));
  const recent = allVersions.slice(-lastN);

  let strongestPattern: SandwichPattern | undefined;
  let strongestScore = 0;

  for (const probe of PROBES) {
    // Build presence map: version → evidence string (or null)
    const presence: Array<{ version: string; evidence: string | null }> = recent.map(
      (v) => ({
        version: v,
        evidence: probe.test(data.versions![v]),
      }),
    );

    // Find sandwich: present (i) → absent (j > i) → present (k > j)
    for (let i = 0; i < presence.length - 2; i++) {
      if (!presence[i].evidence) continue;

      // Find first absence after i
      let j = -1;
      for (let x = i + 1; x < presence.length; x++) {
        if (!presence[x].evidence) {
          j = x;
          break;
        }
      }
      if (j === -1) continue;

      // Find first reappearance after j
      let k = -1;
      for (let x = j + 1; x < presence.length; x++) {
        if (presence[x].evidence) {
          k = x;
          break;
        }
      }
      if (k === -1) continue;

      // Score: more severe patterns get higher scores
      const baseScores: Record<string, number> = {
        install_script: 60,
        remote_url_in_script: 90,
        eval_or_exec: 85,
        base64_blob: 75,
        suspicious_dependency: 95,
      };
      const score = baseScores[probe.type] ?? 50;

      if (score > strongestScore) {
        strongestScore = score;
        strongestPattern = {
          introducedIn: presence[i].version,
          removedIn: presence[j].version,
          reappearedIn: presence[k].version,
          patternType: probe.type,
          evidence: `${presence[i].evidence} → (removed in ${presence[j].version}) → ${presence[k].evidence}`,
        };
      }
    }
  }

  return {
    packageName,
    versionsAnalyzed: recent.length,
    patternDetected: !!strongestPattern,
    pattern: strongestPattern,
    riskScore: strongestScore,
  };
}
