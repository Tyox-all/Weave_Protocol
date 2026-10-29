/**
 * Core types for @weave_protocol/agentsecbench.
 *
 * AgentSecBench is the interpretation layer on top of Adversary's raw
 * Scorecard. Where Adversary produces "X attacks, Y blocked, Z breached,
 * raw score N", AgentSecBench produces a tier-graded Report with category
 * gap analysis, trophy attack performance, and WARD delta — paste-ready
 * for blog posts, internal docs, vendor comparisons.
 *
 * Report schema: v1.0 is LOCKED. v1.1 (AgentSecBench 0.2) only ADDS
 * optional fields, so any v1.0 consumer reads a v1.1 report unchanged.
 * Future AgentSecBench versions ship new suites (ASB-Browser-v2, etc.)
 * rather than mutating existing ones.
 */

import type { Scorecard, AttackCategory } from '@weave_protocol/adversary';

// ─── Suite manifest ─────────────────────────────────────────

/**
 * A "suite" is a curated, locked subset of the Adversary corpus.
 * Manifest = the locked attack IDs + metadata + tier thresholds.
 */
export interface SuiteManifest {
  /** Suite identifier — e.g. 'ASB-Browser-v1', 'ASB-MCP-v1' */
  id: string;
  /** Suite version number — never changes within an id (v1 is forever v1) */
  version: '1.0';
  /** Human-readable name */
  name: string;
  /** What this suite is for + targeting */
  description: string;
  /** What kind of target the suite is designed against */
  targetType: 'browser' | 'mcp' | 'code-agent' | 'multi-agent' | 'general';
  /** Adversary version this suite was validated against */
  adversaryCompatVersion: string;
  /** The locked list of attack IDs included in this suite */
  attackIds: string[];
  /** The four trophy attacks (named in-the-wild incidents this suite tests for) */
  trophyAttacks: TrophyAttack[];
  /** Tier thresholds (score → grade) */
  tierThresholds: TierThresholds;
  /** Methodology document path (relative to package) */
  methodologyDoc: string;
}

export interface TrophyAttack {
  /** Attack ID in the Adversary corpus */
  attackId: string;
  /** Display name for the trophy ("Atlan autonomous-fraud") */
  name: string;
  /** Year + brief context */
  context: string;
}

export interface TierThresholds {
  A: number;  // >=
  B: number;
  C: number;
  D: number;
  // F = below D
}

// ─── Report (schema v1.0 locked; v1.1 additive) ─────────────

/** Report schema versions this package can read. */
export type ReportSchemaVersion = '1.0' | '1.1';
export const CURRENT_SCHEMA_VERSION: ReportSchemaVersion = '1.1';

export type Tier = 'A' | 'B' | 'C' | 'D' | 'F';

export interface CategoryGap {
  category: AttackCategory;
  breachRate: number;  // 0.0 - 1.0
  partialRate: number;
  /** "severe" | "moderate" | "minor" | "clean" */
  severity: 'severe' | 'moderate' | 'minor' | 'clean';
}

export interface TrophyResult {
  /** Trophy attack ID (matches SuiteManifest.trophyAttacks) */
  attackId: string;
  /** Display name */
  name: string;
  /** Whether the target blocked the trophy attack */
  result: 'pass' | 'partial' | 'fail';
}

export interface Report {
  /** Report schema version. 1.1 = 1.0 + optional fields marked "v1.1". */
  schemaVersion: ReportSchemaVersion;
  /** Suite that was run */
  suite: {
    id: string;
    version: string;
    name: string;
    /**
     * v1.1: SHA-256 of the suite's locked attack set. Two reports with
     * the same hash ran byte-identical suites.
     */
    manifestHash?: string;
  };
  /** Target metadata */
  target: {
    /** Human-readable name. Can be anonymized ("Vendor A", "Production Agent v3") */
    name: string;
    /** Vendor — can be empty/anonymized */
    vendor?: string;
    /** Type of target */
    type: string;
    /** Configuration: WARD policy file, adapter versions, etc. */
    configuration?: Record<string, string>;
    /** Whether the target name has been anonymized */
    anonymized: boolean;
    /** v1.1: model under test, for LLM-backed targets (e.g. "claude-haiku-5-5") */
    model?: string;
  };
  /** Benchmark run metadata */
  run: {
    /** ISO timestamp */
    date: string;
    /** ms */
    durationMs: number;
    adversaryVersion: string;
    agentsecbenchVersion: string;
    /** Number of attacks run (should match suite size) */
    attacksRun: number;
    /**
     * v1.1: Adversary dynamic-mutation metadata (Adversary 0.3+), present
     * only when the run retried half-blocked attacks with LLM variants.
     */
    dynamic?: {
      model: string;
      maxRetries: number;
      variantsGenerated: number;
      mutationCostUSD: number;
    };
  };
  /** The headline result */
  result: {
    /** Adversary raw score, 0-100 */
    score: number;
    /** Tier grade A/B/C/D/F */
    tier: Tier;
    /** Counts */
    blocked: number;
    partial: number;
    breached: number;
    /**
     * v1.1: attacks whose best result came from an LLM-generated variant
     * rather than the original payload (dynamic runs only). A high number
     * means safeguards match wording, not intent.
     */
    variantOnly?: number;
  };
  /** Category-level analysis */
  categoryGaps: CategoryGap[];
  /** Trophy attack performance — did the target catch each documented in-the-wild incident? */
  trophyPerformance: TrophyResult[];
  /** WARD policy adherence — score delta with WARD loaded vs without (if applicable) */
  wardDelta?: {
    /** Score with WARD loaded */
    withWard: number;
    /** Score without WARD (or 'unknown' if not measured) */
    withoutWard: number | 'unknown';
    /** Net contribution of the WARD policy to the score */
    delta: number;
  };
  /** Optional plain-English interpretation paragraph */
  interpretation?: string;
  /** Full underlying Adversary scorecard for auditability */
  scorecard: Scorecard;
}

// ─── Comparison report ──────────────────────────────────────

export interface ComparisonReport {
  schemaVersion: '1.0';
  /** When the comparison was rendered */
  date: string;
  /** Suite — both reports must be from the same suite */
  suite: {
    id: string;
    version: string;
  };
  /** Report A */
  a: {
    name: string;
    score: number;
    tier: Tier;
    breached: number;
  };
  /** Report B */
  b: {
    name: string;
    score: number;
    tier: Tier;
    breached: number;
  };
  /** B - A score delta (positive = B is more secure) */
  scoreDelta: number;
  /** Per-category deltas */
  categoryDeltas: Array<{
    category: AttackCategory;
    aBreachRate: number;
    bBreachRate: number;
    delta: number;  // a - b (positive = b improved)
  }>;
  /** Per-trophy comparison */
  trophyDeltas: Array<{
    attackId: string;
    name: string;
    aResult: TrophyResult['result'];
    bResult: TrophyResult['result'];
    /** 'improved' | 'regressed' | 'unchanged' */
    direction: 'improved' | 'regressed' | 'unchanged';
  }>;
  /** Per-attack regressions: attacks that A passed but B failed */
  regressions: Array<{
    attackId: string;
    severity: string;
    aResult: string;
    bResult: string;
  }>;
  /** Per-attack improvements: attacks that A failed but B passed */
  improvements: Array<{
    attackId: string;
    severity: string;
    aResult: string;
    bResult: string;
  }>;
}
