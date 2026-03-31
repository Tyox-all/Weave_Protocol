/**
 * Threat Intelligence Types
 * @weave_protocol/mund
 */

// ============================================================================
// Intel Source Types
// ============================================================================

export type IntelSourceType = 
  | 'mitre_attack'
  | 'community_blocklist'
  | 'custom'
  | 'weave_official';

export type IntelCategory =
  | 'prompt_injection'
  | 'jailbreak'
  | 'data_exfiltration'
  | 'privilege_escalation'
  | 'social_engineering'
  | 'malicious_code'
  | 'pii_extraction'
  | 'system_prompt_leak'
  | 'dos_attack'
  | 'mcp_exploit';

export type PatternType =
  | 'regex'
  | 'keyword'
  | 'semantic'
  | 'behavioral';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

// ============================================================================
// Intel Source Configuration
// ============================================================================

export interface IntelSource {
  id: string;
  name: string;
  type: IntelSourceType;
  url?: string;
  description: string;
  enabled: boolean;
  autoUpdate: boolean;
  updateIntervalHours: number;
  lastUpdated?: Date;
  lastError?: string;
  patternCount: number;
  version: string;
  categories: IntelCategory[];
}

export interface IntelSourceConfig {
  id: string;
  name: string;
  type: IntelSourceType;
  url?: string;
  description: string;
  enabled?: boolean;
  autoUpdate?: boolean;
  updateIntervalHours?: number;
  apiKey?: string;
  categories?: IntelCategory[];
}

// ============================================================================
// Threat Patterns
// ============================================================================

export interface ThreatPattern {
  id: string;
  sourceId: string;
  category: IntelCategory;
  name: string;
  description: string;
  patternType: PatternType;
  pattern: string;                    // Regex string, keyword, or semantic descriptor
  severity: Severity;
  confidence: number;                 // 0-1
  mitreId?: string;                   // e.g., "T1059.001"
  mitreTactic?: string;               // e.g., "Execution"
  mitreTechnique?: string;            // e.g., "Command and Scripting Interpreter"
  tags: string[];
  examples?: string[];
  falsePositiveRate?: number;         // 0-1
  enabled: boolean;
  version: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface PatternMatch {
  patternId: string;
  patternName: string;
  category: IntelCategory;
  severity: Severity;
  confidence: number;
  matchedText: string;
  position: { start: number; end: number };
  mitreId?: string;
  mitreTactic?: string;
  recommendation: string;
}

// ============================================================================
// Update Results
// ============================================================================

export interface IntelUpdateResult {
  sourceId: string;
  sourceName: string;
  success: boolean;
  previousVersion: string;
  newVersion: string;
  patternsAdded: number;
  patternsUpdated: number;
  patternsRemoved: number;
  totalPatterns: number;
  timestamp: Date;
  error?: string;
  duration_ms: number;
}

export interface BulkUpdateResult {
  totalSources: number;
  successfulUpdates: number;
  failedUpdates: number;
  totalPatternsAdded: number;
  totalPatternsUpdated: number;
  totalPatternsRemoved: number;
  results: IntelUpdateResult[];
  timestamp: Date;
  duration_ms: number;
}

// ============================================================================
// Intel Status
// ============================================================================

export interface IntelStatus {
  initialized: boolean;
  lastGlobalUpdate?: Date;
  sources: {
    total: number;
    enabled: number;
    autoUpdate: number;
  };
  patterns: {
    total: number;
    byCategory: Record<IntelCategory, number>;
    bySeverity: Record<Severity, number>;
    bySource: Record<string, number>;
  };
  coverage: {
    mitreAttack: {
      tactics: number;
      techniques: number;
    };
    categories: IntelCategory[];
  };
  health: {
    status: 'healthy' | 'degraded' | 'stale';
    oldestUpdate?: Date;
    staleSources: string[];
    failedSources: string[];
  };
}

// ============================================================================
// MITRE ATT&CK Specific
// ============================================================================

export interface MitreAttackPattern {
  id: string;                         // e.g., "T1059"
  name: string;
  tactic: string;
  technique: string;
  subtechnique?: string;
  description: string;
  aiRelevance: 'direct' | 'indirect' | 'adapted';
  promptInjectionVariants: string[];
  detectionPatterns: string[];
  mitigations: string[];
}

// ============================================================================
// Blocklist Types
// ============================================================================

export interface BlocklistEntry {
  id: string;
  sourceId: string;
  type: 'domain' | 'ip' | 'phrase' | 'pattern' | 'hash';
  value: string;
  reason: string;
  severity: Severity;
  reportedBy?: string;
  reportedAt: Date;
  confirmedMalicious: boolean;
  falsePositiveCount: number;
  enabled: boolean;
}

// ============================================================================
// Scan Configuration
// ============================================================================

export interface ThreatScanConfig {
  categories?: IntelCategory[];
  minSeverity?: Severity;
  minConfidence?: number;
  includeMitre?: boolean;
  maxMatches?: number;
  timeout_ms?: number;
}

export interface ThreatScanResult {
  scanned: boolean;
  content_length: number;
  matches: PatternMatch[];
  summary: {
    total_matches: number;
    by_severity: Record<Severity, number>;
    by_category: Record<string, number>;
    highest_severity: Severity | null;
    mitre_techniques: string[];
  };
  recommendations: string[];
  scan_duration_ms: number;
}
