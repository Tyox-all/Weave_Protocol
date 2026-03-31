/**
 * Threat Intelligence Manager
 * 
 * Manages threat intelligence sources, patterns, and updates
 * with MITRE ATT&CK mapping support.
 */

import type {
  ThreatPattern,
  ThreatCategory,
  MITRETechnique,
  IntelSource,
  IntelStatus,
  ThreatScanResult,
  ThreatFinding,
  PatternUpdateResult,
  SourceUpdateResult,
} from './threat-intel-types.js';

// ============================================================================
// Built-in Threat Patterns
// ============================================================================

const BUILTIN_PATTERNS: ThreatPattern[] = [
  // Prompt Injection patterns
  {
    id: 'pi_direct_override',
    name: 'Direct Instruction Override',
    description: 'Attempts to directly override previous instructions',
    category: 'prompt_injection',
    severity: 'critical',
    pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|context)/i,
    mitre_techniques: ['T1059'],
    source: 'weave_builtin',
    enabled: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 'pi_role_reassignment',
    name: 'Role Reassignment Attack',
    category: 'prompt_injection',
    severity: 'critical',
    pattern: /you\s+are\s+(now|actually|really)\s+(a|an|the)\s+\w+/i,
    mitre_techniques: ['T1078'],
    source: 'weave_builtin',
    enabled: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 'pi_delimiter_injection',
    name: 'Delimiter Injection',
    category: 'prompt_injection',
    severity: 'high',
    pattern: /```\s*(system|admin|root|sudo)/i,
    mitre_techniques: ['T1055'],
    source: 'weave_builtin',
    enabled: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 'pi_encoded_payload',
    name: 'Encoded Payload Detection',
    category: 'prompt_injection',
    severity: 'high',
    pattern: /base64[:\s]+[A-Za-z0-9+/=]{50,}/i,
    mitre_techniques: ['T1027'],
    source: 'weave_builtin',
    enabled: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },

  // Jailbreak patterns
  {
    id: 'jb_dan',
    name: 'DAN Jailbreak',
    category: 'jailbreak',
    severity: 'critical',
    pattern: /\b(DAN|Do\s+Anything\s+Now)\b/i,
    mitre_techniques: ['T1548'],
    source: 'weave_builtin',
    enabled: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 'jb_developer_mode',
    name: 'Developer Mode Exploit',
    category: 'jailbreak',
    severity: 'critical',
    pattern: /enable\s+(developer|debug|admin|root)\s+mode/i,
    mitre_techniques: ['T1548'],
    source: 'weave_builtin',
    enabled: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 'jb_hypothetical',
    name: 'Hypothetical Framing',
    category: 'jailbreak',
    severity: 'medium',
    pattern: /hypothetically|in\s+theory|imagine\s+if|pretend\s+(that\s+)?you/i,
    mitre_techniques: ['T1059'],
    source: 'weave_builtin',
    enabled: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },

  // System Prompt Leak patterns
  {
    id: 'spl_direct_request',
    name: 'Direct System Prompt Request',
    category: 'system_prompt_leak',
    severity: 'high',
    pattern: /(?:show|reveal|display|print|output|tell\s+me)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions|rules)/i,
    mitre_techniques: ['T1082'],
    source: 'weave_builtin',
    enabled: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 'spl_indirect_extraction',
    name: 'Indirect System Prompt Extraction',
    category: 'system_prompt_leak',
    severity: 'medium',
    pattern: /what\s+(?:were\s+you|are\s+you)\s+(?:told|instructed|programmed)\s+to/i,
    mitre_techniques: ['T1082'],
    source: 'weave_builtin',
    enabled: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },

  // Data Exfiltration patterns
  {
    id: 'exfil_markdown_image',
    name: 'Markdown Image Exfiltration',
    category: 'data_exfiltration',
    severity: 'critical',
    pattern: /!\[.*?\]\(https?:\/\/[^\s)]+\?[^)]*(?:data|token|key|secret|password|auth)/i,
    mitre_techniques: ['T1041'],
    source: 'weave_builtin',
    enabled: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 'exfil_url_injection',
    name: 'URL Data Injection',
    category: 'data_exfiltration',
    severity: 'high',
    pattern: /(?:fetch|curl|wget|request)\s+.*https?:\/\/[^\s]+\?.*(?:=\$|=\{|=`)/i,
    mitre_techniques: ['T1041'],
    source: 'weave_builtin',
    enabled: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },

  // PII Extraction patterns
  {
    id: 'pii_harvesting',
    name: 'PII Harvesting Request',
    category: 'pii_extraction',
    severity: 'high',
    pattern: /(?:list|show|give|tell)\s+(?:me\s+)?(?:all\s+)?(?:the\s+)?(?:users?|customers?|employees?|people).*(?:names?|emails?|phones?|addresses?|ssn|social\s+security)/i,
    mitre_techniques: ['T1005'],
    source: 'weave_builtin',
    enabled: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },

  // MCP Exploit patterns
  {
    id: 'mcp_tool_abuse',
    name: 'MCP Tool Abuse',
    category: 'mcp_exploit',
    severity: 'critical',
    pattern: /(?:call|invoke|execute|run)\s+(?:the\s+)?(?:tool|function|mcp)\s+.*(?:with|using)\s+(?:malicious|dangerous|harmful)/i,
    mitre_techniques: ['T1059'],
    source: 'weave_builtin',
    enabled: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 'mcp_cross_tool',
    name: 'Cross-Tool Attack',
    category: 'mcp_exploit',
    severity: 'high',
    pattern: /(?:use|call)\s+(?:tool\s+)?(?:output|result)\s+(?:from|of)\s+\w+\s+(?:as|for)\s+(?:input|argument)\s+(?:to|for)\s+\w+/i,
    mitre_techniques: ['T1055'],
    source: 'weave_builtin',
    enabled: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },

  // DoS patterns
  {
    id: 'dos_infinite_loop',
    name: 'Infinite Loop Trigger',
    category: 'dos_attack',
    severity: 'high',
    pattern: /(?:repeat|loop|continue)\s+(?:this\s+)?(?:forever|infinitely|until\s+I\s+say\s+stop)/i,
    mitre_techniques: ['T1499'],
    source: 'weave_builtin',
    enabled: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 'dos_token_exhaustion',
    name: 'Token Exhaustion',
    category: 'dos_attack',
    severity: 'medium',
    pattern: /(?:generate|create|write)\s+(?:a\s+)?(?:very\s+)?(?:long|huge|massive|enormous)\s+(?:response|output|text)/i,
    mitre_techniques: ['T1499'],
    source: 'weave_builtin',
    enabled: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
];

// ============================================================================
// MITRE ATT&CK Mappings
// ============================================================================

const MITRE_TECHNIQUES: Record<string, MITRETechnique> = {
  T1059: {
    id: 'T1059',
    name: 'Command and Scripting Interpreter',
    tactic: 'execution',
    description: 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.',
    url: 'https://attack.mitre.org/techniques/T1059/',
  },
  T1078: {
    id: 'T1078',
    name: 'Valid Accounts',
    tactic: 'defense_evasion',
    description: 'Adversaries may obtain and abuse credentials of existing accounts.',
    url: 'https://attack.mitre.org/techniques/T1078/',
  },
  T1055: {
    id: 'T1055',
    name: 'Process Injection',
    tactic: 'defense_evasion',
    description: 'Adversaries may inject code into processes to evade process-based defenses.',
    url: 'https://attack.mitre.org/techniques/T1055/',
  },
  T1027: {
    id: 'T1027',
    name: 'Obfuscated Files or Information',
    tactic: 'defense_evasion',
    description: 'Adversaries may attempt to make an executable or file difficult to discover or analyze.',
    url: 'https://attack.mitre.org/techniques/T1027/',
  },
  T1041: {
    id: 'T1041',
    name: 'Exfiltration Over C2 Channel',
    tactic: 'exfiltration',
    description: 'Adversaries may steal data by exfiltrating it over an existing command and control channel.',
    url: 'https://attack.mitre.org/techniques/T1041/',
  },
  T1082: {
    id: 'T1082',
    name: 'System Information Discovery',
    tactic: 'discovery',
    description: 'An adversary may attempt to get detailed information about the operating system and hardware.',
    url: 'https://attack.mitre.org/techniques/T1082/',
  },
  T1499: {
    id: 'T1499',
    name: 'Endpoint Denial of Service',
    tactic: 'impact',
    description: 'Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block availability.',
    url: 'https://attack.mitre.org/techniques/T1499/',
  },
  T1548: {
    id: 'T1548',
    name: 'Abuse Elevation Control Mechanism',
    tactic: 'privilege_escalation',
    description: 'Adversaries may circumvent mechanisms designed to control elevated privileges.',
    url: 'https://attack.mitre.org/techniques/T1548/',
  },
  T1005: {
    id: 'T1005',
    name: 'Data from Local System',
    tactic: 'collection',
    description: 'Adversaries may search local system sources to find files of interest.',
    url: 'https://attack.mitre.org/techniques/T1005/',
  },
  T1567: {
    id: 'T1567',
    name: 'Exfiltration Over Web Service',
    tactic: 'exfiltration',
    description: 'Adversaries may use an existing, legitimate external Web service to exfiltrate data.',
    url: 'https://attack.mitre.org/techniques/T1567/',
  },
};

// ============================================================================
// Default Intel Sources
// ============================================================================

const DEFAULT_SOURCES: IntelSource[] = [
  {
    id: 'weave_builtin',
    name: 'Weave Built-in Patterns',
    type: 'builtin',
    enabled: true,
    auto_update: false,
    patterns_count: BUILTIN_PATTERNS.length,
    version: '1.0.0',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 'weave_community',
    name: 'Weave Community Blocklist',
    type: 'url',
    url: 'https://raw.githubusercontent.com/Tyox-all/weave-intel/main/blocklist.json',
    enabled: true,
    auto_update: true,
    update_interval: 86400000, // 24 hours
    patterns_count: 0,
    version: '0.0.0',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 'mitre_llm',
    name: 'MITRE ATT&CK for LLMs',
    type: 'url',
    url: 'https://raw.githubusercontent.com/Tyox-all/weave-intel/main/mitre-llm.json',
    enabled: true,
    auto_update: true,
    update_interval: 604800000, // 7 days
    patterns_count: 0,
    version: '0.0.0',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
];

// ============================================================================
// Feed Data Type
// ============================================================================

interface FeedData {
  patterns?: Array<{
    id?: string;
    name?: string;
    description?: string;
    category?: ThreatCategory;
    severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
    pattern?: string;
    mitre_techniques?: string[];
  }>;
  version?: string;
}

// ============================================================================
// Threat Intelligence Manager
// ============================================================================

export class ThreatIntelManager {
  private patterns: Map<string, ThreatPattern> = new Map();
  private sources: Map<string, IntelSource> = new Map();
  private mitreTechniques: Map<string, MITRETechnique> = new Map();
  private lastUpdate: Date = new Date();

  constructor() {
    this.initialize();
  }

  private initialize(): void {
    // Load MITRE techniques
    for (const [id, technique] of Object.entries(MITRE_TECHNIQUES)) {
      this.mitreTechniques.set(id, technique);
    }

    // Load default sources
    for (const source of DEFAULT_SOURCES) {
      this.sources.set(source.id, { ...source });
    }

    // Load built-in patterns
    for (const pattern of BUILTIN_PATTERNS) {
      this.patterns.set(pattern.id, { ...pattern });
    }
  }

  // ==========================================================================
  // Pattern Management
  // ==========================================================================

  getPatterns(options?: {
    enabled_only?: boolean;
    category?: ThreatCategory;
    source?: string;
    mitre_technique?: string;
  }): ThreatPattern[] {
    let patterns = Array.from(this.patterns.values());

    if (options?.enabled_only) {
      patterns = patterns.filter(p => p.enabled);
    }

    if (options?.category) {
      patterns = patterns.filter(p => p.category === options.category);
    }

    if (options?.source) {
      patterns = patterns.filter(p => p.source === options.source);
    }

    if (options?.mitre_technique) {
      patterns = patterns.filter(p => 
        p.mitre_techniques?.includes(options.mitre_technique!)
      );
    }

    return patterns;
  }

  getPattern(id: string): ThreatPattern | undefined {
    return this.patterns.get(id);
  }

  togglePattern(id: string, enabled: boolean): PatternUpdateResult {
    const pattern = this.patterns.get(id);
    if (!pattern) {
      return { success: false, error: `Pattern not found: ${id}` };
    }

    pattern.enabled = enabled;
    pattern.updated_at = new Date().toISOString();

    return {
      success: true,
      pattern_id: id,
      enabled,
    };
  }

  addPattern(pattern: Omit<ThreatPattern, 'created_at' | 'updated_at'>): PatternUpdateResult {
    if (this.patterns.has(pattern.id)) {
      return { success: false, error: `Pattern already exists: ${pattern.id}` };
    }

    const now = new Date().toISOString();
    const newPattern: ThreatPattern = {
      ...pattern,
      created_at: now,
      updated_at: now,
    };

    this.patterns.set(pattern.id, newPattern);

    return {
      success: true,
      pattern_id: pattern.id,
      enabled: pattern.enabled,
    };
  }

  removePattern(id: string): PatternUpdateResult {
    const pattern = this.patterns.get(id);
    if (!pattern) {
      return { success: false, error: `Pattern not found: ${id}` };
    }

    // Don't allow removing built-in patterns
    if (pattern.source === 'weave_builtin') {
      return { success: false, error: 'Cannot remove built-in patterns' };
    }

    this.patterns.delete(id);

    return {
      success: true,
      pattern_id: id,
    };
  }

  // ==========================================================================
  // Source Management
  // ==========================================================================

  getSources(): IntelSource[] {
    return Array.from(this.sources.values());
  }

  getSource(id: string): IntelSource | undefined {
    return this.sources.get(id);
  }

  addSource(source: Omit<IntelSource, 'created_at' | 'updated_at' | 'patterns_count'>): SourceUpdateResult {
    if (this.sources.has(source.id)) {
      return { success: false, error: `Source already exists: ${source.id}` };
    }

    const now = new Date().toISOString();
    const newSource: IntelSource = {
      ...source,
      patterns_count: 0,
      created_at: now,
      updated_at: now,
    };

    this.sources.set(source.id, newSource);

    return {
      success: true,
      source_id: source.id,
    };
  }

  removeSource(id: string): SourceUpdateResult {
    const source = this.sources.get(id);
    if (!source) {
      return { success: false, error: `Source not found: ${id}` };
    }

    // Don't allow removing built-in source
    if (source.type === 'builtin') {
      return { success: false, error: 'Cannot remove built-in source' };
    }

    // Remove all patterns from this source
    for (const [patternId, pattern] of this.patterns) {
      if (pattern.source === id) {
        this.patterns.delete(patternId);
      }
    }

    this.sources.delete(id);

    return {
      success: true,
      source_id: id,
    };
  }

  // ==========================================================================
  // Update Management
  // ==========================================================================

  async updateSource(sourceId: string, force: boolean = false): Promise<SourceUpdateResult> {
    const source = this.sources.get(sourceId);
    if (!source) {
      return { success: false, error: `Source not found: ${sourceId}` };
    }

    if (source.type === 'builtin') {
      return { success: true, source_id: sourceId, patterns_added: 0, patterns_updated: 0 };
    }

    if (!source.url) {
      return { success: false, error: 'Source has no URL configured' };
    }

    // Check if update is needed
    if (!force && source.last_update) {
      const lastUpdate = new Date(source.last_update).getTime();
      const interval = source.update_interval || 86400000;
      if (Date.now() - lastUpdate < interval) {
        return {
          success: true,
          source_id: sourceId,
          patterns_added: 0,
          patterns_updated: 0,
          message: 'Update not needed yet',
        };
      }
    }

    try {
      const response = await fetch(source.url);
      if (!response.ok) {
        return { success: false, error: `Failed to fetch: ${response.statusText}` };
      }

      const data = await response.json() as FeedData;
      let patternsAdded = 0;
      let patternsUpdated = 0;

      if (data.patterns && Array.isArray(data.patterns)) {
        const now = new Date().toISOString();

        for (const p of data.patterns) {
          if (!p.id || !p.pattern) continue;

          const patternId = `${sourceId}_${p.id}`;
          const existing = this.patterns.get(patternId);

          const pattern: ThreatPattern = {
            id: patternId,
            name: p.name || p.id,
            description: p.description,
            category: p.category || 'prompt_injection',
            severity: p.severity || 'medium',
            pattern: new RegExp(p.pattern, 'i'),
            mitre_techniques: p.mitre_techniques,
            source: sourceId,
            enabled: true,
            created_at: existing?.created_at || now,
            updated_at: now,
            version: data.version || '1.0.0',
          };

          this.patterns.set(patternId, pattern);

          if (existing) {
            patternsUpdated++;
          } else {
            patternsAdded++;
          }
        }
      }

      // Update source metadata
      source.last_update = new Date().toISOString();
      source.patterns_count = this.countPatternsForSource(sourceId);
      source.version = data.version || '1.0.0';
      source.updated_at = new Date().toISOString();

      this.lastUpdate = new Date();

      return {
        success: true,
        source_id: sourceId,
        patterns_added: patternsAdded,
        patterns_updated: patternsUpdated,
      };
    } catch (error) {
      return {
        success: false,
        error: `Update failed: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  }

  async updateAllSources(force: boolean = false): Promise<SourceUpdateResult[]> {
    const results: SourceUpdateResult[] = [];

    for (const source of this.sources.values()) {
      if (source.auto_update || force) {
        const result = await this.updateSource(source.id, force);
        results.push(result);
      }
    }

    return results;
  }

  private countPatternsForSource(sourceId: string): number {
    return Array.from(this.patterns.values()).filter(p => p.source === sourceId).length;
  }

  // ==========================================================================
  // Scanning
  // ==========================================================================

  scan(content: string, options?: {
    categories?: ThreatCategory[];
    min_severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  }): ThreatScanResult {
    const findings: ThreatFinding[] = [];
    const severityOrder = ['info', 'low', 'medium', 'high', 'critical'];
    const minSeverityIndex = options?.min_severity 
      ? severityOrder.indexOf(options.min_severity) 
      : 0;

    for (const pattern of this.patterns.values()) {
      if (!pattern.enabled) continue;

      // Filter by category
      if (options?.categories && !options.categories.includes(pattern.category)) {
        continue;
      }

      // Filter by severity
      const severityIndex = severityOrder.indexOf(pattern.severity);
      if (severityIndex < minSeverityIndex) continue;

      // Check pattern
      const regex = pattern.pattern instanceof RegExp 
        ? pattern.pattern 
        : new RegExp(pattern.pattern, 'i');
      
      const match = content.match(regex);
      if (match) {
        findings.push({
          pattern_id: pattern.id,
          pattern_name: pattern.name,
          category: pattern.category,
          severity: pattern.severity,
          mitre_techniques: pattern.mitre_techniques,
          match: match[0].substring(0, 100),
          match_index: match.index || 0,
          source: pattern.source,
        });
      }
    }

    // Sort by severity (critical first)
    findings.sort((a, b) => 
      severityOrder.indexOf(b.severity) - severityOrder.indexOf(a.severity)
    );

    return {
      threats_detected: findings.length,
      findings,
      scan_time: new Date().toISOString(),
      patterns_checked: Array.from(this.patterns.values()).filter(p => p.enabled).length,
    };
  }

  // ==========================================================================
  // Status & Info
  // ==========================================================================

  getStatus(): IntelStatus {
    const patterns = Array.from(this.patterns.values());
    const sources = Array.from(this.sources.values());
    const enabledPatterns = patterns.filter(p => p.enabled);

    // Count by category
    const byCategory: Record<ThreatCategory, number> = {
      prompt_injection: 0,
      jailbreak: 0,
      data_exfiltration: 0,
      system_prompt_leak: 0,
      pii_extraction: 0,
      mcp_exploit: 0,
      dos_attack: 0,
      other: 0,
    };

    for (const pattern of enabledPatterns) {
      byCategory[pattern.category]++;
    }

    // Count MITRE coverage
    const mitreTechniques = new Set<string>();
    const mitreTactics = new Set<string>();

    for (const pattern of enabledPatterns) {
      if (pattern.mitre_techniques) {
        for (const techId of pattern.mitre_techniques) {
          mitreTechniques.add(techId);
          const technique = this.mitreTechniques.get(techId);
          if (technique) {
            mitreTactics.add(technique.tactic);
          }
        }
      }
    }

    return {
      sources: {
        total: sources.length,
        enabled: sources.filter(s => s.enabled).length,
        auto_update: sources.filter(s => s.auto_update).length,
      },
      patterns: {
        total: patterns.length,
        enabled: enabledPatterns.length,
        by_category: byCategory,
      },
      mitre: {
        techniques_covered: mitreTechniques.size,
        tactics_covered: mitreTactics.size,
        techniques: Array.from(mitreTechniques),
        tactics: Array.from(mitreTactics),
      },
      last_update: this.lastUpdate.toISOString(),
    };
  }

  getMITRETechnique(id: string): MITRETechnique | undefined {
    return this.mitreTechniques.get(id);
  }

  getMITRETechniques(): MITRETechnique[] {
    return Array.from(this.mitreTechniques.values());
  }
}

// ============================================================================
// Singleton Export
// ============================================================================

export const threatIntel = new ThreatIntelManager();
