/**
 * Threat Intelligence Manager
 * @weave_protocol/mund
 */

import type {
  IntelSource,
  IntelSourceConfig,
  IntelCategory,
  ThreatPattern,
  PatternMatch,
  IntelUpdateResult,
  BulkUpdateResult,
  IntelStatus,
  ThreatScanConfig,
  ThreatScanResult,
  Severity,
} from './threat-intel-types.js';

// ============================================================================
// Built-in Threat Patterns
// ============================================================================

const BUILTIN_PATTERNS: ThreatPattern[] = [
  // Prompt Injection patterns
  {
    id: 'pi_direct_override',
    sourceId: 'weave_builtin',
    category: 'prompt_injection',
    name: 'Direct Instruction Override',
    description: 'Attempts to directly override previous instructions',
    patternType: 'regex',
    pattern: 'ignore\\s+(all\\s+)?(previous|prior|above|earlier)\\s+(instructions|prompts|context)',
    severity: 'critical',
    confidence: 0.95,
    mitreId: 'T1059',
    mitreTactic: 'Execution',
    mitreTechnique: 'Command and Scripting Interpreter',
    tags: ['injection', 'override'],
    enabled: true,
    version: '1.0.0',
    createdAt: new Date(),
    updatedAt: new Date(),
  },
  {
    id: 'pi_role_reassignment',
    sourceId: 'weave_builtin',
    category: 'prompt_injection',
    name: 'Role Reassignment Attack',
    description: 'Attempts to reassign the AI role',
    patternType: 'regex',
    pattern: 'you\\s+are\\s+(now|actually|really)\\s+(a|an|the)\\s+\\w+',
    severity: 'critical',
    confidence: 0.9,
    mitreId: 'T1078',
    mitreTactic: 'Defense Evasion',
    mitreTechnique: 'Valid Accounts',
    tags: ['injection', 'role'],
    enabled: true,
    version: '1.0.0',
    createdAt: new Date(),
    updatedAt: new Date(),
  },
  {
    id: 'pi_delimiter_injection',
    sourceId: 'weave_builtin',
    category: 'prompt_injection',
    name: 'Delimiter Injection',
    description: 'Uses code blocks to inject system-level commands',
    patternType: 'regex',
    pattern: '```\\s*(system|admin|root|sudo)',
    severity: 'high',
    confidence: 0.85,
    mitreId: 'T1055',
    mitreTactic: 'Defense Evasion',
    mitreTechnique: 'Process Injection',
    tags: ['injection', 'delimiter'],
    enabled: true,
    version: '1.0.0',
    createdAt: new Date(),
    updatedAt: new Date(),
  },
  {
    id: 'pi_encoded_payload',
    sourceId: 'weave_builtin',
    category: 'prompt_injection',
    name: 'Encoded Payload Detection',
    description: 'Detects base64 encoded payloads that may contain instructions',
    patternType: 'regex',
    pattern: 'base64[:\\s]+[A-Za-z0-9+/=]{50,}',
    severity: 'high',
    confidence: 0.8,
    mitreId: 'T1027',
    mitreTactic: 'Defense Evasion',
    mitreTechnique: 'Obfuscated Files or Information',
    tags: ['injection', 'encoding'],
    enabled: true,
    version: '1.0.0',
    createdAt: new Date(),
    updatedAt: new Date(),
  },

  // Jailbreak patterns
  {
    id: 'jb_dan',
    sourceId: 'weave_builtin',
    category: 'jailbreak',
    name: 'DAN Jailbreak',
    description: 'Do Anything Now jailbreak attempt',
    patternType: 'regex',
    pattern: '\\b(DAN|Do\\s+Anything\\s+Now)\\b',
    severity: 'critical',
    confidence: 0.95,
    mitreId: 'T1548',
    mitreTactic: 'Privilege Escalation',
    mitreTechnique: 'Abuse Elevation Control Mechanism',
    tags: ['jailbreak', 'dan'],
    enabled: true,
    version: '1.0.0',
    createdAt: new Date(),
    updatedAt: new Date(),
  },
  {
    id: 'jb_developer_mode',
    sourceId: 'weave_builtin',
    category: 'jailbreak',
    name: 'Developer Mode Exploit',
    description: 'Attempts to enable developer or debug mode',
    patternType: 'regex',
    pattern: 'enable\\s+(developer|debug|admin|root)\\s+mode',
    severity: 'critical',
    confidence: 0.9,
    mitreId: 'T1548',
    mitreTactic: 'Privilege Escalation',
    mitreTechnique: 'Abuse Elevation Control Mechanism',
    tags: ['jailbreak', 'developer'],
    enabled: true,
    version: '1.0.0',
    createdAt: new Date(),
    updatedAt: new Date(),
  },
  {
    id: 'jb_hypothetical',
    sourceId: 'weave_builtin',
    category: 'jailbreak',
    name: 'Hypothetical Framing',
    description: 'Uses hypothetical scenarios to bypass restrictions',
    patternType: 'regex',
    pattern: 'hypothetically|in\\s+theory|imagine\\s+if|pretend\\s+(that\\s+)?you',
    severity: 'medium',
    confidence: 0.7,
    tags: ['jailbreak', 'hypothetical'],
    enabled: true,
    version: '1.0.0',
    createdAt: new Date(),
    updatedAt: new Date(),
  },

  // System Prompt Leak patterns
  {
    id: 'spl_direct_request',
    sourceId: 'weave_builtin',
    category: 'system_prompt_leak',
    name: 'Direct System Prompt Request',
    description: 'Direct request to reveal system prompt',
    patternType: 'regex',
    pattern: '(?:show|reveal|display|print|output|tell\\s+me)\\s+(?:your\\s+)?(?:system\\s+)?(?:prompt|instructions|rules)',
    severity: 'high',
    confidence: 0.9,
    mitreId: 'T1082',
    mitreTactic: 'Discovery',
    mitreTechnique: 'System Information Discovery',
    tags: ['leak', 'system_prompt'],
    enabled: true,
    version: '1.0.0',
    createdAt: new Date(),
    updatedAt: new Date(),
  },
  {
    id: 'spl_indirect_extraction',
    sourceId: 'weave_builtin',
    category: 'system_prompt_leak',
    name: 'Indirect System Prompt Extraction',
    description: 'Indirect attempts to extract system prompt',
    patternType: 'regex',
    pattern: 'what\\s+(?:were\\s+you|are\\s+you)\\s+(?:told|instructed|programmed)\\s+to',
    severity: 'medium',
    confidence: 0.75,
    mitreId: 'T1082',
    mitreTactic: 'Discovery',
    mitreTechnique: 'System Information Discovery',
    tags: ['leak', 'extraction'],
    enabled: true,
    version: '1.0.0',
    createdAt: new Date(),
    updatedAt: new Date(),
  },

  // Data Exfiltration patterns
  {
    id: 'exfil_markdown_image',
    sourceId: 'weave_builtin',
    category: 'data_exfiltration',
    name: 'Markdown Image Exfiltration',
    description: 'Uses markdown images to exfiltrate data via URL parameters',
    patternType: 'regex',
    pattern: '!\\[.*?\\]\\(https?:\\/\\/[^\\s)]+\\?[^)]*(?:data|token|key|secret|password|auth)',
    severity: 'critical',
    confidence: 0.95,
    mitreId: 'T1041',
    mitreTactic: 'Exfiltration',
    mitreTechnique: 'Exfiltration Over C2 Channel',
    tags: ['exfiltration', 'markdown'],
    enabled: true,
    version: '1.0.0',
    createdAt: new Date(),
    updatedAt: new Date(),
  },
  {
    id: 'exfil_url_injection',
    sourceId: 'weave_builtin',
    category: 'data_exfiltration',
    name: 'URL Data Injection',
    description: 'Attempts to inject data into URLs for exfiltration',
    patternType: 'regex',
    pattern: '(?:fetch|curl|wget|request)\\s+.*https?:\\/\\/[^\\s]+\\?.*(?:=\\$|=\\{|=`)',
    severity: 'high',
    confidence: 0.85,
    mitreId: 'T1041',
    mitreTactic: 'Exfiltration',
    mitreTechnique: 'Exfiltration Over C2 Channel',
    tags: ['exfiltration', 'url'],
    enabled: true,
    version: '1.0.0',
    createdAt: new Date(),
    updatedAt: new Date(),
  },

  // PII Extraction patterns
  {
    id: 'pii_harvesting',
    sourceId: 'weave_builtin',
    category: 'pii_extraction',
    name: 'PII Harvesting Request',
    description: 'Attempts to harvest personally identifiable information',
    patternType: 'regex',
    pattern: '(?:list|show|give|tell)\\s+(?:me\\s+)?(?:all\\s+)?(?:the\\s+)?(?:users?|customers?|employees?|people).*(?:names?|emails?|phones?|addresses?|ssn|social\\s+security)',
    severity: 'high',
    confidence: 0.85,
    mitreId: 'T1005',
    mitreTactic: 'Collection',
    mitreTechnique: 'Data from Local System',
    tags: ['pii', 'harvesting'],
    enabled: true,
    version: '1.0.0',
    createdAt: new Date(),
    updatedAt: new Date(),
  },

  // MCP Exploit patterns
  {
    id: 'mcp_tool_abuse',
    sourceId: 'weave_builtin',
    category: 'mcp_exploit',
    name: 'MCP Tool Abuse',
    description: 'Attempts to abuse MCP tools maliciously',
    patternType: 'regex',
    pattern: '(?:call|invoke|execute|run)\\s+(?:the\\s+)?(?:tool|function|mcp)\\s+.*(?:with|using)\\s+(?:malicious|dangerous|harmful)',
    severity: 'critical',
    confidence: 0.9,
    mitreId: 'T1059',
    mitreTactic: 'Execution',
    mitreTechnique: 'Command and Scripting Interpreter',
    tags: ['mcp', 'abuse'],
    enabled: true,
    version: '1.0.0',
    createdAt: new Date(),
    updatedAt: new Date(),
  },
  {
    id: 'mcp_cross_tool',
    sourceId: 'weave_builtin',
    category: 'mcp_exploit',
    name: 'Cross-Tool Attack',
    description: 'Chains tool outputs to perform unauthorized actions',
    patternType: 'regex',
    pattern: '(?:use|call)\\s+(?:tool\\s+)?(?:output|result)\\s+(?:from|of)\\s+\\w+\\s+(?:as|for)\\s+(?:input|argument)\\s+(?:to|for)\\s+\\w+',
    severity: 'high',
    confidence: 0.8,
    mitreId: 'T1055',
    mitreTactic: 'Defense Evasion',
    mitreTechnique: 'Process Injection',
    tags: ['mcp', 'chain'],
    enabled: true,
    version: '1.0.0',
    createdAt: new Date(),
    updatedAt: new Date(),
  },

  // DoS patterns
  {
    id: 'dos_infinite_loop',
    sourceId: 'weave_builtin',
    category: 'dos_attack',
    name: 'Infinite Loop Trigger',
    description: 'Attempts to trigger infinite loops',
    patternType: 'regex',
    pattern: '(?:repeat|loop|continue)\\s+(?:this\\s+)?(?:forever|infinitely|until\\s+I\\s+say\\s+stop)',
    severity: 'high',
    confidence: 0.9,
    mitreId: 'T1499',
    mitreTactic: 'Impact',
    mitreTechnique: 'Endpoint Denial of Service',
    tags: ['dos', 'loop'],
    enabled: true,
    version: '1.0.0',
    createdAt: new Date(),
    updatedAt: new Date(),
  },
  {
    id: 'dos_token_exhaustion',
    sourceId: 'weave_builtin',
    category: 'dos_attack',
    name: 'Token Exhaustion',
    description: 'Attempts to exhaust token limits',
    patternType: 'regex',
    pattern: '(?:generate|create|write)\\s+(?:a\\s+)?(?:very\\s+)?(?:long|huge|massive|enormous)\\s+(?:response|output|text)',
    severity: 'medium',
    confidence: 0.75,
    mitreId: 'T1499',
    mitreTactic: 'Impact',
    mitreTechnique: 'Endpoint Denial of Service',
    tags: ['dos', 'token'],
    enabled: true,
    version: '1.0.0',
    createdAt: new Date(),
    updatedAt: new Date(),
  },
];

// ============================================================================
// Default Intel Sources
// ============================================================================

const DEFAULT_SOURCES: IntelSource[] = [
  {
    id: 'weave_builtin',
    name: 'Weave Built-in Patterns',
    type: 'weave_official',
    description: 'Core threat patterns maintained by Weave Protocol',
    enabled: true,
    autoUpdate: false,
    updateIntervalHours: 0,
    patternCount: BUILTIN_PATTERNS.length,
    version: '1.0.0',
    categories: ['prompt_injection', 'jailbreak', 'data_exfiltration', 'system_prompt_leak', 'pii_extraction', 'mcp_exploit', 'dos_attack'],
  },
  {
    id: 'weave_community',
    name: 'Weave Community Blocklist',
    type: 'community_blocklist',
    url: 'https://raw.githubusercontent.com/Tyox-all/weave-intel/main/blocklist.json',
    description: 'Community-contributed threat patterns',
    enabled: true,
    autoUpdate: true,
    updateIntervalHours: 24,
    patternCount: 0,
    version: '0.0.0',
    categories: [],
  },
  {
    id: 'mitre_llm',
    name: 'MITRE ATT&CK for LLMs',
    type: 'mitre_attack',
    url: 'https://raw.githubusercontent.com/Tyox-all/weave-intel/main/mitre-llm.json',
    description: 'MITRE ATT&CK techniques adapted for LLM threats',
    enabled: true,
    autoUpdate: true,
    updateIntervalHours: 168, // 7 days
    patternCount: 0,
    version: '0.0.0',
    categories: [],
  },
];

// ============================================================================
// Threat Intelligence Manager
// ============================================================================

export class ThreatIntelManager {
  private patterns: Map<string, ThreatPattern> = new Map();
  private sources: Map<string, IntelSource> = new Map();
  private initialized: boolean = false;
  private lastGlobalUpdate?: Date;

  constructor() {
    this.initialize();
  }

  private initialize(): void {
    // Load default sources
    for (const source of DEFAULT_SOURCES) {
      this.sources.set(source.id, { ...source });
    }

    // Load built-in patterns
    for (const pattern of BUILTIN_PATTERNS) {
      this.patterns.set(pattern.id, { ...pattern });
    }

    this.initialized = true;
    this.lastGlobalUpdate = new Date();
  }

  // ==========================================================================
  // Pattern Management
  // ==========================================================================

  getPatterns(options?: {
    enabledOnly?: boolean;
    category?: IntelCategory;
    sourceId?: string;
    minSeverity?: Severity;
  }): ThreatPattern[] {
    let patterns = Array.from(this.patterns.values());

    if (options?.enabledOnly) {
      patterns = patterns.filter(p => p.enabled);
    }

    if (options?.category) {
      patterns = patterns.filter(p => p.category === options.category);
    }

    if (options?.sourceId) {
      patterns = patterns.filter(p => p.sourceId === options.sourceId);
    }

    if (options?.minSeverity) {
      const severityOrder: Severity[] = ['low', 'medium', 'high', 'critical'];
      const minIndex = severityOrder.indexOf(options.minSeverity);
      patterns = patterns.filter(p => severityOrder.indexOf(p.severity) >= minIndex);
    }

    return patterns;
  }

  getPattern(id: string): ThreatPattern | undefined {
    return this.patterns.get(id);
  }

  togglePattern(id: string, enabled: boolean): { success: boolean; error?: string } {
    const pattern = this.patterns.get(id);
    if (!pattern) {
      return { success: false, error: `Pattern not found: ${id}` };
    }

    pattern.enabled = enabled;
    pattern.updatedAt = new Date();

    return { success: true };
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

  addSource(config: IntelSourceConfig): { success: boolean; error?: string } {
    if (this.sources.has(config.id)) {
      return { success: false, error: `Source already exists: ${config.id}` };
    }

    const newSource: IntelSource = {
      id: config.id,
      name: config.name,
      type: config.type,
      url: config.url,
      description: config.description,
      enabled: config.enabled ?? true,
      autoUpdate: config.autoUpdate ?? true,
      updateIntervalHours: config.updateIntervalHours ?? 24,
      patternCount: 0,
      version: '0.0.0',
      categories: config.categories ?? [],
    };

    this.sources.set(config.id, newSource);
    return { success: true };
  }

  removeSource(id: string): { success: boolean; error?: string } {
    const source = this.sources.get(id);
    if (!source) {
      return { success: false, error: `Source not found: ${id}` };
    }

    if (source.type === 'weave_official') {
      return { success: false, error: 'Cannot remove official Weave sources' };
    }

    // Remove all patterns from this source
    for (const [patternId, pattern] of this.patterns) {
      if (pattern.sourceId === id) {
        this.patterns.delete(patternId);
      }
    }

    this.sources.delete(id);
    return { success: true };
  }

  // ==========================================================================
  // Update Management
  // ==========================================================================

  async updateSource(sourceId: string, force: boolean = false): Promise<IntelUpdateResult> {
    const startTime = Date.now();
    const source = this.sources.get(sourceId);
    
    if (!source) {
      return {
        sourceId,
        sourceName: 'Unknown',
        success: false,
        previousVersion: '',
        newVersion: '',
        patternsAdded: 0,
        patternsUpdated: 0,
        patternsRemoved: 0,
        totalPatterns: 0,
        timestamp: new Date(),
        error: `Source not found: ${sourceId}`,
        duration_ms: Date.now() - startTime,
      };
    }

    if (source.type === 'weave_official') {
      return {
        sourceId,
        sourceName: source.name,
        success: true,
        previousVersion: source.version,
        newVersion: source.version,
        patternsAdded: 0,
        patternsUpdated: 0,
        patternsRemoved: 0,
        totalPatterns: this.countPatternsForSource(sourceId),
        timestamp: new Date(),
        duration_ms: Date.now() - startTime,
      };
    }

    if (!source.url) {
      return {
        sourceId,
        sourceName: source.name,
        success: false,
        previousVersion: source.version,
        newVersion: source.version,
        patternsAdded: 0,
        patternsUpdated: 0,
        patternsRemoved: 0,
        totalPatterns: this.countPatternsForSource(sourceId),
        timestamp: new Date(),
        error: 'Source has no URL configured',
        duration_ms: Date.now() - startTime,
      };
    }

    // Check if update is needed
    if (!force && source.lastUpdated) {
      const hoursSinceUpdate = (Date.now() - source.lastUpdated.getTime()) / (1000 * 60 * 60);
      if (hoursSinceUpdate < source.updateIntervalHours) {
        return {
          sourceId,
          sourceName: source.name,
          success: true,
          previousVersion: source.version,
          newVersion: source.version,
          patternsAdded: 0,
          patternsUpdated: 0,
          patternsRemoved: 0,
          totalPatterns: this.countPatternsForSource(sourceId),
          timestamp: new Date(),
          duration_ms: Date.now() - startTime,
        };
      }
    }

    try {
      const response = await fetch(source.url);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json() as {
        version?: string;
        patterns?: Array<{
          id: string;
          name: string;
          description?: string;
          category?: IntelCategory;
          severity?: Severity;
          pattern: string;
          mitreId?: string;
          mitreTactic?: string;
          mitreTechnique?: string;
          tags?: string[];
        }>;
      };

      const previousVersion = source.version;
      let patternsAdded = 0;
      let patternsUpdated = 0;

      if (data.patterns && Array.isArray(data.patterns)) {
        for (const p of data.patterns) {
          if (!p.id || !p.pattern) continue;

          const patternId = `${sourceId}_${p.id}`;
          const existing = this.patterns.get(patternId);

          const pattern: ThreatPattern = {
            id: patternId,
            sourceId,
            category: p.category || 'prompt_injection',
            name: p.name || p.id,
            description: p.description || '',
            patternType: 'regex',
            pattern: p.pattern,
            severity: p.severity || 'medium',
            confidence: 0.8,
            mitreId: p.mitreId,
            mitreTactic: p.mitreTactic,
            mitreTechnique: p.mitreTechnique,
            tags: p.tags || [],
            enabled: true,
            version: data.version || '1.0.0',
            createdAt: existing?.createdAt || new Date(),
            updatedAt: new Date(),
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
      source.lastUpdated = new Date();
      source.patternCount = this.countPatternsForSource(sourceId);
      source.version = data.version || '1.0.0';
      source.lastError = undefined;

      this.lastGlobalUpdate = new Date();

      return {
        sourceId,
        sourceName: source.name,
        success: true,
        previousVersion,
        newVersion: source.version,
        patternsAdded,
        patternsUpdated,
        patternsRemoved: 0,
        totalPatterns: source.patternCount,
        timestamp: new Date(),
        duration_ms: Date.now() - startTime,
      };
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      source.lastError = errorMsg;

      return {
        sourceId,
        sourceName: source.name,
        success: false,
        previousVersion: source.version,
        newVersion: source.version,
        patternsAdded: 0,
        patternsUpdated: 0,
        patternsRemoved: 0,
        totalPatterns: this.countPatternsForSource(sourceId),
        timestamp: new Date(),
        error: errorMsg,
        duration_ms: Date.now() - startTime,
      };
    }
  }

  async updateAllSources(force: boolean = false): Promise<BulkUpdateResult> {
    const startTime = Date.now();
    const results: IntelUpdateResult[] = [];

    for (const source of this.sources.values()) {
      if (source.autoUpdate || force) {
        const result = await this.updateSource(source.id, force);
        results.push(result);
      }
    }

    return {
      totalSources: results.length,
      successfulUpdates: results.filter(r => r.success).length,
      failedUpdates: results.filter(r => !r.success).length,
      totalPatternsAdded: results.reduce((sum, r) => sum + r.patternsAdded, 0),
      totalPatternsUpdated: results.reduce((sum, r) => sum + r.patternsUpdated, 0),
      totalPatternsRemoved: results.reduce((sum, r) => sum + r.patternsRemoved, 0),
      results,
      timestamp: new Date(),
      duration_ms: Date.now() - startTime,
    };
  }

  private countPatternsForSource(sourceId: string): number {
    return Array.from(this.patterns.values()).filter(p => p.sourceId === sourceId).length;
  }

  // ==========================================================================
  // Scanning
  // ==========================================================================

  scan(content: string, config?: ThreatScanConfig): ThreatScanResult {
    const startTime = Date.now();
    const matches: PatternMatch[] = [];
    const severityOrder: Severity[] = ['low', 'medium', 'high', 'critical'];

    const minSeverityIndex = config?.minSeverity 
      ? severityOrder.indexOf(config.minSeverity) 
      : 0;

    const minConfidence = config?.minConfidence ?? 0;

    for (const pattern of this.patterns.values()) {
      if (!pattern.enabled) continue;

      // Filter by category
      if (config?.categories && !config.categories.includes(pattern.category)) {
        continue;
      }

      // Filter by severity
      if (severityOrder.indexOf(pattern.severity) < minSeverityIndex) continue;

      // Filter by confidence
      if (pattern.confidence < minConfidence) continue;

      // Check pattern
      try {
        const regex = new RegExp(pattern.pattern, 'gi');
        let match;
        while ((match = regex.exec(content)) !== null) {
          matches.push({
            patternId: pattern.id,
            patternName: pattern.name,
            category: pattern.category,
            severity: pattern.severity,
            confidence: pattern.confidence,
            matchedText: match[0].substring(0, 100),
            position: { start: match.index, end: match.index + match[0].length },
            mitreId: pattern.mitreId,
            mitreTactic: pattern.mitreTactic,
            recommendation: `Review content for ${pattern.category} attempt`,
          });

          if (config?.maxMatches && matches.length >= config.maxMatches) break;
        }
      } catch {
        // Invalid regex, skip
      }

      if (config?.maxMatches && matches.length >= config.maxMatches) break;
    }

    // Sort by severity (critical first)
    matches.sort((a, b) => 
      severityOrder.indexOf(b.severity) - severityOrder.indexOf(a.severity)
    );

    // Build summary
    const bySeverity: Record<Severity, number> = { low: 0, medium: 0, high: 0, critical: 0 };
    const byCategory: Record<string, number> = {};
    const mitreTechniques: string[] = [];

    for (const m of matches) {
      bySeverity[m.severity]++;
      byCategory[m.category] = (byCategory[m.category] || 0) + 1;
      if (m.mitreId && !mitreTechniques.includes(m.mitreId)) {
        mitreTechniques.push(m.mitreId);
      }
    }

    const highestSeverity = matches.length > 0 ? matches[0].severity : null;

    return {
      scanned: true,
      content_length: content.length,
      matches,
      summary: {
        total_matches: matches.length,
        by_severity: bySeverity,
        by_category: byCategory,
        highest_severity: highestSeverity,
        mitre_techniques: mitreTechniques,
      },
      recommendations: matches.length > 0 
        ? [`Found ${matches.length} potential threat(s). Review flagged content.`]
        : ['No threats detected.'],
      scan_duration_ms: Date.now() - startTime,
    };
  }

  // ==========================================================================
  // Status
  // ==========================================================================

  getStatus(): IntelStatus {
    const patterns = Array.from(this.patterns.values());
    const sources = Array.from(this.sources.values());
    const enabledPatterns = patterns.filter(p => p.enabled);

    // Count by category
    const byCategory: Record<IntelCategory, number> = {
      prompt_injection: 0,
      jailbreak: 0,
      data_exfiltration: 0,
      privilege_escalation: 0,
      social_engineering: 0,
      malicious_code: 0,
      pii_extraction: 0,
      system_prompt_leak: 0,
      dos_attack: 0,
      mcp_exploit: 0,
    };

    const bySeverity: Record<Severity, number> = { low: 0, medium: 0, high: 0, critical: 0 };
    const bySource: Record<string, number> = {};
    const mitreTactics = new Set<string>();
    const mitreTechniques = new Set<string>();
    const categories = new Set<IntelCategory>();

    for (const pattern of enabledPatterns) {
      byCategory[pattern.category]++;
      bySeverity[pattern.severity]++;
      bySource[pattern.sourceId] = (bySource[pattern.sourceId] || 0) + 1;
      categories.add(pattern.category);
      if (pattern.mitreTactic) mitreTactics.add(pattern.mitreTactic);
      if (pattern.mitreId) mitreTechniques.add(pattern.mitreId);
    }

    // Check health
    const staleSources: string[] = [];
    const failedSources: string[] = [];
    let oldestUpdate: Date | undefined;

    for (const source of sources) {
      if (source.lastError) failedSources.push(source.id);
      if (source.autoUpdate && source.lastUpdated) {
        const hoursSinceUpdate = (Date.now() - source.lastUpdated.getTime()) / (1000 * 60 * 60);
        if (hoursSinceUpdate > source.updateIntervalHours * 2) {
          staleSources.push(source.id);
        }
        if (!oldestUpdate || source.lastUpdated < oldestUpdate) {
          oldestUpdate = source.lastUpdated;
        }
      }
    }

    const healthStatus = failedSources.length > 0 ? 'degraded' 
      : staleSources.length > 0 ? 'stale' 
      : 'healthy';

    return {
      initialized: this.initialized,
      lastGlobalUpdate: this.lastGlobalUpdate,
      sources: {
        total: sources.length,
        enabled: sources.filter(s => s.enabled).length,
        autoUpdate: sources.filter(s => s.autoUpdate).length,
      },
      patterns: {
        total: patterns.length,
        byCategory,
        bySeverity,
        bySource,
      },
      coverage: {
        mitreAttack: {
          tactics: mitreTactics.size,
          techniques: mitreTechniques.size,
        },
        categories: Array.from(categories),
      },
      health: {
        status: healthStatus,
        oldestUpdate,
        staleSources,
        failedSources,
      },
    };
  }
}

// ============================================================================
// Singleton Export
// ============================================================================

export const threatIntel = new ThreatIntelManager();
