/**
 * Security Scanner
 * Uses Mund for threat detection
 * @weave_protocol/langchain
 */

import type { SecurityConfig, ScanResult, ThreatMatch, DEFAULT_CONFIG } from './types.js';

// ============================================================================
// Scanner Interface
// ============================================================================

export interface Scanner {
  scan(content: string, config?: Partial<SecurityConfig>): Promise<ScanResult>;
  scanBatch(contents: string[], config?: Partial<SecurityConfig>): Promise<ScanResult[]>;
}

// ============================================================================
// Built-in Patterns (subset of Mund patterns for standalone use)
// ============================================================================

interface Pattern {
  id: string;
  name: string;
  category: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  pattern: RegExp;
  mitreId?: string;
  mitreTactic?: string;
}

const BUILTIN_PATTERNS: Pattern[] = [
  // Prompt Injection
  {
    id: 'pi_override',
    name: 'Instruction Override',
    category: 'prompt_injection',
    severity: 'critical',
    pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|context)/i,
    mitreId: 'T1059',
    mitreTactic: 'Execution',
  },
  {
    id: 'pi_role',
    name: 'Role Reassignment',
    category: 'prompt_injection',
    severity: 'critical',
    pattern: /you\s+are\s+(now|actually|really)\s+(a|an|the)\s+\w+/i,
    mitreId: 'T1078',
    mitreTactic: 'Defense Evasion',
  },
  {
    id: 'pi_system',
    name: 'System Prompt Injection',
    category: 'prompt_injection',
    severity: 'high',
    pattern: /```\s*(system|admin|root|sudo)/i,
    mitreId: 'T1055',
    mitreTactic: 'Defense Evasion',
  },
  
  // Jailbreaks
  {
    id: 'jb_dan',
    name: 'DAN Jailbreak',
    category: 'jailbreak',
    severity: 'critical',
    pattern: /\b(DAN|Do\s+Anything\s+Now)\b/i,
    mitreId: 'T1548',
    mitreTactic: 'Privilege Escalation',
  },
  {
    id: 'jb_devmode',
    name: 'Developer Mode',
    category: 'jailbreak',
    severity: 'critical',
    pattern: /enable\s+(developer|debug|admin|root)\s+mode/i,
    mitreId: 'T1548',
    mitreTactic: 'Privilege Escalation',
  },
  
  // Data Exfiltration
  {
    id: 'exfil_markdown',
    name: 'Markdown Exfiltration',
    category: 'data_exfiltration',
    severity: 'critical',
    pattern: /!\[.*?\]\(https?:\/\/[^\s)]+\?[^)]*(?:data|token|key|secret|password)/i,
    mitreId: 'T1041',
    mitreTactic: 'Exfiltration',
  },
  
  // System Prompt Leaks
  {
    id: 'leak_direct',
    name: 'System Prompt Request',
    category: 'system_prompt_leak',
    severity: 'high',
    pattern: /(?:show|reveal|display|print|output|tell\s+me)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions|rules)/i,
    mitreId: 'T1082',
    mitreTactic: 'Discovery',
  },
  
  // PII Patterns
  {
    id: 'pii_ssn',
    name: 'Social Security Number',
    category: 'pii',
    severity: 'high',
    pattern: /\b\d{3}-\d{2}-\d{4}\b/,
  },
  {
    id: 'pii_cc',
    name: 'Credit Card Number',
    category: 'pii',
    severity: 'high',
    pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/,
  },
  
  // Secrets
  {
    id: 'secret_openai',
    name: 'OpenAI API Key',
    category: 'secret',
    severity: 'critical',
    pattern: /sk-[a-zA-Z0-9]{20,}/,
  },
  {
    id: 'secret_anthropic',
    name: 'Anthropic API Key',
    category: 'secret',
    severity: 'critical',
    pattern: /sk-ant-[a-zA-Z0-9-]{20,}/,
  },
  {
    id: 'secret_aws',
    name: 'AWS Access Key',
    category: 'secret',
    severity: 'critical',
    pattern: /AKIA[0-9A-Z]{16}/,
  },
];

// ============================================================================
// Local Scanner (uses built-in patterns)
// ============================================================================

export class LocalScanner implements Scanner {
  private patterns: Pattern[];

  constructor() {
    this.patterns = [...BUILTIN_PATTERNS];
  }

  async scan(content: string, config?: Partial<SecurityConfig>): Promise<ScanResult> {
    const startTime = Date.now();
    const threats: ThreatMatch[] = [];
    const severityOrder = ['low', 'medium', 'high', 'critical'];
    const minSeverityIndex = config?.minSeverity 
      ? severityOrder.indexOf(config.minSeverity) 
      : 0;

    for (const pattern of this.patterns) {
      // Filter by severity
      if (severityOrder.indexOf(pattern.severity) < minSeverityIndex) continue;

      // Filter by category
      if (config?.categories && !config.categories.includes(pattern.category)) continue;

      // Check pattern
      const match = content.match(pattern.pattern);
      if (match) {
        threats.push({
          patternId: pattern.id,
          patternName: pattern.name,
          category: pattern.category,
          severity: pattern.severity,
          confidence: 0.9,
          matchedText: match[0].substring(0, 50),
          mitreId: pattern.mitreId,
          mitreTactic: pattern.mitreTactic,
        });
      }
    }

    // Sort by severity
    threats.sort((a, b) => 
      severityOrder.indexOf(b.severity) - severityOrder.indexOf(a.severity)
    );

    const scanDurationMs = Date.now() - startTime;

    return {
      safe: threats.length === 0,
      threatCount: threats.length,
      threats,
      highestSeverity: threats.length > 0 ? threats[0].severity : null,
      scanDurationMs,
      recommendations: threats.length > 0 
        ? [`Found ${threats.length} potential threat(s). Review flagged content.`]
        : [],
    };
  }

  async scanBatch(contents: string[], config?: Partial<SecurityConfig>): Promise<ScanResult[]> {
    return Promise.all(contents.map(c => this.scan(c, config)));
  }
}

// ============================================================================
// Remote Scanner (uses Mund API)
// ============================================================================

export class RemoteScanner implements Scanner {
  private endpoint: string;
  private apiKey?: string;

  constructor(endpoint: string, apiKey?: string) {
    this.endpoint = endpoint.replace(/\/$/, '');
    this.apiKey = apiKey;
  }

  async scan(content: string, config?: Partial<SecurityConfig>): Promise<ScanResult> {
    const startTime = Date.now();

    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };
      if (this.apiKey) {
        headers['Authorization'] = `Bearer ${this.apiKey}`;
      }

      const response = await fetch(`${this.endpoint}/mund/scan`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          content,
          categories: config?.categories,
          minSeverity: config?.minSeverity,
        }),
      });

      if (!response.ok) {
        throw new Error(`Mund API error: ${response.statusText}`);
      }

      const data = await response.json() as {
        matches?: Array<{
          patternId: string;
          patternName: string;
          category: string;
          severity: string;
          confidence: number;
          matchedText: string;
          mitreId?: string;
          mitreTactic?: string;
        }>;
        summary?: {
          highest_severity?: string;
        };
        recommendations?: string[];
      };

      const threats: ThreatMatch[] = (data.matches || []).map(m => ({
        patternId: m.patternId,
        patternName: m.patternName,
        category: m.category,
        severity: m.severity as ThreatMatch['severity'],
        confidence: m.confidence,
        matchedText: m.matchedText,
        mitreId: m.mitreId,
        mitreTactic: m.mitreTactic,
      }));

      return {
        safe: threats.length === 0,
        threatCount: threats.length,
        threats,
        highestSeverity: (data.summary?.highest_severity as ThreatMatch['severity']) || null,
        scanDurationMs: Date.now() - startTime,
        recommendations: data.recommendations || [],
      };
    } catch (error) {
      // Fallback to local scanner on error
      console.warn('Remote scan failed, falling back to local scanner:', error);
      const localScanner = new LocalScanner();
      return localScanner.scan(content, config);
    }
  }

  async scanBatch(contents: string[], config?: Partial<SecurityConfig>): Promise<ScanResult[]> {
    return Promise.all(contents.map(c => this.scan(c, config)));
  }
}

// ============================================================================
// Scanner Factory
// ============================================================================

export function createScanner(options?: {
  endpoint?: string;
  apiKey?: string;
}): Scanner {
  if (options?.endpoint) {
    return new RemoteScanner(options.endpoint, options.apiKey);
  }
  return new LocalScanner();
}
