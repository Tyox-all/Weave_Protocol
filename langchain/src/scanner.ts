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
  /** Extra check on each regex match, to cut false positives (e.g. Luhn) */
  validate?: (match: string) => boolean;
}

/** Luhn checksum, so random 13–19 digit numbers aren't reported as cards. */
function luhn(match: string): boolean {
  const digits = match.replace(/\D/g, '');
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return digits.length >= 13 && sum % 10 === 0;
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
    // "DAN" only in capitals: the name Dan is not a jailbreak
    pattern: /\bDAN\b|\b[Dd]o\s+[Aa]nything\s+[Nn]ow\b/,
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
    // Visa, Mastercard, Amex; digits may be grouped with spaces or dashes
    pattern: /\b(?:4\d{3}(?:[ -]?\d{4}){2}[ -]?\d{1,4}|5[1-5]\d{2}(?:[ -]?\d{4}){3}|3[47]\d{2}[ -]?\d{6}[ -]?\d{5})\b/g,
    validate: luhn,
  },
  
  // Secrets
  {
    id: 'secret_openai',
    name: 'OpenAI API Key',
    category: 'secret',
    severity: 'critical',
    // Legacy keys and current project, service-account and admin keys
    pattern: /\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/,
  },
  {
    id: 'secret_anthropic',
    name: 'Anthropic API Key',
    category: 'secret',
    severity: 'critical',
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}/,
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

      // Check pattern (the first match that passes validation)
      const re = new RegExp(pattern.pattern.source, pattern.pattern.flags.includes('g') ? pattern.pattern.flags : pattern.pattern.flags + 'g');
      const match = [...content.matchAll(re)].find((m) => !pattern.validate || pattern.validate(m[0]));
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
// Remote Scanner (uses the Weave API's Mund scan)
// ============================================================================

const SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;

/**
 * Scans through a running @weave_protocol/api. `endpoint` is the API's base
 * URL (http://host:3000) or its /api/v1 prefix. Any failure, or a response
 * that doesn't look like a scan result, falls back to the local scanner, so
 * content is never passed as safe because the remote call went wrong.
 * (Before 1.1.0 this posted to /mund/scan and read a `matches` array the API
 * never returns, so a reachable API reported every scan as safe.)
 */
export class RemoteScanner implements Scanner {
  private url: string;
  private apiKey?: string;

  constructor(endpoint: string, apiKey?: string) {
    const base = endpoint.replace(/\/+$/, '');
    this.url = /\/api\/v1$/.test(base) ? `${base}/mund/scan` : `${base}/api/v1/mund/scan`;
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

      const response = await fetch(this.url, {
        method: 'POST',
        headers,
        body: JSON.stringify({ content }),
      });

      if (!response.ok) {
        throw new Error(`Mund API error: ${response.status} ${response.statusText}`);
      }

      const data = (await response.json()) as {
        issues?: Array<{ rule_id: string; rule_name: string; type: string; severity: string; match?: string }>;
      };
      if (!Array.isArray(data.issues)) {
        throw new Error('Mund API response has no issues array');
      }

      const minIndex = config?.minSeverity ? SEVERITIES.indexOf(config.minSeverity) : 0;
      const threats: ThreatMatch[] = data.issues
        .map((i) => ({
          patternId: i.rule_id,
          patternName: i.rule_name,
          category: i.type,
          severity: (SEVERITIES as readonly string[]).includes(i.severity) ? (i.severity as ThreatMatch['severity']) : 'high',
          confidence: 1,
          matchedText: String(i.match ?? '').substring(0, 50),
        }))
        .filter((t) => SEVERITIES.indexOf(t.severity) >= minIndex)
        .filter((t) => !config?.categories || config.categories.includes(t.category))
        .sort((a, b) => SEVERITIES.indexOf(b.severity) - SEVERITIES.indexOf(a.severity));

      return {
        safe: threats.length === 0,
        threatCount: threats.length,
        threats,
        highestSeverity: threats[0]?.severity ?? null,
        scanDurationMs: Date.now() - startTime,
        recommendations: threats.length > 0 ? [`Found ${threats.length} potential threat(s). Review flagged content.`] : [],
      };
    } catch (error) {
      // Fall back to the local scanner rather than pass content unscanned
      console.warn('Remote scan failed, falling back to local scanner:', error instanceof Error ? error.message : error);
      return new LocalScanner().scan(content, config);
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
