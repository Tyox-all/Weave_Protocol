/**
 * Mund - The Guardian Protocol
 * Analyzers Index - Exports all analyzer modules
 */

import { compileRulePattern } from './regex.js';
export { SecretScanner } from './secret-scanner.js';
export { PIIDetector } from './pii-detector.js';
export { CodeAnalyzer } from './code-analyzer.js';
export { InjectionDetector } from './injection-detector.js';
export { ExfiltrationDetector } from './exfiltration-detector.js';
export { McpServerAnalyzer } from './mcp-server-analyzer.js';

import { SecretScanner } from './secret-scanner.js';
import { PIIDetector } from './pii-detector.js';
import { CodeAnalyzer } from './code-analyzer.js';
import { InjectionDetector } from './injection-detector.js';
import { ExfiltrationDetector } from './exfiltration-detector.js';
import { McpServerAnalyzer } from './mcp-server-analyzer.js';
import { CanaryDetector } from '../canary.js';
import type { IAnalyzer } from '../types.js';

/**
 * Get all available analyzers
 */
export function getAnalyzers(): IAnalyzer[] {
  return [
    new SecretScanner(),
    new PIIDetector(),
    new CodeAnalyzer(),
    new InjectionDetector(),
    new ExfiltrationDetector(),
    new McpServerAnalyzer(),
    new CanaryDetector()
  ];
}

/**
 * Create analyzer engine that runs all analyzers
 */
/** Every secret and PII value the content's secret and PII rules match. */
export function sensitiveValues(content: string, rules: import('../types.js').DetectionRule[]): string[] {
  const out = new Set<string>();
  for (const r of rules) {
    if ((r.type !== 'secret' && r.type !== 'pii') || !r.enabled || !r.pattern) continue;
    try {
      const re = compileRulePattern(r.pattern, 'g');
      for (const m of content.matchAll(re)) if (m[0].length >= 4) out.add(m[0]);
    } catch { /* invalid custom rule */ }
  }
  return [...out].sort((a, b) => b.length - a.length);
}

/** Replace sensitive values in an excerpt, including one cut off by truncation. */
export function redactValues(excerpt: string, values: string[]): string {
  let out = excerpt;
  for (const v of values) out = out.split(v).join('[REDACTED]');
  if (out.endsWith('...')) {
    const body = out.slice(0, -3);
    for (const v of values) {
      for (let k = Math.min(v.length - 1, body.length); k >= 4; k--) {
        if (body.endsWith(v.slice(0, k))) return body.slice(0, body.length - k) + '[REDACTED]...';
      }
    }
  }
  return out;
}

export class AnalyzerEngine {
  private analyzers: IAnalyzer[];

  constructor(analyzers?: IAnalyzer[]) {
    this.analyzers = analyzers || getAnalyzers();
  }

  async analyzeAll(content: string, rules: import('../types.js').DetectionRule[]): Promise<import('../types.js').SecurityIssue[]> {
    const allIssues: import('../types.js').SecurityIssue[] = [];

    for (const analyzer of this.analyzers) {
      try {
        const issues = await analyzer.analyze(content, rules);
        allIssues.push(...issues);
      } catch (error) {
        console.error(`Error in analyzer ${analyzer.name}:`, error);
      }
    }

    // Findings are logged, stored and sent to webhooks. Secret and PII
    // findings mask their own matches; every other finding's excerpt must not
    // carry a secret or personal value from the content either.
    const values = sensitiveValues(content, rules);
    if (values.length) {
      for (const issue of allIssues) {
        if (issue.type !== 'secret' && issue.type !== 'pii' && issue.match) issue.match = redactValues(issue.match, values);
      }
    }

    // Sort by severity (critical first)
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    allIssues.sort((a, b) => 
      (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4)
    );

    return allIssues;
  }

  addAnalyzer(analyzer: IAnalyzer): void {
    this.analyzers.push(analyzer);
  }

  removeAnalyzer(name: string): void {
    this.analyzers = this.analyzers.filter(a => a.name !== name);
  }

  getAnalyzerNames(): string[] {
    return this.analyzers.map(a => a.name);
  }
}
