/**
 * Mund - The Guardian Protocol
 * Analyzers Index - Exports all analyzer modules
 */

export { SecretScanner } from './secret-scanner.js';
export { PIIDetector } from './pii-detector.js';
export { CodeAnalyzer } from './code-analyzer.js';
export { InjectionDetector } from './injection-detector.js';
export { ExfiltrationDetector } from './exfiltration-detector.js';

import { SecretScanner } from './secret-scanner.js';
import { PIIDetector } from './pii-detector.js';
import { CodeAnalyzer } from './code-analyzer.js';
import { InjectionDetector } from './injection-detector.js';
import { ExfiltrationDetector } from './exfiltration-detector.js';
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
    new ExfiltrationDetector()
  ];
}

/**
 * Create analyzer engine that runs all analyzers
 */
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

    // Sort by severity (critical first)
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    allIssues.sort((a, b) => 
      (severityOrder[a.severity] || 4) - (severityOrder[b.severity] || 4)
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
