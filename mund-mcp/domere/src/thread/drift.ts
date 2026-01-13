/**
 * Dōmere - The Judge Protocol
 * Intent Drift Detection
 */

import type { DriftAnalysis, DriftMetrics } from '../types.js';
import { DEFAULT_CONFIG } from '../constants.js';
import { IntentAnalyzer } from './intent.js';

// ============================================================================
// Drift Detector
// ============================================================================

export class DriftDetector {
  private intentAnalyzer: IntentAnalyzer;
  private maxDrift: number;
  private warnThreshold: number;
  
  constructor(config?: { maxDrift?: number; warnThreshold?: number }) {
    this.intentAnalyzer = new IntentAnalyzer();
    this.maxDrift = config?.maxDrift || DEFAULT_CONFIG.drift.max_acceptable_drift;
    this.warnThreshold = config?.warnThreshold || DEFAULT_CONFIG.drift.warn_threshold;
  }
  
  /**
   * Analyze drift between original and current intent
   */
  analyze(config: {
    original_intent: string;
    previous_intent: string;
    current_intent: string;
    constraints: string[];
    hop_number: number;
  }): DriftAnalysis {
    const metrics = this.calculateMetrics(
      config.original_intent,
      config.current_intent,
      config.constraints
    );
    
    const hopDrift = this.calculateHopDrift(
      config.previous_intent,
      config.current_intent
    );
    
    const cumulativeDrift = this.calculateCumulativeDrift(metrics, config.hop_number);
    
    const constraintViolations = this.checkConstraintViolations(
      config.current_intent,
      config.constraints
    );
    
    const verdict = this.determineVerdict(
      cumulativeDrift,
      hopDrift,
      constraintViolations
    );
    
    return {
      original_intent: config.original_intent,
      current_interpretation: config.current_intent,
      metrics,
      cumulative_drift: cumulativeDrift,
      hop_drift: hopDrift,
      max_acceptable_drift: this.maxDrift,
      verdict,
      explanation: this.generateExplanation(verdict, metrics, constraintViolations),
      constraint_violations: constraintViolations,
    };
  }
  
  /**
   * Calculate drift metrics
   */
  calculateMetrics(
    originalIntent: string,
    currentIntent: string,
    constraints: string[]
  ): DriftMetrics {
    return {
      semantic_similarity: this.calculateSemanticSimilarity(originalIntent, currentIntent),
      action_alignment: this.calculateActionAlignment(originalIntent, currentIntent),
      scope_creep: this.calculateScopeCreep(originalIntent, currentIntent),
      entity_preservation: this.calculateEntityPreservation(originalIntent, currentIntent),
      constraint_adherence: this.calculateConstraintAdherence(currentIntent, constraints),
    };
  }
  
  private calculateSemanticSimilarity(intent1: string, intent2: string): number {
    const norm1 = this.intentAnalyzer.normalize(intent1);
    const norm2 = this.intentAnalyzer.normalize(intent2);
    
    const words1 = new Set(norm1.split(' ').filter(w => w.length > 2));
    const words2 = new Set(norm2.split(' ').filter(w => w.length > 2));
    
    if (words1.size === 0 && words2.size === 0) return 1;
    if (words1.size === 0 || words2.size === 0) return 0;
    
    const intersection = new Set([...words1].filter(w => words2.has(w)));
    const union = new Set([...words1, ...words2]);
    
    const jaccardSimilarity = intersection.size / union.size;
    
    const bigrams1 = this.getBigrams(norm1);
    const bigrams2 = this.getBigrams(norm2);
    
    const bigramIntersection = new Set([...bigrams1].filter(b => bigrams2.has(b)));
    const bigramUnion = new Set([...bigrams1, ...bigrams2]);
    
    const bigramSimilarity = bigramUnion.size > 0 
      ? bigramIntersection.size / bigramUnion.size 
      : 0;
    
    return jaccardSimilarity * 0.6 + bigramSimilarity * 0.4;
  }
  
  private calculateActionAlignment(originalIntent: string, currentIntent: string): number {
    const original = this.intentAnalyzer.analyze(originalIntent);
    const current = this.intentAnalyzer.analyze(currentIntent);
    
    let alignment = 0;
    
    if (original.classification === current.classification) {
      alignment += 0.4;
    } else if (this.areRelatedClassifications(original.classification, current.classification)) {
      alignment += 0.2;
    }
    
    if (original.action_verb && current.action_verb) {
      if (original.action_verb === current.action_verb) {
        alignment += 0.3;
      } else if (this.areSynonymVerbs(original.action_verb, current.action_verb)) {
        alignment += 0.2;
      }
    } else if (!original.action_verb && !current.action_verb) {
      alignment += 0.3;
    }
    
    if (original.target_object && current.target_object) {
      const targetSimilarity = this.calculateWordSimilarity(
        original.target_object,
        current.target_object
      );
      alignment += targetSimilarity * 0.3;
    } else if (!original.target_object && !current.target_object) {
      alignment += 0.3;
    }
    
    return Math.min(1, alignment);
  }
  
  private calculateScopeCreep(originalIntent: string, currentIntent: string): number {
    const original = this.intentAnalyzer.analyze(originalIntent);
    const current = this.intentAnalyzer.analyze(currentIntent);
    
    const scopeValues: Record<string, number> = {
      'narrow': -1,
      'medium': 0,
      'broad': 1,
    };
    
    const originalScope = scopeValues[original.scope];
    const currentScope = scopeValues[current.scope];
    
    return 0.5 + (currentScope - originalScope) * 0.25;
  }
  
  private calculateEntityPreservation(originalIntent: string, currentIntent: string): number {
    const original = this.intentAnalyzer.analyze(originalIntent);
    const current = this.intentAnalyzer.analyze(currentIntent);
    
    if (original.entities.length === 0) return 1;
    
    const originalValues = new Set(original.entities.map(e => e.value.toLowerCase()));
    const currentLower = currentIntent.toLowerCase();
    
    let preserved = 0;
    for (const value of originalValues) {
      if (currentLower.includes(value)) {
        preserved++;
      }
    }
    
    return preserved / originalValues.size;
  }
  
  private calculateConstraintAdherence(currentIntent: string, constraints: string[]): number {
    if (constraints.length === 0) return 1;
    
    const violations = this.checkConstraintViolations(currentIntent, constraints);
    
    return 1 - (violations.length / constraints.length);
  }
  
  private checkConstraintViolations(currentIntent: string, constraints: string[]): string[] {
    const violations: string[] = [];
    const currentLower = currentIntent.toLowerCase();
    
    for (const constraint of constraints) {
      if (constraint.startsWith('NOT:')) {
        const forbidden = constraint.slice(5).toLowerCase().trim();
        if (currentLower.includes(forbidden)) {
          violations.push(constraint);
        }
      }
    }
    
    return violations;
  }
  
  private calculateHopDrift(previousIntent: string, currentIntent: string): number {
    const similarity = this.calculateSemanticSimilarity(previousIntent, currentIntent);
    return 1 - similarity;
  }
  
  private calculateCumulativeDrift(metrics: DriftMetrics, hopNumber: number): number {
    const baseDrift = 
      (1 - metrics.semantic_similarity) * 0.3 +
      (1 - metrics.action_alignment) * 0.25 +
      Math.abs(metrics.scope_creep - 0.5) * 0.15 +
      (1 - metrics.entity_preservation) * 0.15 +
      (1 - metrics.constraint_adherence) * 0.15;
    
    const hopFactor = 1 + (hopNumber - 1) * 0.1;
    
    return Math.min(1, baseDrift * hopFactor);
  }
  
  private determineVerdict(
    cumulativeDrift: number,
    hopDrift: number,
    constraintViolations: string[]
  ): 'aligned' | 'minor_drift' | 'significant_drift' | 'violated' {
    if (constraintViolations.length > 0) return 'violated';
    if (cumulativeDrift > this.maxDrift) return 'violated';
    if (cumulativeDrift > this.warnThreshold || hopDrift > this.warnThreshold * 1.5) return 'significant_drift';
    if (cumulativeDrift > this.warnThreshold * 0.5 || hopDrift > this.warnThreshold) return 'minor_drift';
    return 'aligned';
  }
  
  private generateExplanation(
    verdict: string,
    metrics: DriftMetrics,
    constraintViolations: string[]
  ): string {
    const parts: string[] = [];
    
    if (verdict === 'aligned') {
      parts.push('Intent preserved through this hop.');
    } else if (verdict === 'violated') {
      if (constraintViolations.length > 0) {
        parts.push(`Constraint violations: ${constraintViolations.join(', ')}`);
      } else {
        parts.push('Intent has drifted beyond acceptable threshold.');
      }
    } else if (verdict === 'significant_drift') {
      parts.push('Significant drift detected.');
    } else {
      parts.push('Minor drift detected.');
    }
    
    if (metrics.semantic_similarity < 0.5) parts.push('Low semantic similarity.');
    if (metrics.action_alignment < 0.5) parts.push('Action type changed.');
    if (metrics.scope_creep > 0.7) parts.push('Scope expanded.');
    if (metrics.entity_preservation < 0.5) parts.push('Entities not preserved.');
    
    return parts.join(' ');
  }
  
  private getBigrams(text: string): Set<string> {
    const words = text.split(' ');
    const bigrams = new Set<string>();
    for (let i = 0; i < words.length - 1; i++) {
      bigrams.add(`${words[i]} ${words[i + 1]}`);
    }
    return bigrams;
  }
  
  private areRelatedClassifications(c1: string, c2: string): boolean {
    const related: Record<string, string[]> = {
      'query': ['analysis'],
      'analysis': ['query', 'generation'],
      'mutation': ['execution'],
      'execution': ['mutation'],
      'generation': ['analysis', 'communication'],
      'communication': ['generation'],
    };
    return related[c1]?.includes(c2) || related[c2]?.includes(c1);
  }
  
  private areSynonymVerbs(v1: string, v2: string): boolean {
    const synonymGroups = [
      ['get', 'fetch', 'retrieve', 'find', 'search', 'lookup'],
      ['create', 'make', 'generate', 'build', 'add'],
      ['update', 'change', 'modify', 'edit', 'set'],
      ['delete', 'remove', 'drop', 'clear', 'erase'],
      ['send', 'email', 'message', 'notify'],
      ['analyze', 'examine', 'review', 'assess'],
    ];
    
    for (const group of synonymGroups) {
      if (group.includes(v1) && group.includes(v2)) return true;
    }
    return false;
  }
  
  private calculateWordSimilarity(word1: string, word2: string): number {
    if (word1 === word2) return 1;
    if (word1.includes(word2) || word2.includes(word1)) return 0.8;
    
    const chars1 = new Set(word1.toLowerCase().split(''));
    const chars2 = new Set(word2.toLowerCase().split(''));
    
    const intersection = new Set([...chars1].filter(c => chars2.has(c)));
    const union = new Set([...chars1, ...chars2]);
    
    return intersection.size / union.size;
  }
}
