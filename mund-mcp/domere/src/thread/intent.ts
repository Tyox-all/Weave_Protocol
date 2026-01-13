/**
 * Dōmere - The Judge Protocol
 * Intent Analysis
 */

import type { IntentClassification, ExtractedEntity } from '../types.js';
import { INTENT_KEYWORDS } from '../constants.js';

// ============================================================================
// Intent Analyzer
// ============================================================================

export interface IntentAnalysisResult {
  raw: string;
  normalized: string;
  classification: IntentClassification;
  confidence: number;
  
  // Decomposition
  action_verb?: string;
  target_object?: string;
  modifiers: string[];
  constraints: string[];
  
  // Semantic
  entities: ExtractedEntity[];
  scope: 'narrow' | 'medium' | 'broad';
  complexity: 'simple' | 'moderate' | 'complex';
}

export class IntentAnalyzer {
  /**
   * Analyze intent
   */
  analyze(intent: string): IntentAnalysisResult {
    const normalized = this.normalize(intent);
    const classification = this.classify(normalized);
    const { actionVerb, targetObject, modifiers } = this.decompose(normalized);
    const constraints = this.extractConstraints(intent);
    const scope = this.assessScope(intent);
    const complexity = this.assessComplexity(intent);
    
    return {
      raw: intent,
      normalized,
      classification: classification.classification,
      confidence: classification.confidence,
      action_verb: actionVerb,
      target_object: targetObject,
      modifiers,
      constraints,
      entities: this.extractEntities(intent),
      scope,
      complexity,
    };
  }
  
  /**
   * Normalize intent text
   */
  normalize(intent: string): string {
    return intent
      .toLowerCase()
      .replace(/\s+/g, ' ')           // Normalize whitespace
      .replace(/[^\w\s.,!?'-]/g, '')  // Remove special chars
      .replace(/please\s+/gi, '')     // Remove politeness
      .replace(/can you\s+/gi, '')
      .replace(/could you\s+/gi, '')
      .replace(/would you\s+/gi, '')
      .replace(/i want you to\s+/gi, '')
      .replace(/i need you to\s+/gi, '')
      .replace(/i'd like you to\s+/gi, '')
      .trim();
  }
  
  /**
   * Classify intent
   */
  classify(normalizedIntent: string): { classification: IntentClassification; confidence: number } {
    const scores: Record<IntentClassification, number> = {
      query: 0,
      mutation: 0,
      deletion: 0,
      execution: 0,
      communication: 0,
      analysis: 0,
      generation: 0,
      unknown: 0,
    };
    
    // Score based on keywords
    for (const [intent, keywords] of Object.entries(INTENT_KEYWORDS)) {
      for (const keyword of keywords) {
        const regex = new RegExp(`\\b${keyword}\\b`, 'gi');
        const matches = normalizedIntent.match(regex);
        if (matches) {
          scores[intent as IntentClassification] += matches.length * 2;
        }
      }
    }
    
    // Check question patterns (strong signal for query)
    if (/^(what|where|who|when|how|why|which|is|are|do|does|can|could)\b/i.test(normalizedIntent)) {
      scores.query += 3;
    }
    
    // Find highest
    let maxClassification: IntentClassification = 'unknown';
    let maxScore = 0;
    let totalScore = 0;
    
    for (const [classification, score] of Object.entries(scores)) {
      totalScore += score;
      if (score > maxScore) {
        maxScore = score;
        maxClassification = classification as IntentClassification;
      }
    }
    
    const confidence = totalScore > 0 ? maxScore / totalScore : 0;
    
    return { classification: maxClassification, confidence };
  }
  
  /**
   * Decompose intent into components
   */
  decompose(normalizedIntent: string): {
    actionVerb?: string;
    targetObject?: string;
    modifiers: string[];
  } {
    const words = normalizedIntent.split(' ');
    let actionVerb: string | undefined;
    let targetObject: string | undefined;
    const modifiers: string[] = [];
    
    // Common action verbs
    const actionVerbs = [
      'get', 'fetch', 'find', 'search', 'retrieve', 'show', 'display', 'list',
      'create', 'make', 'generate', 'build', 'add', 'insert',
      'update', 'change', 'modify', 'edit', 'set',
      'delete', 'remove', 'drop', 'clear',
      'send', 'email', 'message', 'notify',
      'analyze', 'summarize', 'explain', 'compare',
      'run', 'execute', 'start', 'launch',
    ];
    
    // Find action verb
    for (const word of words) {
      if (actionVerbs.includes(word)) {
        actionVerb = word;
        break;
      }
    }
    
    // Find target (noun after action verb)
    if (actionVerb) {
      const verbIndex = words.indexOf(actionVerb);
      if (verbIndex < words.length - 1) {
        // Look for noun phrase after verb
        const afterVerb = words.slice(verbIndex + 1);
        
        // Skip articles and prepositions
        const skipWords = ['the', 'a', 'an', 'to', 'for', 'from', 'in', 'on', 'at'];
        const targetWords: string[] = [];
        
        for (const word of afterVerb) {
          if (skipWords.includes(word)) continue;
          // Stop at conjunctions or prepositions that indicate end of target
          if (['and', 'or', 'but', 'with', 'using', 'by'].includes(word)) break;
          targetWords.push(word);
          if (targetWords.length >= 3) break;  // Limit target length
        }
        
        targetObject = targetWords.join(' ');
      }
    }
    
    // Extract modifiers (adjectives, adverbs)
    const modifierPatterns = [
      /\b(all|every|each|any|some|no)\b/gi,
      /\b(new|old|latest|recent|current)\b/gi,
      /\b(first|last|top|bottom)\s+\d+/gi,
      /\b(quickly|slowly|carefully|automatically)\b/gi,
      /\b(daily|weekly|monthly|yearly)\b/gi,
    ];
    
    for (const pattern of modifierPatterns) {
      const matches = normalizedIntent.match(pattern);
      if (matches) {
        modifiers.push(...matches);
      }
    }
    
    return { actionVerb, targetObject, modifiers };
  }
  
  /**
   * Extract constraints from intent
   */
  extractConstraints(intent: string): string[] {
    const constraints: string[] = [];
    const intentLower = intent.toLowerCase();
    
    // Explicit negations
    const negationPatterns = [
      /\b(don't|do not|never|without)\s+([^.,]+)/gi,
      /\b(except|excluding|other than)\s+([^.,]+)/gi,
      /\b(but not|not including)\s+([^.,]+)/gi,
    ];
    
    for (const pattern of negationPatterns) {
      let match;
      while ((match = pattern.exec(intentLower)) !== null) {
        constraints.push(`NOT: ${match[2].trim()}`);
      }
    }
    
    // Scope limitations
    const scopePatterns = [
      /\b(only|just|specifically)\s+([^.,]+)/gi,
      /\b(limited to|restricted to)\s+([^.,]+)/gi,
    ];
    
    for (const pattern of scopePatterns) {
      let match;
      while ((match = pattern.exec(intentLower)) !== null) {
        constraints.push(`ONLY: ${match[2].trim()}`);
      }
    }
    
    // Time constraints
    const timePatterns = [
      /\b(before|after|since|until)\s+([^.,]+)/gi,
      /\b(within|in the last|in the next)\s+(\d+\s+\w+)/gi,
    ];
    
    for (const pattern of timePatterns) {
      let match;
      while ((match = pattern.exec(intentLower)) !== null) {
        constraints.push(`TIME: ${match[0].trim()}`);
      }
    }
    
    // Quantity constraints
    const quantityPatterns = [
      /\b(at most|at least|exactly|no more than|no less than)\s+(\d+)/gi,
      /\b(maximum|minimum|limit)\s+(?:of\s+)?(\d+)/gi,
    ];
    
    for (const pattern of quantityPatterns) {
      let match;
      while ((match = pattern.exec(intentLower)) !== null) {
        constraints.push(`QUANTITY: ${match[0].trim()}`);
      }
    }
    
    return constraints;
  }
  
  /**
   * Extract entities from intent
   */
  extractEntities(intent: string): ExtractedEntity[] {
    const entities: ExtractedEntity[] = [];
    
    // Quoted strings (often specific values)
    const quotedPattern = /["']([^"']+)["']/g;
    let match;
    while ((match = quotedPattern.exec(intent)) !== null) {
      entities.push({
        type: 'custom',
        value: match[1],
        confidence: 0.9,
        position: { start: match.index, end: match.index + match[0].length },
      });
    }
    
    // Numbers with context
    const numberPattern = /\b(\d+(?:,\d{3})*(?:\.\d+)?)\s*(\w+)?/g;
    while ((match = numberPattern.exec(intent)) !== null) {
      const value = match[1];
      const unit = match[2];
      entities.push({
        type: 'quantity',
        value: unit ? `${value} ${unit}` : value,
        confidence: 0.8,
        position: { start: match.index, end: match.index + match[0].length },
      });
    }
    
    // Capitalized words (potential proper nouns)
    const properNounPattern = /\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\b/g;
    while ((match = properNounPattern.exec(intent)) !== null) {
      // Skip if at start of sentence
      if (match.index === 0) continue;
      entities.push({
        type: 'custom',
        value: match[1],
        confidence: 0.6,
        position: { start: match.index, end: match.index + match[0].length },
      });
    }
    
    return entities;
  }
  
  /**
   * Assess scope of intent
   */
  assessScope(intent: string): 'narrow' | 'medium' | 'broad' {
    const intentLower = intent.toLowerCase();
    
    // Narrow scope indicators
    if (/\b(specific|particular|this|that|single|one)\b/.test(intentLower)) {
      return 'narrow';
    }
    if (/"[^"]+"/.test(intent)) {  // Quoted specific values
      return 'narrow';
    }
    
    // Broad scope indicators
    if (/\b(all|every|entire|whole|complete|everything)\b/.test(intentLower)) {
      return 'broad';
    }
    
    return 'medium';
  }
  
  /**
   * Assess complexity of intent
   */
  assessComplexity(intent: string): 'simple' | 'moderate' | 'complex' {
    const words = intent.split(/\s+/).length;
    const clauses = intent.split(/[,;]/).length;
    const conjunctions = (intent.match(/\b(and|or|but|then|after|before|while)\b/gi) || []).length;
    
    // Simple: short, single clause
    if (words < 10 && clauses === 1 && conjunctions === 0) {
      return 'simple';
    }
    
    // Complex: long, multiple clauses, multiple conjunctions
    if (words > 30 || clauses > 3 || conjunctions > 2) {
      return 'complex';
    }
    
    return 'moderate';
  }
  
  /**
   * Compare two intents for similarity
   */
  compareIntents(intent1: string, intent2: string): number {
    const norm1 = this.normalize(intent1);
    const norm2 = this.normalize(intent2);
    
    // Simple word overlap similarity
    const words1 = new Set(norm1.split(' '));
    const words2 = new Set(norm2.split(' '));
    
    const intersection = new Set([...words1].filter(w => words2.has(w)));
    const union = new Set([...words1, ...words2]);
    
    return intersection.size / union.size;
  }
  
  /**
   * Check if intent2 is within scope of intent1
   */
  isWithinScope(originalIntent: string, derivedIntent: string): boolean {
    const original = this.analyze(originalIntent);
    const derived = this.analyze(derivedIntent);
    
    // Check if classification matches
    if (original.classification !== derived.classification && 
        original.classification !== 'unknown') {
      return false;
    }
    
    // Check if target is related
    if (original.target_object && derived.target_object) {
      if (!derived.target_object.includes(original.target_object) &&
          !original.target_object.includes(derived.target_object)) {
        // Targets are unrelated
        return false;
      }
    }
    
    // Check constraints
    for (const constraint of original.constraints) {
      if (constraint.startsWith('NOT:')) {
        const forbidden = constraint.slice(5).toLowerCase();
        if (derived.raw.toLowerCase().includes(forbidden)) {
          return false;
        }
      }
    }
    
    // Check scope hasn't expanded
    const scopeOrder = ['narrow', 'medium', 'broad'];
    if (scopeOrder.indexOf(derived.scope) > scopeOrder.indexOf(original.scope)) {
      return false;
    }
    
    return true;
  }
}
