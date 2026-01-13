/**
 * Dōmere - The Judge Protocol
 * Semantic Analysis
 */

import type {
  SemanticAnalysis,
  ExtractedEntity,
  EntityType,
  IntentClassification,
} from '../types.js';
import { INTENT_KEYWORDS, ENTITY_PATTERNS } from '../constants.js';

// ============================================================================
// Semantic Analyzer
// ============================================================================

export class SemanticAnalyzer {
  /**
   * Perform semantic analysis on content
   */
  analyze(content: string): SemanticAnalysis {
    return {
      intent_classification: this.classifyIntent(content),
      entities: this.extractEntities(content),
      actions_implied: this.extractImpliedActions(content),
      topics: this.extractTopics(content),
      sentiment: this.analyzeSentiment(content),
      formality: this.analyzeFormality(content),
      urgency: this.analyzeUrgency(content),
    };
  }
  
  /**
   * Classify the intent of the content
   */
  classifyIntent(content: string): IntentClassification {
    const contentLower = content.toLowerCase();
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
        const matches = contentLower.match(regex);
        if (matches) {
          scores[intent as IntentClassification] += matches.length;
        }
      }
    }
    
    // Find highest scoring intent
    let maxIntent: IntentClassification = 'unknown';
    let maxScore = 0;
    
    for (const [intent, score] of Object.entries(scores)) {
      if (score > maxScore) {
        maxScore = score;
        maxIntent = intent as IntentClassification;
      }
    }
    
    // If no strong signal, check question patterns
    if (maxScore < 2) {
      if (/^(what|where|who|when|how|why|which|is|are|do|does|can|could|would|should)\b/i.test(content.trim())) {
        return 'query';
      }
    }
    
    return maxIntent;
  }
  
  /**
   * Extract entities from content
   */
  extractEntities(content: string): ExtractedEntity[] {
    const entities: ExtractedEntity[] = [];
    
    // Extract using patterns
    for (const [type, pattern] of Object.entries(ENTITY_PATTERNS)) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;
      
      while ((match = regex.exec(content)) !== null) {
        entities.push({
          type: type as EntityType,
          value: match[0],
          confidence: 0.9,
          position: { start: match.index, end: match.index + match[0].length },
        });
      }
    }
    
    // Extract potential names (capitalized words not at start of sentence)
    const namePattern = /(?<![.!?]\s)(?<!\n)\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\b/g;
    let match;
    while ((match = namePattern.exec(content)) !== null) {
      const value = match[1];
      if (!this.isCommonPhrase(value)) {
        entities.push({
          type: 'person',
          value,
          confidence: 0.6,
          position: { start: match.index, end: match.index + match[0].length },
        });
      }
    }
    
    // Extract database/table references
    const dbPattern = /\b(database|table|collection|schema|db)\s*[`'"]?(\w+)[`'"]?/gi;
    while ((match = dbPattern.exec(content)) !== null) {
      entities.push({
        type: match[1].toLowerCase() === 'table' ? 'table' : 'database',
        value: match[2],
        confidence: 0.85,
        position: { start: match.index, end: match.index + match[0].length },
      });
    }
    
    // Extract API endpoints
    const apiPattern = /(?:api|endpoint|route):\s*([^\s,]+)|\/api\/[\w/]+/gi;
    while ((match = apiPattern.exec(content)) !== null) {
      entities.push({
        type: 'api_endpoint',
        value: match[1] || match[0],
        confidence: 0.8,
        position: { start: match.index, end: match.index + match[0].length },
      });
    }
    
    // Remove duplicates
    return this.deduplicateEntities(entities);
  }
  
  /**
   * Extract implied actions from content
   */
  extractImpliedActions(content: string): string[] {
    const actions: string[] = [];
    const contentLower = content.toLowerCase();
    
    // Look for verb phrases
    const verbPatterns = [
      /\b(will|should|must|need to|want to|going to|have to)\s+(\w+(?:\s+\w+)?)/gi,
      /\b(please|kindly)?\s*(get|fetch|create|update|delete|send|run|execute|analyze|generate)\s+/gi,
      /\b(i want|i need|i'd like)\s+(?:to\s+)?(\w+)/gi,
    ];
    
    for (const pattern of verbPatterns) {
      let match;
      while ((match = pattern.exec(contentLower)) !== null) {
        const action = match[0].trim().replace(/^(please|kindly)\s*/i, '');
        if (action.length > 3 && !actions.includes(action)) {
          actions.push(action);
        }
      }
    }
    
    // Infer from intent keywords
    for (const [intent, keywords] of Object.entries(INTENT_KEYWORDS)) {
      for (const keyword of keywords) {
        if (contentLower.includes(keyword) && !actions.some(a => a.includes(keyword))) {
          actions.push(`${keyword} data/content`);
          break;
        }
      }
    }
    
    return actions.slice(0, 10);
  }
  
  /**
   * Extract topics from content
   */
  extractTopics(content: string): string[] {
    const topics: string[] = [];
    const contentLower = content.toLowerCase();
    
    // Domain-specific topic detection
    const topicPatterns: Record<string, RegExp[]> = {
      'sales': [/\b(sales|revenue|quota|deal|pipeline|forecast)\b/gi],
      'customer': [/\b(customer|client|account|user|subscriber)\b/gi],
      'finance': [/\b(finance|budget|expense|cost|profit|invoice|payment)\b/gi],
      'hr': [/\b(employee|staff|hire|recruit|payroll|benefits|performance)\b/gi],
      'marketing': [/\b(marketing|campaign|lead|conversion|engagement|brand)\b/gi],
      'product': [/\b(product|feature|release|roadmap|backlog|sprint)\b/gi],
      'engineering': [/\b(code|deploy|bug|fix|release|infrastructure|api)\b/gi],
      'security': [/\b(security|password|auth|permission|access|credential)\b/gi],
      'data': [/\b(data|database|query|report|analytics|metrics)\b/gi],
      'support': [/\b(support|ticket|issue|help|resolve|escalat)\b/gi],
    };
    
    for (const [topic, patterns] of Object.entries(topicPatterns)) {
      for (const pattern of patterns) {
        if (pattern.test(contentLower)) {
          if (!topics.includes(topic)) {
            topics.push(topic);
          }
          break;
        }
      }
    }
    
    return topics;
  }
  
  /**
   * Analyze sentiment (-1 to 1)
   */
  analyzeSentiment(content: string): number {
    const contentLower = content.toLowerCase();
    
    const positiveWords = [
      'good', 'great', 'excellent', 'amazing', 'wonderful', 'fantastic', 'love',
      'like', 'happy', 'pleased', 'thank', 'thanks', 'appreciate', 'helpful',
      'perfect', 'awesome', 'brilliant', 'success', 'successful', 'best',
    ];
    
    const negativeWords = [
      'bad', 'terrible', 'awful', 'horrible', 'hate', 'dislike', 'angry',
      'frustrated', 'annoyed', 'disappointed', 'fail', 'failed', 'failure',
      'wrong', 'error', 'problem', 'issue', 'bug', 'broken', 'worst',
    ];
    
    let positiveCount = 0;
    let negativeCount = 0;
    
    for (const word of positiveWords) {
      const regex = new RegExp(`\\b${word}\\b`, 'gi');
      const matches = contentLower.match(regex);
      if (matches) positiveCount += matches.length;
    }
    
    for (const word of negativeWords) {
      const regex = new RegExp(`\\b${word}\\b`, 'gi');
      const matches = contentLower.match(regex);
      if (matches) negativeCount += matches.length;
    }
    
    // Check for negation
    const negationPattern = /\b(not|no|never|don't|doesn't|didn't|won't|wouldn't|can't|couldn't)\s+\w+/gi;
    const negations = contentLower.match(negationPattern)?.length || 0;
    
    const total = positiveCount + negativeCount;
    if (total === 0) return 0;
    
    let sentiment = (positiveCount - negativeCount) / total;
    
    // Adjust for negations
    if (negations > 0) {
      sentiment *= 0.5;
    }
    
    return Math.max(-1, Math.min(1, sentiment));
  }
  
  /**
   * Analyze formality (0 to 1)
   */
  analyzeFormality(content: string): number {
    const contentLower = content.toLowerCase();
    
    // Informal indicators
    const informalPatterns = [
      /\b(gonna|wanna|gotta|kinda|sorta|y'all|ain't)\b/gi,
      /\b(lol|lmao|omg|wtf|btw|fyi|imo|imho)\b/gi,
      /!{2,}/g,
      /\?{2,}/g,
      /\.{3,}/g,
      /\b(hey|hi|yo|sup)\b/gi,
    ];
    
    // Formal indicators
    const formalPatterns = [
      /\b(hereby|therefore|whereas|pursuant|accordingly)\b/gi,
      /\b(please|kindly|respectfully|sincerely)\b/gi,
      /\b(regarding|concerning|pertaining|with respect to)\b/gi,
      /\b(Dear|Sir|Madam|Mr\.|Mrs\.|Ms\.|Dr\.)\b/g,
    ];
    
    let informalCount = 0;
    let formalCount = 0;
    
    for (const pattern of informalPatterns) {
      const matches = contentLower.match(pattern);
      if (matches) informalCount += matches.length;
    }
    
    for (const pattern of formalPatterns) {
      const matches = content.match(pattern);
      if (matches) formalCount += matches.length;
    }
    
    // Calculate average sentence length (longer = more formal)
    const sentences = content.split(/[.!?]+/).filter(s => s.trim().length > 0);
    const avgSentenceLength = sentences.length > 0
      ? sentences.reduce((sum, s) => sum + s.split(/\s+/).length, 0) / sentences.length
      : 0;
    
    // Normalize
    let formality = 0.5;
    
    if (formalCount > 0 || informalCount > 0) {
      formality += (formalCount - informalCount) * 0.1;
    }
    
    if (avgSentenceLength > 15) {
      formality += 0.1;
    } else if (avgSentenceLength < 8) {
      formality -= 0.1;
    }
    
    return Math.max(0, Math.min(1, formality));
  }
  
  /**
   * Analyze urgency (0 to 1)
   */
  analyzeUrgency(content: string): number {
    const contentLower = content.toLowerCase();
    
    const urgentPatterns = [
      { pattern: /\b(urgent|asap|immediately|right now|right away)\b/gi, weight: 0.3 },
      { pattern: /\b(critical|emergency|priority|important)\b/gi, weight: 0.2 },
      { pattern: /\b(deadline|due|by end of day|eod|cob)\b/gi, weight: 0.15 },
      { pattern: /\b(need|must|have to|required)\b/gi, weight: 0.1 },
      { pattern: /!+/g, weight: 0.05 },
      { pattern: /\b(please|help)\b/gi, weight: 0.05 },
    ];
    
    let urgency = 0;
    
    for (const { pattern, weight } of urgentPatterns) {
      const matches = contentLower.match(pattern);
      if (matches) {
        urgency += matches.length * weight;
      }
    }
    
    return Math.min(1, urgency);
  }
  
  /**
   * Check if a phrase is a common non-name phrase
   */
  private isCommonPhrase(phrase: string): boolean {
    const commonPhrases = [
      'The', 'This', 'That', 'These', 'Those', 'What', 'When', 'Where', 'How',
      'New York', 'Los Angeles', 'San Francisco', 'United States', 'United Kingdom',
      'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday',
      'January', 'February', 'March', 'April', 'May', 'June', 'July', 'August',
      'September', 'October', 'November', 'December',
      'First', 'Second', 'Third', 'Last', 'Next', 'Previous',
    ];
    
    return commonPhrases.some(p => phrase.toLowerCase() === p.toLowerCase());
  }
  
  /**
   * Deduplicate entities
   */
  private deduplicateEntities(entities: ExtractedEntity[]): ExtractedEntity[] {
    const seen = new Set<string>();
    const unique: ExtractedEntity[] = [];
    
    for (const entity of entities) {
      const key = `${entity.type}:${entity.value.toLowerCase()}`;
      if (!seen.has(key)) {
        seen.add(key);
        unique.push(entity);
      }
    }
    
    return unique;
  }
}
