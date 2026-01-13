/**
 * Dōmere - The Judge Protocol
 * Language Detection
 */

import type {
  LanguageAnalysis,
  DetectedLanguage,
  LanguageSegment,
  LanguageType,
} from '../types.js';
import { LANGUAGE_PATTERNS } from '../constants.js';

// ============================================================================
// Language Detector
// ============================================================================

export class LanguageDetector {
  /**
   * Detect the primary language(s) in content
   */
  detect(content: string): LanguageAnalysis {
    const detectedLanguages = this.detectLanguages(content);
    const primary = this.determinePrimaryLanguage(detectedLanguages);
    
    return {
      detected_languages: detectedLanguages,
      primary_language: primary.language,
      confidence: primary.confidence,
    };
  }
  
  /**
   * Detect all languages present in content
   */
  detectLanguages(content: string): DetectedLanguage[] {
    const results: Map<LanguageType, { score: number; segments: LanguageSegment[] }> = new Map();
    
    // First pass: detect code languages (more specific patterns)
    const codeLanguages: LanguageType[] = [
      'typescript', 'javascript', 'python', 'sql', 'java', 'csharp', 'go', 'rust',
      'ruby', 'php', 'swift', 'kotlin', 'scala', 'bash', 'powershell',
      'json', 'yaml', 'xml', 'html', 'css', 'markdown',
      'graphql', 'protobuf', 'regex',
    ];
    
    for (const lang of codeLanguages) {
      const detection = this.detectLanguage(content, lang);
      if (detection.score > 0.1) {
        results.set(lang, detection);
      }
    }
    
    // If no code detected, check for natural language
    if (results.size === 0 || this.isLikelyNaturalLanguage(content)) {
      const nlLanguages: LanguageType[] = ['english', 'spanish', 'french', 'german', 'chinese', 'japanese'];
      
      for (const lang of nlLanguages) {
        const detection = this.detectLanguage(content, lang);
        if (detection.score > 0.1) {
          // Check if we already have code - if so, this might be mixed
          const existingTotal = Array.from(results.values()).reduce((sum, d) => sum + d.score, 0);
          if (existingTotal < 0.5 || detection.score > 0.3) {
            results.set(lang, detection);
          }
        }
      }
    }
    
    // Convert to array and normalize
    const detected: DetectedLanguage[] = [];
    const totalScore = Array.from(results.values()).reduce((sum, d) => sum + d.score, 0);
    
    for (const [language, data] of results) {
      const confidence = totalScore > 0 ? data.score / totalScore : 0;
      if (confidence > 0.05) {  // Only include if > 5% confidence
        detected.push({
          language,
          confidence,
          segments: data.segments,
        });
      }
    }
    
    // Sort by confidence
    detected.sort((a, b) => b.confidence - a.confidence);
    
    // If nothing detected, return unknown
    if (detected.length === 0) {
      return [{
        language: 'unknown',
        confidence: 1,
        segments: [{ start: 0, end: content.length, language: 'unknown', content, confidence: 1 }],
      }];
    }
    
    return detected;
  }
  
  /**
   * Detect a specific language in content
   */
  private detectLanguage(content: string, language: LanguageType): { score: number; segments: LanguageSegment[] } {
    const config = LANGUAGE_PATTERNS[language];
    if (!config) {
      return { score: 0, segments: [] };
    }
    
    let score = 0;
    const segments: LanguageSegment[] = [];
    const contentLower = content.toLowerCase();
    
    // Check patterns
    for (const pattern of config.patterns) {
      const matches = content.match(pattern);
      if (matches) {
        score += matches.length * 0.15;
        
        // Find positions of matches
        let lastIndex = 0;
        for (const match of matches) {
          const index = content.indexOf(match, lastIndex);
          if (index !== -1) {
            segments.push({
              start: index,
              end: index + match.length,
              language,
              content: match,
              confidence: 0.8,
            });
            lastIndex = index + match.length;
          }
        }
      }
    }
    
    // Check keywords
    for (const keyword of config.keywords) {
      const keywordLower = keyword.toLowerCase();
      // Match whole words only
      const regex = new RegExp(`\\b${this.escapeRegex(keywordLower)}\\b`, 'gi');
      const matches = contentLower.match(regex);
      if (matches) {
        score += matches.length * 0.05;
      }
    }
    
    // Normalize score (cap at 1)
    score = Math.min(1, score);
    
    // Merge overlapping segments
    const mergedSegments = this.mergeSegments(segments);
    
    return { score, segments: mergedSegments };
  }
  
  /**
   * Check if content is likely natural language (not code)
   */
  private isLikelyNaturalLanguage(content: string): boolean {
    // Check for common indicators of natural language
    const sentencePattern = /[.!?]\s+[A-Z]/g;
    const sentences = content.match(sentencePattern)?.length || 0;
    
    // Check for lack of code indicators
    const codeIndicators = /[{}();=<>]|\bfunction\b|\bclass\b|\bdef\b|\bimport\b|\bexport\b/g;
    const codeMatches = content.match(codeIndicators)?.length || 0;
    
    // Natural language has more sentences than code indicators
    return sentences > codeMatches || (sentences > 2 && codeMatches < 5);
  }
  
  /**
   * Determine the primary language
   */
  private determinePrimaryLanguage(detected: DetectedLanguage[]): { language: LanguageType; confidence: number } {
    if (detected.length === 0) {
      return { language: 'unknown', confidence: 0 };
    }
    
    // If multiple languages with similar confidence, it's mixed
    if (detected.length > 1 && detected[0].confidence < 0.6 && 
        detected[1].confidence > detected[0].confidence * 0.5) {
      return { language: 'mixed', confidence: detected[0].confidence };
    }
    
    return { language: detected[0].language, confidence: detected[0].confidence };
  }
  
  /**
   * Merge overlapping segments
   */
  private mergeSegments(segments: LanguageSegment[]): LanguageSegment[] {
    if (segments.length <= 1) return segments;
    
    // Sort by start position
    segments.sort((a, b) => a.start - b.start);
    
    const merged: LanguageSegment[] = [];
    let current = segments[0];
    
    for (let i = 1; i < segments.length; i++) {
      const next = segments[i];
      
      if (next.start <= current.end) {
        // Overlapping - merge
        current = {
          start: current.start,
          end: Math.max(current.end, next.end),
          language: current.language,
          content: current.content + next.content.slice(Math.max(0, current.end - next.start)),
          confidence: Math.max(current.confidence, next.confidence),
        };
      } else {
        merged.push(current);
        current = next;
      }
    }
    merged.push(current);
    
    return merged;
  }
  
  /**
   * Escape regex special characters
   */
  private escapeRegex(str: string): string {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
  
  /**
   * Check if content is a specific language type
   */
  isLanguage(content: string, language: LanguageType): boolean {
    const detection = this.detectLanguage(content, language);
    return detection.score > 0.3;
  }
  
  /**
   * Check if content contains code
   */
  containsCode(content: string): boolean {
    const codeLanguages: LanguageType[] = [
      'javascript', 'typescript', 'python', 'sql', 'java', 'csharp', 'go', 'rust',
      'ruby', 'php', 'swift', 'kotlin', 'bash', 'powershell',
    ];
    
    for (const lang of codeLanguages) {
      if (this.isLanguage(content, lang)) {
        return true;
      }
    }
    
    return false;
  }
  
  /**
   * Extract code blocks from content
   */
  extractCodeBlocks(content: string): { language: string; code: string; start: number; end: number }[] {
    const blocks: { language: string; code: string; start: number; end: number }[] = [];
    
    // Match fenced code blocks (```language ... ```)
    const fencedRegex = /```(\w+)?\s*\n([\s\S]*?)```/g;
    let match;
    
    while ((match = fencedRegex.exec(content)) !== null) {
      const language = match[1] || 'unknown';
      const code = match[2];
      blocks.push({
        language,
        code,
        start: match.index,
        end: match.index + match[0].length,
      });
    }
    
    // Match indented code blocks (4 spaces or tab)
    const indentedRegex = /(?:^|\n)((?:(?:    |\t).+\n?)+)/g;
    
    while ((match = indentedRegex.exec(content)) !== null) {
      const code = match[1].replace(/^(    |\t)/gm, '');
      // Detect language of this block
      const detection = this.detectLanguages(code);
      const language = detection[0]?.language || 'unknown';
      
      blocks.push({
        language,
        code,
        start: match.index,
        end: match.index + match[0].length,
      });
    }
    
    return blocks;
  }
}
