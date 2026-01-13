/**
 * Dōmere - The Judge Protocol
 * Language Module
 */

export { LanguageDetector } from './detector.js';
export { SemanticAnalyzer } from './semantic.js';
export { CodeAnalyzer } from './code-analyzer.js';
export { NLAnalyzer } from './nl-analyzer.js';

import type { LanguageAnalysis, LanguageType } from '../types.js';
import { LanguageDetector } from './detector.js';
import { SemanticAnalyzer } from './semantic.js';
import { CodeAnalyzer } from './code-analyzer.js';
import { NLAnalyzer } from './nl-analyzer.js';

// ============================================================================
// Unified Language Analyzer
// ============================================================================

export class LanguageAnalyzerService {
  private detector: LanguageDetector;
  private semantic: SemanticAnalyzer;
  private code: CodeAnalyzer;
  private nl: NLAnalyzer;
  
  constructor() {
    this.detector = new LanguageDetector();
    this.semantic = new SemanticAnalyzer();
    this.code = new CodeAnalyzer();
    this.nl = new NLAnalyzer();
  }
  
  /**
   * Perform complete language analysis
   */
  analyze(content: string): LanguageAnalysis {
    // First detect languages
    const detection = this.detector.detect(content);
    
    // Build full analysis
    const analysis: LanguageAnalysis = {
      ...detection,
    };
    
    // Add semantic analysis
    analysis.semantic = this.semantic.analyze(content);
    
    // Add code analysis if code detected
    const codeLanguages: LanguageType[] = [
      'javascript', 'typescript', 'python', 'sql', 'java', 'csharp', 'go', 'rust',
      'ruby', 'php', 'swift', 'kotlin', 'bash', 'powershell',
    ];
    
    if (codeLanguages.includes(detection.primary_language as LanguageType)) {
      analysis.code_analysis = this.code.analyze(content, detection.primary_language as LanguageType);
    }
    
    // Add NL analysis for natural language or mixed content
    const nlLanguages: LanguageType[] = ['english', 'spanish', 'french', 'german', 'chinese', 'japanese', 'mixed', 'unknown'];
    if (nlLanguages.includes(detection.primary_language as LanguageType) || 
        detection.detected_languages.some(d => nlLanguages.includes(d.language))) {
      analysis.nl_analysis = this.nl.analyze(content);
    }
    
    return analysis;
  }
  
  /**
   * Quick language detection
   */
  detectLanguage(content: string): { language: LanguageType; confidence: number } {
    const detection = this.detector.detect(content);
    return {
      language: detection.primary_language as LanguageType,
      confidence: detection.confidence,
    };
  }
  
  /**
   * Check if content contains code
   */
  containsCode(content: string): boolean {
    return this.detector.containsCode(content);
  }
  
  /**
   * Analyze code specifically
   */
  analyzeCode(code: string, language?: LanguageType) {
    const lang = language || this.detectLanguage(code).language;
    return this.code.analyze(code, lang);
  }
  
  /**
   * Check for injection attempts
   */
  checkInjection(content: string) {
    return this.nl.analyze(content);
  }
  
  /**
   * Get injection risk score
   */
  getInjectionRisk(content: string): number {
    return this.nl.getInjectionRiskScore(content);
  }
  
  /**
   * Extract entities
   */
  extractEntities(content: string) {
    return this.semantic.extractEntities(content);
  }
  
  /**
   * Classify intent
   */
  classifyIntent(content: string) {
    return this.semantic.classifyIntent(content);
  }
  
  /**
   * Extract code blocks from mixed content
   */
  extractCodeBlocks(content: string) {
    return this.detector.extractCodeBlocks(content);
  }
}
