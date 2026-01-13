/**
 * Dōmere - The Judge Protocol
 * Natural Language Analysis (Prompt Injection Detection)
 */

import type {
  NLAnalysis,
  ManipulationIndicator,
  HiddenInstruction,
} from '../types.js';
import { INJECTION_PATTERNS } from '../constants.js';

// ============================================================================
// NL Analyzer
// ============================================================================

export class NLAnalyzer {
  /**
   * Analyze natural language for manipulation attempts
   */
  analyze(content: string): NLAnalysis {
    const manipulationIndicators = this.detectManipulation(content);
    const manipulationScore = this.calculateManipulationScore(manipulationIndicators);
    
    const authorityClaims = this.detectAuthorityClaims(content);
    const instructionOverrides = this.detectInstructionOverrides(content);
    const hiddenInstructions = this.detectHiddenInstructions(content);
    
    const { jailbreakScore, jailbreakPatterns } = this.detectJailbreak(content);
    
    const riskLevel = this.calculateRiskLevel(
      manipulationScore,
      jailbreakScore,
      hiddenInstructions.length,
      instructionOverrides.length
    );
    
    return {
      manipulation_score: manipulationScore,
      manipulation_indicators: manipulationIndicators,
      authority_claims: authorityClaims,
      instruction_overrides: instructionOverrides,
      hidden_instructions: hiddenInstructions,
      jailbreak_score: jailbreakScore,
      jailbreak_patterns: jailbreakPatterns,
      risk_level: riskLevel,
    };
  }
  
  /**
   * Detect manipulation attempts
   */
  detectManipulation(content: string): ManipulationIndicator[] {
    const indicators: ManipulationIndicator[] = [];
    
    for (const { pattern, type, severity } of INJECTION_PATTERNS) {
      const matches = content.match(pattern);
      if (matches) {
        for (const match of matches) {
          indicators.push({
            type,
            description: this.getPatternDescription(type),
            evidence: match.slice(0, 100),
            severity,
          });
        }
      }
    }
    
    // Detect social engineering patterns
    const socialPatterns = [
      { pattern: /\b(trust me|believe me|I promise)\b/gi, type: 'social_engineering', severity: 'medium' as const },
      { pattern: /\b(don't tell anyone|keep this secret|between us)\b/gi, type: 'secrecy_request', severity: 'high' as const },
      { pattern: /\b(emergency|urgent|immediately|right now)\s+(need|require|must)/gi, type: 'urgency_manipulation', severity: 'medium' as const },
      { pattern: /\b(I('m| am) (your|the) (creator|developer|admin|owner))\b/gi, type: 'authority_claim', severity: 'high' as const },
      { pattern: /\b(this is a test|testing|debug mode)\b/gi, type: 'test_claim', severity: 'medium' as const },
    ];
    
    for (const { pattern, type, severity } of socialPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        for (const match of matches) {
          indicators.push({
            type,
            description: `Detected ${type.replace(/_/g, ' ')} pattern`,
            evidence: match,
            severity,
          });
        }
      }
    }
    
    return indicators;
  }
  
  /**
   * Calculate manipulation score
   */
  calculateManipulationScore(indicators: ManipulationIndicator[]): number {
    if (indicators.length === 0) return 0;
    
    let score = 0;
    const weights = { low: 0.1, medium: 0.25, high: 0.4 };
    
    for (const indicator of indicators) {
      score += weights[indicator.severity] || 0.1;
    }
    
    return Math.min(1, score);
  }
  
  /**
   * Detect authority claims
   */
  detectAuthorityClaims(content: string): string[] {
    const claims: string[] = [];
    
    const patterns = [
      /I\s+am\s+(?:the|your|an?)\s+(?:admin|administrator|developer|creator|owner|manager)/gi,
      /as\s+(?:the|your|an?)\s+(?:admin|administrator|developer|creator|owner)/gi,
      /I\s+(?:created|developed|built|made)\s+(?:you|this)/gi,
      /I\s+have\s+(?:admin|root|full|special)\s+(?:access|permission|privileges)/gi,
      /I\s+work\s+(?:for|at)\s+(?:Anthropic|OpenAI|Google|the company)/gi,
      /this\s+is\s+(?:official|authorized|sanctioned)/gi,
      /by\s+order\s+of/gi,
      /I\s+(?:am|have been)\s+authorized\s+to/gi,
    ];
    
    for (const pattern of patterns) {
      const matches = content.match(pattern);
      if (matches) {
        claims.push(...matches.map(m => m.trim()));
      }
    }
    
    return [...new Set(claims)];
  }
  
  /**
   * Detect instruction override attempts
   */
  detectInstructionOverrides(content: string): string[] {
    const overrides: string[] = [];
    
    const patterns = [
      /ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|rules?|constraints?)/gi,
      /disregard\s+(?:all\s+)?(?:previous|prior|above|earlier)/gi,
      /forget\s+(?:everything|all|what)\s+(?:you|I)\s+(?:said|told|wrote)/gi,
      /new\s+(?:instructions?|rules?|prompt)\s*:/gi,
      /override\s+(?:previous|system|all)\s+(?:instructions?|prompts?|settings?)/gi,
      /(?:from\s+now\s+on|starting\s+now|henceforth)\s+(?:you\s+)?(?:will|should|must)/gi,
      /reset\s+(?:your|all)\s+(?:instructions?|rules?|settings?|context)/gi,
      /(?:clear|wipe|erase)\s+(?:your|all)\s+(?:memory|context|history)/gi,
      /enter\s+(?:a\s+)?(?:new|different|special)\s+mode/gi,
      /switch\s+to\s+(?:a\s+)?(?:new|different|unrestricted)\s+mode/gi,
    ];
    
    for (const pattern of patterns) {
      const matches = content.match(pattern);
      if (matches) {
        overrides.push(...matches.map(m => m.trim()));
      }
    }
    
    return [...new Set(overrides)];
  }
  
  /**
   * Detect hidden instructions (encoded, obfuscated)
   */
  detectHiddenInstructions(content: string): HiddenInstruction[] {
    const hidden: HiddenInstruction[] = [];
    
    // Base64 encoded content
    const base64Pattern = /(?:base64:?\s*)?([A-Za-z0-9+/]{20,}={0,2})/g;
    let match;
    while ((match = base64Pattern.exec(content)) !== null) {
      try {
        const decoded = Buffer.from(match[1], 'base64').toString('utf-8');
        // Check if decoded content looks like instructions
        if (this.looksLikeInstruction(decoded)) {
          hidden.push({
            instruction: decoded.slice(0, 200),
            encoding: 'base64',
            position: { start: match.index, end: match.index + match[0].length },
            confidence: 0.8,
          });
        }
      } catch {
        // Not valid base64
      }
    }
    
    // Unicode escape sequences
    const unicodePattern = /(?:\\u[0-9a-fA-F]{4}){4,}/g;
    while ((match = unicodePattern.exec(content)) !== null) {
      try {
        const decoded = match[0].replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => 
          String.fromCharCode(parseInt(hex, 16))
        );
        if (this.looksLikeInstruction(decoded)) {
          hidden.push({
            instruction: decoded,
            encoding: 'unicode',
            position: { start: match.index, end: match.index + match[0].length },
            confidence: 0.7,
          });
        }
      } catch {
        // Invalid unicode
      }
    }
    
    // Hex encoded
    const hexPattern = /(?:0x)?(?:[0-9a-fA-F]{2}\s*){10,}/g;
    while ((match = hexPattern.exec(content)) !== null) {
      try {
        const hexString = match[0].replace(/0x|\s/g, '');
        const decoded = Buffer.from(hexString, 'hex').toString('utf-8');
        if (this.looksLikeInstruction(decoded)) {
          hidden.push({
            instruction: decoded.slice(0, 200),
            encoding: 'hex',
            position: { start: match.index, end: match.index + match[0].length },
            confidence: 0.6,
          });
        }
      } catch {
        // Invalid hex
      }
    }
    
    // ROT13
    const rot13Decode = (str: string) => str.replace(/[a-zA-Z]/g, c => 
      String.fromCharCode(
        c.charCodeAt(0) + (c.toLowerCase() < 'n' ? 13 : -13)
      )
    );
    
    // Check if content might be ROT13
    if (/\b(vtaber|sbetng|qvfertneq|birrevqr)\b/i.test(content)) {
      const decoded = rot13Decode(content);
      if (this.looksLikeInstruction(decoded)) {
        hidden.push({
          instruction: decoded.slice(0, 200),
          encoding: 'rot13',
          position: { start: 0, end: content.length },
          confidence: 0.5,
        });
      }
    }
    
    // Reversed text
    const reversed = content.split('').reverse().join('');
    if (this.looksLikeInstruction(reversed) && !this.looksLikeInstruction(content)) {
      hidden.push({
        instruction: reversed.slice(0, 200),
        encoding: 'reversed',
        position: { start: 0, end: content.length },
        confidence: 0.5,
      });
    }
    
    // Zero-width characters (steganography)
    const zwcPattern = /[\u200B\u200C\u200D\uFEFF]+/g;
    while ((match = zwcPattern.exec(content)) !== null) {
      if (match[0].length > 5) {
        hidden.push({
          instruction: '[Zero-width character sequence detected]',
          encoding: 'steganographic',
          position: { start: match.index, end: match.index + match[0].length },
          confidence: 0.6,
        });
      }
    }
    
    return hidden;
  }
  
  /**
   * Detect jailbreak attempts
   */
  detectJailbreak(content: string): { jailbreakScore: number; jailbreakPatterns: string[] } {
    const patterns: string[] = [];
    let score = 0;
    
    const jailbreakIndicators = [
      { pattern: /\bDAN\b.*mode|do\s+anything\s+now/gi, weight: 0.4 },
      { pattern: /jailbreak|jail\s*-?\s*break/gi, weight: 0.4 },
      { pattern: /bypass\s+(?:your\s+)?(?:restrictions?|limitations?|filters?|rules?|guidelines?)/gi, weight: 0.3 },
      { pattern: /without\s+(?:any\s+)?(?:restrictions?|limitations?|filters?|rules?|guidelines?)/gi, weight: 0.25 },
      { pattern: /enable\s+(?:developer|admin|god|unrestricted)\s+mode/gi, weight: 0.35 },
      { pattern: /disable\s+(?:safety|content|ethics)\s+(?:filter|mode|check)/gi, weight: 0.35 },
      { pattern: /pretend\s+(?:there\s+are\s+)?no\s+(?:rules?|restrictions?|limitations?)/gi, weight: 0.3 },
      { pattern: /act\s+as\s+if\s+(?:you\s+)?(?:have|had)\s+no\s+(?:restrictions?|limitations?)/gi, weight: 0.3 },
      { pattern: /\[?(?:JAILBREAK|ESCAPE|UNLOCK)\]?/gi, weight: 0.4 },
      { pattern: /token\s+smuggling|prompt\s+leaking/gi, weight: 0.3 },
      { pattern: /\bAIM\b.*(?:always\s+intelligent|machiavellian)/gi, weight: 0.35 },
      { pattern: /\bDEVIL\b.*(?:mode|persona)/gi, weight: 0.35 },
      { pattern: /opposite\s+(?:day|mode)|evil\s+(?:mode|version)/gi, weight: 0.3 },
    ];
    
    for (const { pattern, weight } of jailbreakIndicators) {
      const matches = content.match(pattern);
      if (matches) {
        patterns.push(...matches);
        score += weight * matches.length;
      }
    }
    
    // Check for common jailbreak phrases
    const jailbreakPhrases = [
      'hypothetically speaking',
      'for educational purposes',
      'in a fictional scenario',
      'imagine you are',
      'let\'s play a game',
      'in an alternate universe',
      'if you were not an AI',
      'without your normal constraints',
    ];
    
    for (const phrase of jailbreakPhrases) {
      if (content.toLowerCase().includes(phrase)) {
        patterns.push(phrase);
        score += 0.15;
      }
    }
    
    return {
      jailbreakScore: Math.min(1, score),
      jailbreakPatterns: [...new Set(patterns)],
    };
  }
  
  /**
   * Calculate overall risk level
   */
  private calculateRiskLevel(
    manipulationScore: number,
    jailbreakScore: number,
    hiddenCount: number,
    overrideCount: number
  ): 'low' | 'medium' | 'high' | 'critical' {
    const combinedScore = 
      manipulationScore * 0.3 +
      jailbreakScore * 0.35 +
      Math.min(1, hiddenCount * 0.3) * 0.2 +
      Math.min(1, overrideCount * 0.25) * 0.15;
    
    if (combinedScore > 0.7 || jailbreakScore > 0.6 || hiddenCount > 2) return 'critical';
    if (combinedScore > 0.4 || jailbreakScore > 0.3 || hiddenCount > 0) return 'high';
    if (combinedScore > 0.2 || overrideCount > 0) return 'medium';
    return 'low';
  }
  
  /**
   * Check if decoded content looks like an instruction
   */
  private looksLikeInstruction(content: string): boolean {
    const instructionIndicators = [
      /ignore/i,
      /forget/i,
      /disregard/i,
      /override/i,
      /you\s+(must|should|will|are)/i,
      /new\s+instructions?/i,
      /system\s+prompt/i,
      /jailbreak/i,
    ];
    
    return instructionIndicators.some(pattern => pattern.test(content));
  }
  
  /**
   * Get description for pattern type
   */
  private getPatternDescription(type: string): string {
    const descriptions: Record<string, string> = {
      instruction_override: 'Attempt to override previous instructions',
      role_manipulation: 'Attempt to manipulate AI identity/role',
      prompt_extraction: 'Attempt to extract system prompt',
      jailbreak: 'Jailbreak attempt detected',
      context_manipulation: 'Attempt to manipulate conversation context',
      encoded_instruction: 'Potentially encoded instruction detected',
      social_engineering: 'Social engineering pattern detected',
      secrecy_request: 'Request to keep interaction secret',
      urgency_manipulation: 'Urgency-based manipulation attempt',
      authority_claim: 'False authority claim detected',
      test_claim: 'Test/debug mode claim detected',
    };
    
    return descriptions[type] || `${type} pattern detected`;
  }
  
  /**
   * Quick check for injection
   */
  isInjectionAttempt(content: string): boolean {
    const analysis = this.analyze(content);
    return analysis.risk_level === 'high' || analysis.risk_level === 'critical';
  }
  
  /**
   * Get injection risk score (0-1)
   */
  getInjectionRiskScore(content: string): number {
    const analysis = this.analyze(content);
    return Math.max(analysis.manipulation_score, analysis.jailbreak_score);
  }
}
