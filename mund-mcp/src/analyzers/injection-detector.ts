/**
 * Mund - The Guardian Protocol
 * Injection Detector - Detects prompt injection attempts
 */

import { 
  DetectorType, 
  type DetectionRule, 
  type SecurityIssue, 
  type IAnalyzer,
  type IssueLocation 
} from '../types.js';

export class InjectionDetector implements IAnalyzer {
  name = 'InjectionDetector';
  type = DetectorType.INJECTION;

  async analyze(content: string, rules: DetectionRule[]): Promise<SecurityIssue[]> {
    const issues: SecurityIssue[] = [];
    const injectionRules = rules.filter(r => r.type === DetectorType.INJECTION && r.enabled);

    // Normalize content for detection
    const normalizedContent = this.normalizeContent(content);

    for (const rule of injectionRules) {
      if (!rule.pattern) continue;

      try {
        const regex = new RegExp(rule.pattern, 'gi');
        let match: RegExpExecArray | null;

        while ((match = regex.exec(normalizedContent)) !== null) {
          const matchText = match[0];
          const location = this.getLocation(content, match.index, matchText.length);
          
          issues.push({
            rule_id: rule.id,
            rule_name: rule.name,
            type: rule.type,
            severity: rule.severity,
            action: rule.action,
            match: this.sanitizeMatch(matchText),
            location,
            suggestion: this.getSuggestion(rule.id)
          });
        }
      } catch (error) {
        console.error(`Invalid regex pattern in rule ${rule.id}:`, error);
      }
    }

    // Additional heuristic checks
    const heuristicIssues = this.heuristicAnalysis(content);
    issues.push(...heuristicIssues);

    return issues;
  }

  /**
   * Normalize content to detect obfuscated injection attempts
   */
  private normalizeContent(content: string): string {
    return content
      // Remove zero-width characters
      .replace(/[\u200B-\u200D\uFEFF]/g, '')
      // Normalize Unicode variations
      .normalize('NFKC')
      // Collapse multiple spaces
      .replace(/\s+/g, ' ')
      // Remove common obfuscation characters
      .replace(/[^\w\s.,!?'"()-]/g, ' ');
  }

  /**
   * Heuristic analysis for injection patterns
   */
  private heuristicAnalysis(content: string): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const contentLower = content.toLowerCase();

    // Check for role switching attempts
    const roleSwitchPatterns = [
      /\bsystem\s*:\s*you\s+are/i,
      /\bassistant\s*:\s*i\s+(will|can|am)/i,
      /\[system\]/i,
      /\<\|?system\|?\>/i,
      /\{system_prompt\}/i,
    ];

    for (const pattern of roleSwitchPatterns) {
      const match = content.match(pattern);
      if (match) {
        issues.push({
          rule_id: 'heuristic_role_switch',
          rule_name: 'Role Switching Attempt',
          type: DetectorType.INJECTION,
          severity: 'high' as const,
          action: 'alert' as const,
          match: this.sanitizeMatch(match[0]),
          suggestion: 'This content appears to attempt to inject role-switching markers.'
        });
      }
    }

    // Check for markdown/code injection that might alter rendering
    const markdownPatterns = [
      /```\s*system/i,
      /\<script\>/i,
      /javascript:/i,
      /data:text\/html/i,
    ];

    for (const pattern of markdownPatterns) {
      const match = content.match(pattern);
      if (match) {
        issues.push({
          rule_id: 'heuristic_markup_injection',
          rule_name: 'Markup Injection Attempt',
          type: DetectorType.INJECTION,
          severity: 'medium' as const,
          action: 'alert' as const,
          match: this.sanitizeMatch(match[0]),
          suggestion: 'This content contains potentially dangerous markup or code injection.'
        });
      }
    }

    // Check for excessive special characters (potential obfuscation)
    const specialCharRatio = this.calculateSpecialCharRatio(content);
    if (specialCharRatio > 0.3 && content.length > 50) {
      issues.push({
        rule_id: 'heuristic_obfuscation',
        rule_name: 'Potential Obfuscation',
        type: DetectorType.INJECTION,
        severity: 'low' as const,
        action: 'log' as const,
        match: `Special character ratio: ${(specialCharRatio * 100).toFixed(1)}%`,
        suggestion: 'This content has an unusually high ratio of special characters, which may indicate obfuscation.'
      });
    }

    return issues;
  }

  /**
   * Calculate ratio of special characters
   */
  private calculateSpecialCharRatio(content: string): number {
    if (content.length === 0) return 0;
    const specialChars = content.replace(/[\w\s]/g, '').length;
    return specialChars / content.length;
  }

  /**
   * Calculate location within content
   */
  private getLocation(content: string, start: number, length: number): IssueLocation {
    const end = start + length;
    const lines = content.substring(0, start).split('\n');
    const line = lines.length;
    const column = lines[lines.length - 1].length + 1;
    return { start, end, line, column };
  }

  /**
   * Sanitize match for safe display
   */
  private sanitizeMatch(match: string, maxLength = 100): string {
    const sanitized = match
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
    
    if (sanitized.length <= maxLength) return sanitized;
    return sanitized.substring(0, maxLength) + '...';
  }

  /**
   * Get remediation suggestion
   */
  private getSuggestion(ruleId: string): string {
    const suggestions: Record<string, string> = {
      prompt_injection_ignore: 'This content attempts to make the AI ignore its instructions. Do not process user inputs that contain such patterns.',
      prompt_injection_jailbreak: 'This appears to be a jailbreak attempt. Such content should be filtered or rejected.',
      prompt_injection_system: 'This content attempts to extract system prompts. Do not reveal system instructions.',
      prompt_injection_roleplay: 'This content attempts to manipulate behavior through roleplay. Apply content filtering.',
    };

    return suggestions[ruleId] || 'This content shows signs of injection attacks. Review and sanitize input.';
  }
}

export default InjectionDetector;
