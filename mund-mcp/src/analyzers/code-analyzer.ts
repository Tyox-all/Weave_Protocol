/**
 * Mund - The Guardian Protocol
 * Code Analyzer - Detects dangerous code patterns
 */

import { 
  DetectorType, 
  type DetectionRule, 
  type SecurityIssue, 
  type IAnalyzer,
  type IssueLocation 
} from '../types.js';

export class CodeAnalyzer implements IAnalyzer {
  name = 'CodeAnalyzer';
  type = DetectorType.CODE_PATTERN;

  async analyze(content: string, rules: DetectionRule[]): Promise<SecurityIssue[]> {
    const issues: SecurityIssue[] = [];
    const codeRules = rules.filter(r => r.type === DetectorType.CODE_PATTERN && r.enabled);

    for (const rule of codeRules) {
      if (!rule.pattern) continue;

      try {
        const regex = new RegExp(rule.pattern, 'gm');
        let match: RegExpExecArray | null;

        while ((match = regex.exec(content)) !== null) {
          const matchText = match[0];
          const location = this.getLocation(content, match.index, matchText.length);
          
          issues.push({
            rule_id: rule.id,
            rule_name: rule.name,
            type: rule.type,
            severity: rule.severity,
            action: rule.action,
            match: this.truncateMatch(matchText),
            location,
            suggestion: this.getSuggestion(rule.id, matchText)
          });
        }
      } catch (error) {
        console.error(`Invalid regex pattern in rule ${rule.id}:`, error);
      }
    }

    return issues;
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
   * Truncate match for display
   */
  private truncateMatch(match: string, maxLength = 100): string {
    if (match.length <= maxLength) return match;
    return match.substring(0, maxLength) + '...';
  }

  /**
   * Get context-aware suggestion
   */
  private getSuggestion(ruleId: string, match: string): string {
    const suggestions: Record<string, string> = {
      shell_injection: 'Avoid using string interpolation in shell commands. Use parameterized commands or escape inputs properly.',
      sql_injection_pattern: 'Use parameterized queries or prepared statements instead of string concatenation for SQL.',
      dangerous_chmod: 'Avoid overly permissive file permissions. Use the minimum required permissions (e.g., 644 for files, 755 for directories).',
      rm_rf: 'Be extremely careful with recursive deletion. Consider using trash/recycle functionality instead.',
      curl_bash: 'Piping curl to bash is dangerous. Download the script first, review it, then execute.',
      base64_decode_exec: 'Decoding and executing arbitrary content is dangerous. Validate the source and content first.',
      disable_ssl_verify: 'Disabling SSL verification exposes you to man-in-the-middle attacks. Fix certificate issues instead.',
    };

    return suggestions[ruleId] || 'Review this code pattern for potential security issues.';
  }
}

export default CodeAnalyzer;
