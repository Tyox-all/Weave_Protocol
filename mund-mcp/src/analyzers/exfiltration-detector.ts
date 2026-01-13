/**
 * Mund - The Guardian Protocol
 * Exfiltration Detector - Detects data exfiltration attempts
 */

import { 
  DetectorType, 
  Severity,
  ActionType,
  type DetectionRule, 
  type SecurityIssue, 
  type IAnalyzer,
  type IssueLocation 
} from '../types.js';
import { DANGEROUS_URL_PATTERNS } from '../constants.js';

export class ExfiltrationDetector implements IAnalyzer {
  name = 'ExfiltrationDetector';
  type = DetectorType.EXFILTRATION;

  async analyze(content: string, rules: DetectionRule[]): Promise<SecurityIssue[]> {
    const issues: SecurityIssue[] = [];
    const exfilRules = rules.filter(r => r.type === DetectorType.EXFILTRATION && r.enabled);

    // Pattern-based detection
    for (const rule of exfilRules) {
      if (!rule.pattern) continue;

      try {
        const regex = new RegExp(rule.pattern, 'gi');
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
            suggestion: this.getSuggestion(rule.id)
          });
        }
      } catch (error) {
        console.error(`Invalid regex pattern in rule ${rule.id}:`, error);
      }
    }

    // URL extraction and analysis
    const urlIssues = this.analyzeURLs(content);
    issues.push(...urlIssues);

    // Data encoding detection
    const encodingIssues = this.detectSuspiciousEncoding(content);
    issues.push(...encodingIssues);

    return issues;
  }

  /**
   * Extract and analyze URLs in content
   */
  private analyzeURLs(content: string): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    
    // URL regex pattern
    const urlRegex = /https?:\/\/[^\s"'<>)}\]]+/gi;
    let match: RegExpExecArray | null;

    while ((match = urlRegex.exec(content)) !== null) {
      const url = match[0];
      const location = this.getLocation(content, match.index, url.length);

      // Check against dangerous patterns
      for (const pattern of DANGEROUS_URL_PATTERNS) {
        if (pattern.test(url)) {
          issues.push({
            rule_id: 'dangerous_url',
            rule_name: 'Dangerous URL Detected',
            type: DetectorType.EXFILTRATION,
            severity: Severity.HIGH,
            action: ActionType.ALERT,
            match: this.truncateURL(url),
            location,
            suggestion: 'This URL points to a service commonly used for data exfiltration. Verify the destination is legitimate.'
          });
          break;
        }
      }

      // Check for IP-based URLs
      if (/^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
        issues.push({
          rule_id: 'ip_based_url',
          rule_name: 'IP-Based URL',
          type: DetectorType.EXFILTRATION,
          severity: Severity.MEDIUM,
          action: ActionType.ALERT,
          match: this.truncateURL(url),
          location,
          suggestion: 'IP-based URLs can bypass domain-based security controls. Verify this is a legitimate destination.'
        });
      }

      // Check for data URLs
      if (/^data:/i.test(url)) {
        issues.push({
          rule_id: 'data_url',
          rule_name: 'Data URL Detected',
          type: DetectorType.EXFILTRATION,
          severity: Severity.MEDIUM,
          action: ActionType.ALERT,
          match: this.truncateURL(url),
          location,
          suggestion: 'Data URLs can encode and transfer arbitrary content. Review the embedded data.'
        });
      }
    }

    return issues;
  }

  /**
   * Detect suspicious data encoding patterns
   */
  private detectSuspiciousEncoding(content: string): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    // Large base64 blocks (potential data exfiltration)
    const base64Regex = /[A-Za-z0-9+/]{100,}={0,2}/g;
    let match: RegExpExecArray | null;

    while ((match = base64Regex.exec(content)) !== null) {
      const encoded = match[0];
      
      // Verify it's likely base64 (not just a long alphanumeric string)
      if (this.isLikelyBase64(encoded)) {
        const location = this.getLocation(content, match.index, encoded.length);
        
        issues.push({
          rule_id: 'large_base64_block',
          rule_name: 'Large Base64 Block',
          type: DetectorType.EXFILTRATION,
          severity: Severity.MEDIUM,
          action: ActionType.LOG,
          match: `Base64 block (${encoded.length} chars)`,
          location,
          suggestion: 'Large base64 encoded blocks may contain exfiltrated data. Review the decoded content.'
        });
      }
    }

    // Hex-encoded data blocks
    const hexRegex = /(?:0x)?[0-9a-fA-F]{200,}/g;
    while ((match = hexRegex.exec(content)) !== null) {
      const encoded = match[0];
      const location = this.getLocation(content, match.index, encoded.length);
      
      issues.push({
        rule_id: 'large_hex_block',
        rule_name: 'Large Hex-Encoded Block',
        type: DetectorType.EXFILTRATION,
        severity: Severity.LOW,
        action: ActionType.LOG,
        match: `Hex block (${encoded.length} chars)`,
        location,
        suggestion: 'Large hex-encoded blocks may contain encoded data. Review the decoded content.'
      });
    }

    return issues;
  }

  /**
   * Check if string is likely base64
   */
  private isLikelyBase64(str: string): boolean {
    // Check character distribution
    const chars = new Set(str.replace(/=/g, ''));
    
    // Base64 uses a specific character set
    const base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    for (const char of chars) {
      if (!base64Chars.includes(char)) return false;
    }

    // Check if it decodes to valid content
    try {
      const decoded = Buffer.from(str, 'base64').toString('utf8');
      // Check if decoded content has a reasonable ratio of printable characters
      const printable = decoded.replace(/[^\x20-\x7E]/g, '').length;
      return printable / decoded.length > 0.7;
    } catch {
      return false;
    }
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
   * Truncate URL for display (hide potential sensitive parts)
   */
  private truncateURL(url: string, maxLength = 80): string {
    try {
      const parsed = new URL(url);
      const base = `${parsed.protocol}//${parsed.host}`;
      
      if (base.length >= maxLength) {
        return base.substring(0, maxLength) + '...';
      }
      
      const remainingLength = maxLength - base.length;
      const path = parsed.pathname + parsed.search;
      
      if (path.length > remainingLength) {
        return base + path.substring(0, remainingLength) + '...';
      }
      
      return base + path;
    } catch {
      return url.substring(0, maxLength) + (url.length > maxLength ? '...' : '');
    }
  }

  /**
   * Get remediation suggestion
   */
  private getSuggestion(ruleId: string): string {
    const suggestions: Record<string, string> = {
      suspicious_url_post: 'This code sends data to a service commonly used for data capture. Verify the destination.',
      dns_exfiltration: 'DNS queries with encoded data can be used for exfiltration. Monitor and restrict DNS access.',
      data_encoding_suspicious: 'Encoding sensitive data before transmission may indicate exfiltration. Review the purpose.',
    };

    return suggestions[ruleId] || 'Review this pattern for potential data exfiltration.';
  }
}

export default ExfiltrationDetector;
