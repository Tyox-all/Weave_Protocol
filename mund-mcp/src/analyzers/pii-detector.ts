/**
 * Mund - The Guardian Protocol
 * PII Detector - Detects personally identifiable information
 */

import { 
  DetectorType, 
  type DetectionRule, 
  type SecurityIssue, 
  type IAnalyzer,
  type IssueLocation 
} from '../types.js';

export class PIIDetector implements IAnalyzer {
  name = 'PIIDetector';
  type = DetectorType.PII;

  async analyze(content: string, rules: DetectionRule[]): Promise<SecurityIssue[]> {
    const issues: SecurityIssue[] = [];
    const piiRules = rules.filter(r => r.type === DetectorType.PII && r.enabled);

    for (const rule of piiRules) {
      if (!rule.pattern) continue;

      try {
        const regex = new RegExp(rule.pattern, 'g');
        let match: RegExpExecArray | null;

        while ((match = regex.exec(content)) !== null) {
          const matchText = match[0];
          
          // Additional validation for specific types
          if (!this.validateMatch(rule.id, matchText)) {
            continue;
          }

          const location = this.getLocation(content, match.index, matchText.length);
          
          issues.push({
            rule_id: rule.id,
            rule_name: rule.name,
            type: rule.type,
            severity: rule.severity,
            action: rule.action,
            match: this.redactPII(rule.id, matchText),
            location,
            suggestion: this.getSuggestion(rule.id)
          });
        }
      } catch (error) {
        console.error(`Invalid regex pattern in rule ${rule.id}:`, error);
      }
    }

    return issues;
  }

  /**
   * Additional validation for matches to reduce false positives
   */
  private validateMatch(ruleId: string, match: string): boolean {
    switch (ruleId) {
      case 'ssn_us':
        return this.validateSSN(match);
      case 'credit_card':
        return this.validateCreditCard(match);
      case 'email_address':
        return this.validateEmail(match);
      case 'ip_address':
        return this.validateIPAddress(match);
      default:
        return true;
    }
  }

  /**
   * Validate SSN format (basic validation, not checking if real)
   */
  private validateSSN(ssn: string): boolean {
    const digits = ssn.replace(/\D/g, '');
    if (digits.length !== 9) return false;
    
    // SSNs cannot start with 000, 666, or 900-999
    const area = parseInt(digits.substring(0, 3));
    if (area === 0 || area === 666 || area >= 900) return false;
    
    // Group number cannot be 00
    const group = parseInt(digits.substring(3, 5));
    if (group === 0) return false;
    
    // Serial number cannot be 0000
    const serial = parseInt(digits.substring(5));
    if (serial === 0) return false;
    
    return true;
  }

  /**
   * Validate credit card using Luhn algorithm
   */
  private validateCreditCard(cc: string): boolean {
    const digits = cc.replace(/\D/g, '');
    if (digits.length < 13 || digits.length > 19) return false;

    let sum = 0;
    let isEven = false;

    for (let i = digits.length - 1; i >= 0; i--) {
      let digit = parseInt(digits[i]);

      if (isEven) {
        digit *= 2;
        if (digit > 9) {
          digit -= 9;
        }
      }

      sum += digit;
      isEven = !isEven;
    }

    return sum % 10 === 0;
  }

  /**
   * Validate email address format
   */
  private validateEmail(email: string): boolean {
    // Check for common false positives
    const falsePaths = ['.js', '.ts', '.py', '.java', '.cpp', '.go', '.rs'];
    if (falsePaths.some(ext => email.endsWith(ext))) return false;
    
    // Check for reasonable length
    if (email.length > 254) return false;
    
    // Check for valid TLD (at least 2 chars)
    const parts = email.split('.');
    const tld = parts[parts.length - 1];
    if (tld.length < 2) return false;
    
    return true;
  }

  /**
   * Validate IP address (exclude obvious non-IPs)
   */
  private validateIPAddress(ip: string): boolean {
    // Exclude version numbers (e.g., 1.2.3.4 in software versions)
    const parts = ip.split('.');
    
    // All parts should be valid octets
    for (const part of parts) {
      const num = parseInt(part);
      if (num < 0 || num > 255) return false;
    }
    
    // Exclude common version patterns
    if (parts[0] === '0' || parts[0] === '1') {
      if (parseInt(parts[1]) <= 20 && parseInt(parts[2]) <= 20) {
        return false; // Likely a version number
      }
    }
    
    // Exclude localhost and broadcast
    if (ip === '127.0.0.1' || ip === '0.0.0.0' || ip === '255.255.255.255') {
      return false;
    }
    
    return true;
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
   * Redact PII for safe display
   */
  private redactPII(ruleId: string, value: string): string {
    switch (ruleId) {
      case 'ssn_us':
        return `***-**-${value.slice(-4)}`;
      case 'credit_card':
        return `****-****-****-${value.slice(-4)}`;
      case 'email_address':
        const [local, domain] = value.split('@');
        return `${local.charAt(0)}***@${domain}`;
      case 'phone_number_us':
        return `***-***-${value.slice(-4)}`;
      case 'ip_address':
        const parts = value.split('.');
        return `${parts[0]}.***.***.*${parts[3].slice(-1)}`;
      default:
        return value.substring(0, 3) + '***' + value.slice(-2);
    }
  }

  /**
   * Get remediation suggestion
   */
  private getSuggestion(ruleId: string): string {
    const suggestions: Record<string, string> = {
      ssn_us: 'Social Security Numbers should never be stored in plain text. Use encryption or tokenization.',
      credit_card: 'Credit card numbers must be handled according to PCI DSS standards. Use tokenization.',
      email_address: 'Consider whether email addresses need to be logged. Hash or encrypt if stored.',
      phone_number_us: 'Phone numbers are PII. Consider whether they need to be included.',
      ip_address: 'IP addresses can be PII under GDPR. Consider hashing or anonymizing.'
    };

    return suggestions[ruleId] || 'Review whether this PII needs to be included and handle according to privacy policies.';
  }
}

export default PIIDetector;
