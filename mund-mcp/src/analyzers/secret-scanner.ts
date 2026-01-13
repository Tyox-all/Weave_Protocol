/**
 * Mund - The Guardian Protocol
 * Secret Scanner - Detects secrets, API keys, and credentials
 */

import { 
  DetectorType, 
  type DetectionRule, 
  type SecurityIssue, 
  type IAnalyzer,
  type IssueLocation 
} from '../types.js';
import { MAX_SNIPPET_LENGTH } from '../constants.js';

export class SecretScanner implements IAnalyzer {
  name = 'SecretScanner';
  type = DetectorType.SECRET;

  async analyze(content: string, rules: DetectionRule[]): Promise<SecurityIssue[]> {
    const issues: SecurityIssue[] = [];
    const secretRules = rules.filter(r => r.type === DetectorType.SECRET && r.enabled);

    for (const rule of secretRules) {
      if (!rule.pattern) continue;

      try {
        const regex = new RegExp(rule.pattern, 'g');
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
            match: this.redactSecret(matchText),
            location,
            suggestion: this.getSuggestion(rule.id)
          });
        }
      } catch (error) {
        // Invalid regex pattern - skip this rule
        console.error(`Invalid regex pattern in rule ${rule.id}:`, error);
      }
    }

    return issues;
  }

  /**
   * Calculate the location of a match within the content
   */
  private getLocation(content: string, start: number, length: number): IssueLocation {
    const end = start + length;
    
    // Calculate line and column
    const lines = content.substring(0, start).split('\n');
    const line = lines.length;
    const column = lines[lines.length - 1].length + 1;

    return { start, end, line, column };
  }

  /**
   * Redact the middle portion of a secret for safe display
   */
  private redactSecret(secret: string): string {
    if (secret.length <= 8) {
      return '****';
    }

    const visibleStart = Math.min(4, Math.floor(secret.length * 0.2));
    const visibleEnd = Math.min(4, Math.floor(secret.length * 0.2));
    const redactedLength = secret.length - visibleStart - visibleEnd;

    return `${secret.substring(0, visibleStart)}${'*'.repeat(Math.min(redactedLength, 20))}${secret.substring(secret.length - visibleEnd)}`;
  }

  /**
   * Get remediation suggestion for a specific rule
   */
  private getSuggestion(ruleId: string): string {
    const suggestions: Record<string, string> = {
      aws_access_key_id: 'Use AWS IAM roles or environment variables instead of hardcoding credentials.',
      aws_secret_access_key: 'Never commit AWS secret keys. Use AWS Secrets Manager or environment variables.',
      github_token: 'Use GitHub Actions secrets or environment variables for tokens.',
      github_fine_grained_token: 'Store GitHub tokens in a secrets manager, not in code.',
      openai_api_key: 'Use environment variables (OPENAI_API_KEY) instead of hardcoding.',
      anthropic_api_key: 'Use environment variables (ANTHROPIC_API_KEY) instead of hardcoding.',
      google_api_key: 'Restrict API key usage in Google Cloud Console and use environment variables.',
      slack_token: 'Store Slack tokens in environment variables or a secrets manager.',
      slack_webhook: 'Webhook URLs should be stored in environment variables.',
      stripe_api_key: 'Use environment variables. Never expose live keys in client-side code.',
      private_key_block: 'Private keys should never be in code. Use a key management service.',
      jwt_token: 'JWTs should be transmitted securely and never logged or stored in code.',
      database_url: 'Database credentials should be in environment variables or a secrets manager.',
      generic_api_key: 'API keys should be stored in environment variables or a secrets manager.',
      generic_password: 'Passwords should never be hardcoded. Use a secrets manager.',
    };

    return suggestions[ruleId] || 'Remove this secret from code and use a secrets manager or environment variables.';
  }

  /**
   * Calculate Shannon entropy of a string (higher = more random = more likely a secret)
   */
  static calculateEntropy(str: string): number {
    const len = str.length;
    if (len === 0) return 0;

    const frequencies: Record<string, number> = {};
    for (const char of str) {
      frequencies[char] = (frequencies[char] || 0) + 1;
    }

    let entropy = 0;
    for (const count of Object.values(frequencies)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }

  /**
   * Check if a string is likely a high-entropy secret
   */
  static isHighEntropy(str: string, threshold = 4.5): boolean {
    // Skip strings that are too short or too long
    if (str.length < 16 || str.length > 200) return false;
    
    // Skip if it looks like a common word or path
    if (/^[a-z]+$/i.test(str)) return false;
    if (str.includes('/') && !str.includes('://')) return false;
    
    return SecretScanner.calculateEntropy(str) > threshold;
  }
}

export default SecretScanner;
