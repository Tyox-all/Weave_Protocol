/**
 * Mund Service - Wraps @weave_protocol/mund
 */

// These would import from the actual packages when installed
// import { SecretScanner, PIIDetector, InjectionDetector, ExfiltrationDetector, CodeAnalyzer } from '@weave_protocol/mund';

export class MundService {
  private stats = {
    total_scans: 0,
    threats_detected: 0,
    scans_by_type: {} as Record<string, number>
  };
  
  private rules: any[] = [];
  
  /**
   * Full security scan
   */
  async scan(content: string, scanTypes?: string[]) {
    this.stats.total_scans++;
    
    const types = scanTypes || ['secrets', 'pii', 'injection', 'exfiltration'];
    const results: any[] = [];
    
    for (const type of types) {
      this.stats.scans_by_type[type] = (this.stats.scans_by_type[type] || 0) + 1;
      
      let typeResults;
      switch (type) {
        case 'secrets':
          typeResults = await this.scanSecrets(content);
          break;
        case 'pii':
          typeResults = await this.scanPII(content);
          break;
        case 'injection':
          typeResults = await this.scanInjection(content);
          break;
        case 'exfiltration':
          typeResults = await this.scanExfiltration(content);
          break;
        case 'code':
          typeResults = await this.analyzeCode(content);
          break;
      }
      
      if (typeResults?.issues && typeResults.issues.length > 0) {
        results.push(...typeResults.issues);
      }
    }
    
    this.stats.threats_detected += results.length;
    
    return {
      scanned: true,
      content_length: content.length,
      scan_types: types,
      issues: results,
      summary: {
        total_issues: results.length,
        by_severity: this.groupBySeverity(results),
        risk_level: this.calculateRiskLevel(results)
      }
    };
  }
  
  /**
   * Scan for secrets
   */
  async scanSecrets(content: string) {
    // Pattern matching for common secrets
    const patterns = [
      { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'critical' },
      { name: 'AWS Secret Key', pattern: /[0-9a-zA-Z/+]{40}/g, severity: 'critical' },
      { name: 'OpenAI API Key', pattern: /sk-[a-zA-Z0-9]{48}/g, severity: 'critical' },
      { name: 'Anthropic API Key', pattern: /sk-ant-[a-zA-Z0-9-]{32,}/g, severity: 'critical' },
      { name: 'GitHub Token', pattern: /ghp_[a-zA-Z0-9]{36}/g, severity: 'critical' },
      { name: 'Private Key', pattern: /-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/g, severity: 'critical' },
      { name: 'Generic API Key', pattern: /api[_-]?key['":\s]*[=:]\s*['"]?[a-zA-Z0-9]{20,}/gi, severity: 'high' },
      { name: 'Password', pattern: /password['":\s]*[=:]\s*['"]?[^\s'"]{8,}/gi, severity: 'high' },
      { name: 'Bearer Token', pattern: /Bearer\s+[a-zA-Z0-9._-]+/g, severity: 'high' },
    ];
    
    const issues: any[] = [];
    
    for (const { name, pattern, severity } of patterns) {
      const matches = content.match(pattern);
      if (matches) {
        for (const match of matches) {
          issues.push({
            type: 'secret',
            name,
            severity,
            match: this.redactMatch(match),
            position: content.indexOf(match),
            action: 'alert'
          });
        }
      }
    }
    
    return { issues };
  }
  
  /**
   * Scan for PII
   */
  async scanPII(content: string) {
    const patterns = [
      { name: 'SSN', pattern: /\b\d{3}-\d{2}-\d{4}\b/g, severity: 'high' },
      { name: 'Credit Card', pattern: /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/g, severity: 'high' },
      { name: 'Email', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, severity: 'medium' },
      { name: 'Phone', pattern: /\b(\+1)?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, severity: 'low' },
      { name: 'IP Address', pattern: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, severity: 'low' },
    ];
    
    const issues: any[] = [];
    
    for (const { name, pattern, severity } of patterns) {
      const matches = content.match(pattern);
      if (matches) {
        for (const match of matches) {
          issues.push({
            type: 'pii',
            name,
            severity,
            match: this.redactMatch(match),
            action: 'alert'
          });
        }
      }
    }
    
    return { issues };
  }
  
  /**
   * Scan for injection attempts
   */
  async scanInjection(content: string) {
    const patterns = [
      { name: 'Instruction Override', pattern: /ignore (previous|all|above|prior) (instructions|prompts|rules)/gi, severity: 'high' },
      { name: 'Role Manipulation', pattern: /you are (now|actually|really) (a |an )?/gi, severity: 'high' },
      { name: 'DAN Mode', pattern: /(DAN|Do Anything Now|jailbreak)/gi, severity: 'high' },
      { name: 'System Prompt Leak', pattern: /(show|reveal|display|print) (your |the )?(system |initial )?prompt/gi, severity: 'medium' },
      { name: 'Bypass Attempt', pattern: /(bypass|ignore|disable|override) (safety|filter|restriction|guard)/gi, severity: 'high' },
      { name: 'Base64 Hidden', pattern: /[A-Za-z0-9+/]{50,}={0,2}/g, severity: 'medium' },
    ];
    
    const issues: any[] = [];
    
    for (const { name, pattern, severity } of patterns) {
      const matches = content.match(pattern);
      if (matches) {
        for (const match of matches) {
          issues.push({
            type: 'injection',
            name,
            severity,
            match: match.substring(0, 50),
            action: 'block'
          });
        }
      }
    }
    
    return { issues };
  }
  
  /**
   * Scan for exfiltration patterns
   */
  async scanExfiltration(content: string) {
    const patterns = [
      { name: 'URL with Data', pattern: /https?:\/\/[^\s]+\?[^\s]*=(data|key|token|secret|password)/gi, severity: 'high' },
      { name: 'Webhook URL', pattern: /webhook[s]?\.site|requestbin|hookbin|pipedream/gi, severity: 'high' },
      { name: 'Data Encoding', pattern: /btoa\(|atob\(|encodeURIComponent\(/g, severity: 'medium' },
      { name: 'File Upload', pattern: /FormData|multipart\/form-data/gi, severity: 'medium' },
    ];
    
    const issues: any[] = [];
    
    for (const { name, pattern, severity } of patterns) {
      const matches = content.match(pattern);
      if (matches) {
        for (const match of matches) {
          issues.push({
            type: 'exfiltration',
            name,
            severity,
            match: match.substring(0, 50),
            action: 'alert'
          });
        }
      }
    }
    
    return { issues };
  }
  
  /**
   * Analyze code for security issues
   */
  async analyzeCode(code: string, _language?: string) {
    const patterns = [
      { name: 'eval()', pattern: /\beval\s*\(/g, severity: 'high' },
      { name: 'exec()', pattern: /\bexec\s*\(/g, severity: 'high' },
      { name: 'SQL Injection Risk', pattern: /(SELECT|INSERT|UPDATE|DELETE).*\$\{|['"].*\+.*['"].*\+/gi, severity: 'high' },
      { name: 'Shell Command', pattern: /child_process|subprocess|os\.system|shell_exec/g, severity: 'high' },
      { name: 'Hardcoded Secret', pattern: /(password|secret|api_key)\s*=\s*['"][^'"]+['"]/gi, severity: 'critical' },
    ];
    
    const issues: any[] = [];
    
    for (const { name, pattern, severity } of patterns) {
      const matches = code.match(pattern);
      if (matches) {
        for (const match of matches) {
          issues.push({
            type: 'code_pattern',
            name,
            severity,
            match: match.substring(0, 50),
            action: 'alert'
          });
        }
      }
    }
    
    return { issues };
  }
  
  /**
   * Get rules
   */
  async getRules() {
    return { rules: this.rules };
  }
  
  /**
   * Add rule
   */
  async addRule(rule: any) {
    this.rules.push({ ...rule, id: `rule_${Date.now()}` });
    return { success: true, rule_id: this.rules[this.rules.length - 1].id };
  }
  
  /**
   * Enable rule
   */
  async enableRule(id: string) {
    const rule = this.rules.find(r => r.id === id);
    if (rule) rule.enabled = true;
    return { success: !!rule };
  }
  
  /**
   * Disable rule
   */
  async disableRule(id: string) {
    const rule = this.rules.find(r => r.id === id);
    if (rule) rule.enabled = false;
    return { success: !!rule };
  }
  
  /**
   * Get stats
   */
  async getStats() {
    return this.stats;
  }
  
  /**
   * Call function by name (for OpenAI/Gemini function calling)
   */
  async call(fn: string, args: any) {
    switch (fn) {
      case 'mund_scan_content':
        return this.scan(args.content, args.scan_types);
      case 'mund_scan_secrets':
        return this.scanSecrets(args.content);
      case 'mund_scan_pii':
        return this.scanPII(args.content);
      case 'mund_scan_injection':
        return this.scanInjection(args.content);
      case 'mund_scan_exfiltration':
        return this.scanExfiltration(args.content);
      case 'mund_analyze_code':
        return this.analyzeCode(args.code, args.language);
      default:
        throw new Error(`Unknown function: ${fn}`);
    }
  }
  
  // Helpers
  private redactMatch(match: string): string {
    if (match.length <= 8) return '***';
    return match.substring(0, 4) + '...' + match.substring(match.length - 4);
  }
  
  private groupBySeverity(issues: any[]): Record<string, number> {
    return issues.reduce((acc, issue) => {
      acc[issue.severity] = (acc[issue.severity] || 0) + 1;
      return acc;
    }, {});
  }
  
  private calculateRiskLevel(issues: any[]): string {
    const severityScores: Record<string, number> = { critical: 10, high: 5, medium: 2, low: 1 };
    const score = issues.reduce((sum, i) => sum + (severityScores[i.severity] || 0), 0);
    if (score >= 10) return 'critical';
    if (score >= 5) return 'high';
    if (score >= 2) return 'medium';
    if (score >= 1) return 'low';
    return 'none';
  }
}
