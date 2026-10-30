/**
 * Mund Service - backed by @weave_protocol/mund
 *
 * Scans run Mund's real analyzers and rules (the same pipeline as the
 * mund_scan_content MCP tool). Matches come back masked by Mund.
 * Rule changes made through the API apply to this service's rule set.
 */

import { scan as mundScan, DEFAULT_RULES, type DetectionRule, type ScanType, type SecurityIssue } from '@weave_protocol/mund';

const SCAN_TYPES: ScanType[] = ['secrets', 'pii', 'injection', 'exfiltration', 'code'];

export class MundService {
  private stats = {
    total_scans: 0,
    threats_detected: 0,
    scans_by_type: {} as Record<string, number>
  };

  /** Built-in rules plus any added through the API; enable/disable edits this copy. */
  private rules: DetectionRule[] = DEFAULT_RULES.map((r) => ({ ...r }));

  /**
   * Full security scan
   */
  async scan(content: string, scanTypes?: string[]) {
    const types = (scanTypes?.length ? scanTypes : ['secrets', 'pii', 'injection', 'exfiltration']) as ScanType[];
    const unknown = types.filter((t) => !SCAN_TYPES.includes(t));
    if (unknown.length) throw new Error(`Unknown scan type(s): ${unknown.join(', ')}. Use: ${SCAN_TYPES.join(', ')}`);

    this.stats.total_scans++;
    for (const t of types) this.stats.scans_by_type[t] = (this.stats.scans_by_type[t] || 0) + 1;

    const { issues, risk } = await mundScan(content, { types, rules: this.rules });
    this.stats.threats_detected += issues.length;

    return {
      scanned: true,
      content_length: content.length,
      scan_types: types,
      issues,
      summary: {
        total_issues: issues.length,
        by_severity: risk.counts,
        risk_level: risk.label,
        risk_score: risk.score
      }
    };
  }

  async scanSecrets(content: string) {
    return this.scanOnly(content, 'secrets');
  }

  async scanPII(content: string) {
    return this.scanOnly(content, 'pii');
  }

  async scanInjection(content: string) {
    return this.scanOnly(content, 'injection');
  }

  async scanExfiltration(content: string) {
    return this.scanOnly(content, 'exfiltration');
  }

  async analyzeCode(code: string, _language?: string) {
    return this.scanOnly(code, 'code');
  }

  async getRules() {
    return { rules: this.rules };
  }

  async addRule(rule: Partial<DetectionRule>) {
    if (!rule.name || !rule.type || !rule.pattern || !rule.severity) {
      throw new Error('rule needs name, type, pattern and severity');
    }
    try {
      new RegExp(rule.pattern);
    } catch {
      throw new Error('rule.pattern is not a valid regular expression');
    }
    const id = rule.id || `custom_${Date.now()}`;
    this.rules.push({ action: 'alert', enabled: true, description: '', ...rule, id } as DetectionRule);
    return { success: true, rule_id: id };
  }

  async enableRule(id: string) {
    return this.setEnabled(id, true);
  }

  async disableRule(id: string) {
    return this.setEnabled(id, false);
  }

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
  private async scanOnly(content: string, type: ScanType): Promise<{ issues: SecurityIssue[]; risk: { score: number; label: string } }> {
    this.stats.total_scans++;
    this.stats.scans_by_type[type] = (this.stats.scans_by_type[type] || 0) + 1;
    const { issues, risk } = await mundScan(content, { types: [type], rules: this.rules });
    this.stats.threats_detected += issues.length;
    return { issues, risk: { score: risk.score, label: risk.label } };
  }

  private setEnabled(id: string, enabled: boolean) {
    const rule = this.rules.find((r) => r.id === id);
    if (rule) rule.enabled = enabled;
    return { success: !!rule };
  }
}
