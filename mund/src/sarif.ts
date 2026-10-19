/**
 * Mund - The Guardian Protocol
 * SARIF 2.1.0 output - for GitHub code scanning and other SARIF consumers
 *
 * https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 * GitHub-specific: rules carry `security-severity` (0.0-10.0) so code
 * scanning ranks alerts as critical/high/medium/low.
 */

import { createHash } from 'crypto';
import type { SecurityIssue, Severity } from './types.js';
import { computeRiskScore } from './scoring.js';

export interface SarifTarget {
  /** Path relative to the repository root, using forward slashes. */
  uri: string;
  issues: SecurityIssue[];
}

export interface SarifOptions {
  toolVersion: string;
  informationUri?: string;
}

type SarifLevel = 'error' | 'warning' | 'note' | 'none';

const LEVELS: Record<Severity, SarifLevel> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

/** GitHub maps >=9.0 critical, >=7.0 high, >=4.0 medium, >0.1 low. */
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: '9.5',
  high: '8.0',
  medium: '5.5',
  low: '3.0',
  info: '0.0',
};

export function toSarif(targets: SarifTarget[], options: SarifOptions): object {
  const rules = new Map<string, { issue: SecurityIssue; index: number }>();
  const results: object[] = [];
  const allIssues: SecurityIssue[] = [];

  for (const target of targets) {
    for (const issue of target.issues) {
      allIssues.push(issue);

      let rule = rules.get(issue.rule_id);
      if (!rule) {
        rule = { issue, index: rules.size };
        rules.set(issue.rule_id, rule);
      } else if (severityRank(issue.severity) < severityRank(rule.issue.severity)) {
        // A rule's descriptor takes the worst severity seen for it.
        rule.issue = issue;
      }

      results.push({
        ruleId: issue.rule_id,
        ruleIndex: rule.index,
        level: LEVELS[issue.severity] ?? 'warning',
        message: { text: issue.suggestion ? `${issue.rule_name}. ${issue.suggestion}` : issue.rule_name },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: target.uri },
            ...(issue.location?.line ? { region: toRegion(issue) } : {}),
          },
        }],
        partialFingerprints: {
          'mundFinding/v1': fingerprint(target.uri, issue),
        },
        properties: {
          severity: issue.severity,
          type: issue.type,
        },
      });
    }
  }

  const risk = computeRiskScore(allIssues);

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'Mund',
          fullName: 'Mund - The Guardian Protocol',
          version: options.toolVersion,
          semanticVersion: options.toolVersion,
          informationUri: options.informationUri ?? 'https://github.com/Tyox-all/Weave_Protocol/tree/main/mund',
          rules: [...rules.values()].map(({ issue }) => ({
            id: issue.rule_id,
            name: toPascalCase(issue.rule_name),
            shortDescription: { text: issue.rule_name },
            ...(issue.suggestion ? { help: { text: issue.suggestion } } : {}),
            defaultConfiguration: { level: LEVELS[issue.severity] ?? 'warning' },
            properties: {
              'security-severity': SECURITY_SEVERITY[issue.severity] ?? '5.5',
              tags: ['security', issue.type],
            },
          })),
        },
      },
      results,
      properties: {
        riskScore: risk.score,
        riskLabel: risk.label,
      },
    }],
  };
}

function toRegion(issue: SecurityIssue): object {
  const loc = issue.location!;
  const region: Record<string, number> = { startLine: loc.line! };
  if (loc.column) {
    region.startColumn = loc.column;
    const length = loc.end - loc.start;
    // Only emit endColumn for single-line matches; multi-line spans would
    // need the source text to compute endLine.
    if (length > 0 && !issue.match.includes('\n')) region.endColumn = loc.column + length;
  }
  return region;
}

function fingerprint(uri: string, issue: SecurityIssue): string {
  return createHash('sha256')
    .update(`${uri}\0${issue.rule_id}\0${issue.location?.line ?? 0}\0${issue.match}`)
    .digest('hex')
    .slice(0, 32);
}

function severityRank(severity: Severity): number {
  return ['critical', 'high', 'medium', 'low', 'info'].indexOf(severity);
}

function toPascalCase(text: string): string {
  return text.replace(/[^A-Za-z0-9]+(.)?/g, (_, c: string | undefined) => (c ? c.toUpperCase() : ''))
    .replace(/^./, c => c.toUpperCase());
}
