import { describe, expect, it } from 'vitest';
import { toSarif } from '../src/sarif.js';
import type { SecurityIssue } from '../src/types.js';

const issue = (over: Partial<SecurityIssue> = {}): SecurityIssue => ({
  rule_id: 'aws_access_key_id', rule_name: 'AWS Access Key ID', type: 'secret',
  severity: 'critical', action: 'alert', match: 'AKIA****',
  location: { start: 12, end: 32, line: 2, column: 5 }, suggestion: 'Use IAM roles.',
  ...over,
});

const run = (sarif: any) => sarif.runs[0];

describe('toSarif', () => {
  it('emits a SARIF 2.1.0 log with tool metadata', () => {
    const log: any = toSarif([], { toolVersion: '1.2.3' });
    expect(log.version).toBe('2.1.0');
    expect(run(log).tool.driver).toMatchObject({ name: 'Mund', version: '1.2.3' });
    expect(run(log).results).toEqual([]);
    expect(run(log).properties).toEqual({ riskScore: 0, riskLabel: 'none' });
  });

  it('maps a finding to a result with region and fingerprint', () => {
    const r = run(toSarif([{ uri: 'src/a.ts', issues: [issue()] }], { toolVersion: '0' })).results[0];
    expect(r).toMatchObject({
      ruleId: 'aws_access_key_id',
      ruleIndex: 0,
      level: 'error',
      message: { text: 'AWS Access Key ID. Use IAM roles.' },
      locations: [{ physicalLocation: { artifactLocation: { uri: 'src/a.ts' }, region: { startLine: 2, startColumn: 5, endColumn: 25 } } }],
    });
    expect(r.partialFingerprints['mundFinding/v1']).toMatch(/^[0-9a-f]{32}$/);
  });

  it('maps severities to levels and GitHub security-severity', () => {
    const issues = (['critical', 'high', 'medium', 'low', 'info'] as const).map(s => issue({ rule_id: s, severity: s }));
    const r = run(toSarif([{ uri: 'a', issues }], { toolVersion: '0' }));
    expect(r.results.map((x: any) => x.level)).toEqual(['error', 'error', 'warning', 'note', 'note']);
    expect(r.tool.driver.rules.map((x: any) => x.properties['security-severity'])).toEqual(['9.5', '8.0', '5.5', '3.0', '0.0']);
  });

  it('dedupes rules and keeps the worst severity per rule', () => {
    const issues = [issue({ severity: 'medium' }), issue({ severity: 'high', location: { start: 0, end: 1, line: 9 } })];
    const r = run(toSarif([{ uri: 'a', issues }], { toolVersion: '0' }));
    expect(r.tool.driver.rules).toHaveLength(1);
    expect(r.tool.driver.rules[0].defaultConfiguration.level).toBe('error');
    expect(r.results.map((x: any) => x.ruleIndex)).toEqual([0, 0]);
  });

  it('omits region when the finding has no line', () => {
    const r = run(toSarif([{ uri: 'a', issues: [issue({ location: undefined })] }], { toolVersion: '0' })).results[0];
    expect(r.locations[0].physicalLocation.region).toBeUndefined();
  });

  it('gives distinct fingerprints to distinct findings', () => {
    const r = run(toSarif([{ uri: 'a', issues: [issue(), issue({ location: { start: 0, end: 1, line: 7 } })] }], { toolVersion: '0' }));
    expect(r.results[0].partialFingerprints['mundFinding/v1']).not.toBe(r.results[1].partialFingerprints['mundFinding/v1']);
  });
});
