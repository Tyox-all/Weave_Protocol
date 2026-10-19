import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SecretScanner } from '../../src/analyzers/secret-scanner.js';
import { DEFAULT_RULES } from '../../src/constants.js';
import type { DetectionRule } from '../../src/types.js';

const scanner = new SecretScanner();

describe('SecretScanner', () => {
  beforeEach(() => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('detects an AWS access key id with line/column location', async () => {
    const content = 'line one\nconst key = "AKIAIOSFODNN7EXAMPLE";';
    const issues = await scanner.analyze(content, DEFAULT_RULES);
    const aws = issues.find(i => i.rule_id === 'aws_access_key_id');

    expect(aws).toBeDefined();
    expect(aws!.severity).toBe('critical');
    expect(aws!.location).toEqual({ start: 22, end: 42, line: 2, column: 14 });
    expect(aws!.suggestion).toMatch(/IAM roles/);
  });

  it('redacts the matched secret', async () => {
    const issues = await scanner.analyze('AKIAIOSFODNN7EXAMPLE', DEFAULT_RULES);
    const aws = issues.find(i => i.rule_id === 'aws_access_key_id')!;
    expect(aws.match).toBe('AKIA************MPLE');
    expect(aws.match).not.toContain('IOSFODNN7EXA');
  });

  it('detects GitHub tokens and private key blocks', async () => {
    const content = [
      'token=ghp_' + 'a'.repeat(36),
      '-----BEGIN RSA PRIVATE KEY-----',
    ].join('\n');
    const ids = (await scanner.analyze(content, DEFAULT_RULES)).map(i => i.rule_id);
    expect(ids).toContain('github_token');
    expect(ids).toContain('private_key_block');
  });

  it('returns nothing for clean content', async () => {
    await expect(scanner.analyze('const greeting = "hello world";', DEFAULT_RULES)).resolves.toEqual([]);
  });

  it('ignores disabled rules and non-secret rules', async () => {
    const rules: DetectionRule[] = [
      { id: 'off', name: 'Off', description: '', type: 'secret', pattern: 'foo', severity: 'high', action: 'alert', enabled: false },
      { id: 'pii', name: 'PII', description: '', type: 'pii', pattern: 'foo', severity: 'high', action: 'alert', enabled: true },
    ];
    await expect(scanner.analyze('foo', rules)).resolves.toEqual([]);
  });

  it('skips a rule with an invalid regex instead of throwing', async () => {
    const rules: DetectionRule[] = [
      { id: 'bad', name: 'Bad', description: '', type: 'secret', pattern: '(foo', severity: 'high', action: 'alert', enabled: true },
      { id: 'good', name: 'Good', description: '', type: 'secret', pattern: 'foo', severity: 'high', action: 'alert', enabled: true },
    ];
    const issues = await scanner.analyze('foo', rules);
    expect(issues.map(i => i.rule_id)).toEqual(['good']);
    expect(issues[0].match).toBe('****');
  });

  describe('entropy helpers', () => {
    it('calculates Shannon entropy', () => {
      expect(SecretScanner.calculateEntropy('')).toBe(0);
      expect(SecretScanner.calculateEntropy('aaaa')).toBe(0);
      expect(SecretScanner.calculateEntropy('abcd')).toBe(2);
    });

    it('flags random-looking strings only', () => {
      expect(SecretScanner.isHighEntropy('aZ3kP9qW2xL7mN5bR8cT1vY4dF6gH0jK')).toBe(true);
      expect(SecretScanner.isHighEntropy('short1!')).toBe(false);
      expect(SecretScanner.isHighEntropy('onlylettersherexyzabc')).toBe(false);
      expect(SecretScanner.isHighEntropy('src/aZ3kP9qW2xL7mN5/path')).toBe(false);
    });
  });
});
