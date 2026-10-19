import { describe, expect, it } from 'vitest';
import { compileRulePattern } from '../../src/analyzers/regex.js';
import { SecretScanner } from '../../src/analyzers/secret-scanner.js';
import { DEFAULT_RULES } from '../../src/constants.js';

describe('compileRulePattern', () => {
  it('translates a leading (?i) into the i flag', () => {
    const re = compileRulePattern('(?i)secret', 'g');
    expect(re.flags).toBe('gi');
    expect(re.source).toBe('secret');
    expect(re.test('SECRET')).toBe(true);
  });

  it('does not duplicate flags', () => {
    expect(compileRulePattern('(?i)x', 'gi').flags).toBe('gi');
  });

  it('leaves ordinary patterns alone', () => {
    expect(compileRulePattern('a(?:b)c', 'g').source).toBe('a(?:b)c');
  });

  it('compiles every default rule pattern', () => {
    for (const rule of DEFAULT_RULES) {
      if (rule.pattern) expect(() => compileRulePattern(rule.pattern!, 'g'), rule.id).not.toThrow();
    }
  });
});

describe('(?i) rules actually fire', () => {
  it('detects an AWS secret access key assignment', async () => {
    const content = 'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"';
    const issues = await new SecretScanner().analyze(content, DEFAULT_RULES);
    expect(issues.map(i => i.rule_id)).toContain('aws_secret_access_key');
  });
});
