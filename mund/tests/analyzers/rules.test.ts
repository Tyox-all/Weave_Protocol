import { describe, expect, it } from 'vitest';
import { DEFAULT_RULES } from '../../src/constants.js';
import { compileRulePattern } from '../../src/analyzers/regex.js';

describe('DEFAULT_RULES', () => {
  it('has unique rule ids', () => {
    const ids = DEFAULT_RULES.map(r => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  // Analyzers compile patterns with compileRulePattern, which turns a leading
  // (?i) into a flag. Every default rule must compile that way.
  it('every rule compiles the way the analyzers load it', () => {
    const broken = DEFAULT_RULES.filter(r => {
      if (!r.pattern) return false;
      try {
        compileRulePattern(r.pattern, 'g');
        return false;
      } catch {
        return true;
      }
    }).map(r => r.id);
    expect(broken).toEqual([]);
  });
});
