import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AnalyzerEngine, getAnalyzers } from '../../src/analyzers/index.js';
import { DEFAULT_RULES } from '../../src/constants.js';
import type { IAnalyzer, SecurityIssue } from '../../src/types.js';

const issue = (rule_id: string, severity: SecurityIssue['severity']): SecurityIssue => ({
  rule_id, rule_name: rule_id, type: 'secret', severity, action: 'alert', match: '',
});

describe('AnalyzerEngine', () => {
  beforeEach(() => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('includes every analyzer by default', () => {
    expect(new AnalyzerEngine().getAnalyzerNames()).toEqual(getAnalyzers().map(a => a.name));
    expect(getAnalyzers()).toHaveLength(6);
  });

  it('sorts high/medium/low in severity order', async () => {
    const fake: IAnalyzer = {
      name: 'Fake', type: 'secret',
      analyze: async () => [issue('low', 'low'), issue('med', 'medium'), issue('high', 'high')],
    };
    const issues = await new AnalyzerEngine([fake]).analyzeAll('x', []);
    expect(issues.map(i => i.rule_id)).toEqual(['high', 'med', 'low']);
  });

  it('sorts critical issues first', async () => {
    const fake: IAnalyzer = {
      name: 'Fake', type: 'secret',
      analyze: async () => [issue('low', 'low'), issue('crit', 'critical'), issue('med', 'medium'), issue('high', 'high')],
    };
    const issues = await new AnalyzerEngine([fake]).analyzeAll('x', []);
    expect(issues.map(i => i.rule_id)).toEqual(['crit', 'high', 'med', 'low']);
  });

  it('keeps going when one analyzer throws', async () => {
    const broken: IAnalyzer = { name: 'Broken', type: 'secret', analyze: async () => { throw new Error('nope'); } };
    const ok: IAnalyzer = { name: 'Ok', type: 'secret', analyze: async () => [issue('found', 'high')] };
    const issues = await new AnalyzerEngine([broken, ok]).analyzeAll('x', []);
    expect(issues.map(i => i.rule_id)).toEqual(['found']);
  });

  it('adds and removes analyzers by name', () => {
    const engine = new AnalyzerEngine([]);
    engine.addAnalyzer({ name: 'A', type: 'secret', analyze: async () => [] });
    engine.addAnalyzer({ name: 'B', type: 'secret', analyze: async () => [] });
    engine.removeAnalyzer('A');
    expect(engine.getAnalyzerNames()).toEqual(['B']);
  });

  it('finds a secret end-to-end with the default rules', async () => {
    const issues = await new AnalyzerEngine().analyzeAll('const k = "AKIAIOSFODNN7EXAMPLE"', DEFAULT_RULES);
    expect(issues[0].rule_id).toBe('aws_access_key_id');
  });
});
