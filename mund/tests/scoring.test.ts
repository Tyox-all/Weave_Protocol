import { describe, expect, it } from 'vitest';
import { computeRiskScore, labelForScore } from '../src/scoring.js';
import type { Severity } from '../src/types.js';

const of = (...severities: Severity[]) => severities.map(severity => ({ severity }));

describe('computeRiskScore', () => {
  it('scores no findings as 0 / none', () => {
    expect(computeRiskScore([])).toMatchObject({ score: 0, label: 'none' });
  });

  it('treats info-only findings as no risk', () => {
    expect(computeRiskScore(of('info', 'info'))).toMatchObject({ score: 0, label: 'none' });
  });

  it('puts a single finding in its own severity band', () => {
    expect(computeRiskScore(of('critical')).label).toBe('critical');
    expect(computeRiskScore(of('high')).label).toBe('high');
    expect(computeRiskScore(of('medium')).label).toBe('medium');
    expect(computeRiskScore(of('low')).label).toBe('low');
  });

  it('is monotonic and capped at 100', () => {
    let prev = 0;
    for (let n = 1; n <= 20; n++) {
      const { score } = computeRiskScore(of(...Array<Severity>(n).fill('high')));
      expect(score).toBeGreaterThanOrEqual(prev);
      expect(score).toBeLessThanOrEqual(100);
      prev = score;
    }
    expect(prev).toBe(100);
  });

  it('needs many low findings to escalate', () => {
    expect(computeRiskScore(of('low', 'low', 'low')).label).toBe('low');
    expect(computeRiskScore(of('low', 'low', 'low', 'low')).label).toBe('medium');
  });

  it('counts findings by severity', () => {
    expect(computeRiskScore(of('high', 'high', 'low', 'info')).counts)
      .toEqual({ critical: 0, high: 2, medium: 0, low: 1, info: 1 });
  });
});

describe('labelForScore', () => {
  it.each([[0, 'none'], [1, 'low'], [14, 'low'], [15, 'medium'], [39, 'medium'], [40, 'high'], [79, 'high'], [80, 'critical'], [100, 'critical']])(
    '%i -> %s', (score, label) => expect(labelForScore(score)).toBe(label),
  );
});
