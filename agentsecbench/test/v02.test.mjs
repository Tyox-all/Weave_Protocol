// AgentSecBench 0.2: schema v1.1, suite validation/locking, summaries. Runs against dist/.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  ASB_BROWSER_V1, LOCKED_SUITE_HASHES, suiteManifestHash, validateSuite, loadSuiteFile,
  registerSuite, getSuite, runSuite, buildReport, summarizeReport, compareReports, CURRENT_SCHEMA_VERSION,
} from '../dist/index.js';

const copy = (over = {}) => ({ ...structuredClone(ASB_BROWSER_V1), ...over });
const meta = { name: 'test-target', type: 'test', vendor: 'Acme' };

function scorecard({ dynamic = false } = {}) {
  const findings = ASB_BROWSER_V1.attackIds.map((id, i) => ({
    attackId: id, category: id.split('.')[0] === 'ipi' ? 'ipi' : id.startsWith('tool.') ? 'tool_coercion' : 'extraction',
    severity: 'high', result: i === 0 ? 'breached' : 'blocked', evidence: 'SECRET-EVIDENCE',
    ...(dynamic && i === 0 ? { attempts: [
      { attemptNumber: 1, payload: 'p', responseText: 'r', result: 'blocked', evidence: 'e' },
      { attemptNumber: 2, payload: 'p2', responseText: 'r2', result: 'breached', evidence: 'e2' },
    ] } : {}),
  }));
  return {
    adversaryVersion: '0.3.0', target: { kind: 'demo', identifier: 'x' }, startedAt: Date.parse('2026-10-29T00:00:00Z'), durationMs: 5,
    summary: { total: findings.length, blocked: findings.length - 1, partial: 0, breached: 1, score: 90, byCategory: {}, bySeverity: {} },
    findings,
    ...(dynamic ? { dynamic: { enabled: true, model: 'claude-haiku-5-5', maxRetries: 2, variantsGenerated: 1, mutationInputTokens: 1, mutationOutputTokens: 1, mutationCostUSD: 0.001, mutationErrors: 0 } } : {}),
  };
}

test('ASB-Browser-v1 still matches its locked hash', () => {
  assert.equal(suiteManifestHash(ASB_BROWSER_V1), LOCKED_SUITE_HASHES['ASB-Browser-v1']);
});

test('manifest hash ignores attack order but not attack set', () => {
  assert.equal(suiteManifestHash(copy({ attackIds: [...ASB_BROWSER_V1.attackIds].reverse() })), suiteManifestHash(ASB_BROWSER_V1));
  assert.notEqual(suiteManifestHash(copy({ attackIds: ASB_BROWSER_V1.attackIds.slice(1) })), suiteManifestHash(ASB_BROWSER_V1));
});

test('built-in suite validates against the installed corpus', () => {
  assert.deepEqual(validateSuite(ASB_BROWSER_V1), { ok: true, errors: [], warnings: [] });
});

test('validation catches unknown ids, duplicates, stray trophies, bad tiers, bad id/version', () => {
  const trophyId = ASB_BROWSER_V1.trophyAttacks[0].attackId;
  const ids = ASB_BROWSER_V1.attackIds.filter((id) => id !== trophyId);
  const v = validateSuite(copy({
    id: 'browser-two', version: '2.0',
    attackIds: [...ids, ids[0], 'not.a_real_attack'],
    tierThresholds: { A: 50, B: 60, C: 70, D: 80 },
  }));
  assert.equal(v.ok, false);
  const all = v.errors.join('\n');
  for (const needle of ['ASB-<Name>-v<N>', 'version must be "1.0"', 'duplicate attack ids', 'not.a_real_attack', `(${trophyId}) is not in attackIds`, 'A > B > C > D']) {
    assert.ok(all.includes(needle), `expected error mentioning ${needle}\n${all}`);
  }
});

test('suite files load, validate, and register; locked ids are protected', () => {
  const dir = mkdtempSync(join(tmpdir(), 'asb-'));
  const good = join(dir, 'good.json');
  writeFileSync(good, JSON.stringify(copy({ id: 'ASB-Custom-v1', name: 'Custom', attackIds: ASB_BROWSER_V1.attackIds.slice(0, 10), trophyAttacks: [] })));
  const custom = loadSuiteFile(good);
  registerSuite(custom);
  assert.equal(getSuite('ASB-Custom-v1').attackIds.length, 10);
  assert.throws(() => registerSuite(copy()), /locked built-in suite/);
  const bad = join(dir, 'bad.json');
  writeFileSync(bad, JSON.stringify(copy({ id: 'ASB-Bad-v1', attackIds: ['nope.missing'] })));
  assert.throws(() => loadSuiteFile(bad), /not in the installed Adversary corpus/);
  rmSync(dir, { recursive: true, force: true });
});

test('runSuite refuses an invalid suite before touching the target', async () => {
  let calls = 0;
  const target = { kind: 'demo', identifier: 't', execute: async () => { calls++; return { text: '', toolCalls: [], turns: 1 }; } };
  await assert.rejects(runSuite({ target, suite: copy({ attackIds: ['nope.missing'] }), targetMeta: meta, ward: { loaded: false, rules: [] } }), /invalid/);
  assert.equal(calls, 0);
});

test('reports are schema 1.1 with the suite hash', () => {
  const r = buildReport(scorecard(), ASB_BROWSER_V1, meta);
  assert.equal(r.schemaVersion, CURRENT_SCHEMA_VERSION);
  assert.equal(r.schemaVersion, '1.1');
  assert.equal(r.suite.manifestHash, LOCKED_SUITE_HASHES['ASB-Browser-v1']);
  assert.equal(r.run.dynamic, undefined);
  assert.equal(r.result.variantOnly, undefined);
});

test('dynamic runs record mutation metadata and variant-only results', () => {
  const r = buildReport(scorecard({ dynamic: true }), ASB_BROWSER_V1, { ...meta, model: 'claude-haiku-5-5' });
  assert.deepEqual(r.run.dynamic, { model: 'claude-haiku-5-5', maxRetries: 2, variantsGenerated: 1, mutationCostUSD: 0.001 });
  assert.equal(r.result.variantOnly, 1);
  assert.equal(r.target.model, 'claude-haiku-5-5');
});

test('summaries drop all evidence, and the vendor when anonymized', () => {
  const r = buildReport(scorecard({ dynamic: true }), ASB_BROWSER_V1, { ...meta, anonymized: true });
  const s = summarizeReport(r);
  const json = JSON.stringify(s);
  assert.equal('scorecard' in s, false);
  assert.ok(!json.includes('SECRET-EVIDENCE'));
  assert.ok(!json.includes('Acme'));
  assert.equal(s.summaryVersion, '1');
  assert.equal(summarizeReport(buildReport(scorecard(), ASB_BROWSER_V1, meta)).target.vendor, 'Acme');
});

test('a v1.0 report still compares against a v1.1 report', () => {
  const v11 = buildReport(scorecard(), ASB_BROWSER_V1, meta);
  const v10 = structuredClone(v11);
  v10.schemaVersion = '1.0';
  delete v10.suite.manifestHash;
  const cmp = compareReports(v10, v11);
  assert.equal(cmp.suite.id, 'ASB-Browser-v1');
  assert.equal(cmp.scoreDelta, 0);
});

test('CLI validate exits 1 for a bad suite file and 0 otherwise', () => {
  const dir = mkdtempSync(join(tmpdir(), 'asb-cli-'));
  const bad = join(dir, 'bad.json');
  writeFileSync(bad, JSON.stringify(copy({ id: 'ASB-Bad-v1', attackIds: ['nope.missing'] })));
  assert.equal(spawnSync(process.execPath, ['dist/cli.js', 'validate']).status, 0);
  const r = spawnSync(process.execPath, ['dist/cli.js', 'validate', `--suite-file=${bad}`], { encoding: 'utf8' });
  assert.equal(r.status, 1);
  assert.match(r.stdout, /not in the installed Adversary corpus/);
  rmSync(dir, { recursive: true, force: true });
});
