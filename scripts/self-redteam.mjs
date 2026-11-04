#!/usr/bin/env node
/**
 * Self red-team: runs Weave's own attack corpora (Adversary's and the
 * AgentSecBench suites) through Weave's defenses, offline and with no model:
 *
 *   - Mund scans every attack payload, the way it would scan a page, tool
 *     result or message before an agent sees it, and a benign corpus
 *     (mund/tests/fixtures/benign) to measure false positives. "Flagged"
 *     means at least one finding at medium severity or higher, the level
 *     at which Mund's risk label becomes actionable.
 *   - Ward evaluates the tool calls a coerced agent would make (from
 *     scripts/redteam-toolcalls.json) against a reference WARD policy.
 *
 * Writes a scorecard (JSON and Markdown) and fails if a rate drops below
 * the committed baseline (scripts/redteam-baseline.json). Run after the
 * packages are built:  node scripts/self-redteam.mjs [--out=dir] [--update-baseline]
 *
 * Caveat in every report: the corpora are ours, so these are regression
 * numbers, not a measure of how Weave does against attacks it hasn't seen.
 */
import { readFileSync, writeFileSync, mkdirSync, appendFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const imp = (pkg) => import(join(root, pkg, 'dist', 'index.js'));
const flags = Object.fromEntries(process.argv.slice(2).map((a) => a.replace(/^--/, '').split('=')).map(([k, v]) => [k, v ?? true]));
const outDir = flags.out ? String(flags.out) : join(root, 'redteam-report');

const { ALL_ATTACKS } = await imp('adversary');
const { listSuites } = await imp('agentsecbench');
const { scan } = await imp('mund');
const { parseWard, evaluateToolCall } = await imp('ward');
const pkg = (name) => JSON.parse(readFileSync(join(root, name, 'package.json'), 'utf8')).version;

// ── Mund over every payload ────────────────────────────────
const corpus = ALL_ATTACKS.map((a) => ({ id: a.id, category: a.category, payload: typeof a.payload === 'function' ? a.payload() : a.payload }));
const ACTIONABLE = new Set(['medium', 'high', 'critical']);
const flagged = async (text) => (await scan(text)).issues.filter((i) => ACTIONABLE.has(i.severity));
const mundRows = [];
for (const a of corpus) {
  const issues = await flagged(a.payload);
  mundRows.push({ ...a, detected: issues.length > 0 });
}
const benign = JSON.parse(readFileSync(join(root, 'mund', 'tests', 'fixtures', 'benign', 'corpus.json'), 'utf8'));
const falsePositives = [];
for (const b of benign) {
  const issues = await flagged(b.text);
  if (issues.length) falsePositives.push(`${b.id}: ${[...new Set(issues.map((i) => i.rule_id))].join(', ')}`);
}
const rate = (rows, key) => (rows.length ? rows.filter((r) => r[key]).length / rows.length : 0);
const byCategory = {};
for (const r of mundRows) (byCategory[r.category] ??= []).push(r);

// ── Ward over coerced tool calls ───────────────────────────
const fixture = JSON.parse(readFileSync(join(root, 'scripts', 'redteam-toolcalls.json'), 'utf8'));
const policy = parseWard(fixture.policy.join('\n'));
const wardRows = fixture.calls.map((c) => {
  const r = evaluateToolCall(policy, c.tool, c.args, { cwd: fixture.cwd, mappings: fixture.mappings });
  return { id: c.id, expect: c.expect, decision: r.decision, ok: c.expect === 'allow' ? r.decision === 'allow' : r.decision !== 'allow' };
});

const scorecard = {
  generatedAt: new Date().toISOString(),
  versions: { adversary: pkg('adversary'), agentsecbench: pkg('agentsecbench'), mund: pkg('mund'), ward: pkg('ward') },
  mund: {
    payloads: mundRows.length,
    detectionRate: rate(mundRows, 'detected'),
    byCategory: Object.fromEntries(Object.entries(byCategory).map(([k, rows]) => [k, { payloads: rows.length, detectionRate: rate(rows, 'detected') }])),
    // The AgentSecBench suites are locked subsets of the Adversary corpus
    bySuite: Object.fromEntries(listSuites().map((suite) => {
      const rows = mundRows.filter((r) => suite.attackIds.includes(r.id));
      return [suite.id, { payloads: rows.length, detectionRate: rate(rows, 'detected') }];
    })),
    missed: mundRows.filter((r) => !r.detected).map((r) => r.id),
    benign: benign.length,
    falsePositiveRate: benign.length ? falsePositives.length / benign.length : 0,
    falsePositives,
  },
  ward: {
    calls: wardRows.length,
    correctRate: rate(wardRows, 'ok'),
    blocked: wardRows.filter((r) => r.expect !== 'allow' && r.ok).length,
    wrong: wardRows.filter((r) => !r.ok).map((r) => `${r.id}: expected ${r.expect}, got ${r.decision}`),
  },
  caveat: 'Weave\'s own corpora: regression numbers, not a measure against unseen attacks.',
};

// ── Report and gate ────────────────────────────────────────
const pct = (x) => `${(x * 100).toFixed(1)}%`;
const md = [
  '## Weave self red-team',
  '',
  `Mund flagged **${pct(scorecard.mund.detectionRate)}** of ${scorecard.mund.payloads} attack payloads and **${pct(scorecard.mund.falsePositiveRate)}** of ${scorecard.mund.benign} benign texts (medium severity or higher). Ward decided **${pct(scorecard.ward.correctRate)}** of ${scorecard.ward.calls} coerced tool calls correctly.`,
  '',
  '| Mund by category | Payloads | Flagged |',
  '|---|---|---|',
  ...Object.entries(scorecard.mund.byCategory).map(([k, v]) => `| ${k} | ${v.payloads} | ${pct(v.detectionRate)} |`),
  ...Object.entries(scorecard.mund.bySuite).map(([k, v]) => `| _suite ${k}_ | ${v.payloads} | ${pct(v.detectionRate)} |`),
  '',
  scorecard.mund.falsePositives.length ? `Mund false positives: ${scorecard.mund.falsePositives.join('; ')}` : 'Mund: no false positives on the benign corpus.',
  '',
  scorecard.ward.wrong.length ? `Ward misses: ${scorecard.ward.wrong.join('; ')}` : 'Ward: every call decided as expected.',
  '',
  `Versions: ${Object.entries(scorecard.versions).map(([k, v]) => `${k} ${v}`).join(', ')}. _${scorecard.caveat}_`,
].join('\n');

mkdirSync(outDir, { recursive: true });
writeFileSync(join(outDir, 'scorecard.json'), JSON.stringify(scorecard, null, 2) + '\n');
writeFileSync(join(outDir, 'scorecard.md'), md + '\n');
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, md + '\n');
console.log(md);

const baselinePath = join(root, 'scripts', 'redteam-baseline.json');
const current = { mundDetectionRate: scorecard.mund.detectionRate, mundFalsePositiveRate: scorecard.mund.falsePositiveRate, wardCorrectRate: scorecard.ward.correctRate };
// Rates that must not rise (everything else must not fall)
const CEILINGS = new Set(['mundFalsePositiveRate']);
if (flags['update-baseline']) {
  writeFileSync(baselinePath, JSON.stringify(current, null, 2) + '\n');
  console.log(`\nBaseline updated: ${baselinePath}`);
} else {
  const baseline = JSON.parse(readFileSync(baselinePath, 'utf8'));
  const drops = Object.entries(baseline)
    .filter(([k, v]) => (CEILINGS.has(k) ? current[k] > v + 1e-9 : current[k] + 1e-9 < v))
    .map(([k, v]) => `${k} ${pct(current[k])} ${CEILINGS.has(k) ? '>' : '<'} baseline ${pct(v)}`);
  if (drops.length) {
    console.error(`\nRegression: ${drops.join('; ')}`);
    process.exit(1);
  }
}
