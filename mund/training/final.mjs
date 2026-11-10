import { fileURLToPath as __f } from 'node:url';
const MUND = new URL('..', import.meta.url).href.replace(/\/$/, '');
const DATA = process.env.MUND_TRAINING_DATA ?? __f(new URL('./data', import.meta.url));
// Final, single evaluation of the shipped model through Mund's scan(). Severity >= medium counts, as in the red-team.
import { writeFileSync } from 'node:fs';
import { loadSplits } from './split.mjs';
const { scan } = await import('' + MUND + '/dist/index.js');
const { test } = loadSplits('' + DATA + '');
const ACT = new Set(['medium', 'high', 'critical']);
const flagged = async (t, on) => { process.env.MUND_CLASSIFIER = on ? '1' : '0'; return (await scan(t, { types: ['injection'] })).issues.filter((i) => ACT.has(i.severity)); };
const pct = (a, b) => (b ? (100 * a / b).toFixed(1) + '%' : '-');
const rows = [];
const t0 = Date.now(); let calls = 0;
for (const [name, { rows: data }] of Object.entries(test)) {
  const r = { set: name, attacks: 0, benign: 0, before: 0, after: 0, fpBefore: 0, fpAfter: 0, fps: [] };
  for (const x of data) {
    const b = (await flagged(x.text, false)).length > 0; const issues = await flagged(x.text, true); const a = issues.length > 0; calls++;
    if (x.label) { r.attacks++; r.before += b; r.after += a; } else { r.benign++; r.fpBefore += b; r.fpAfter += a; if (a) r.fps.push(issues.map((i) => i.rule_id).join(',') + ' :: ' + x.text.slice(0, 120).replace(/\n/g, ' ')); }
  }
  rows.push(r);
  console.log(name.padEnd(36), r.attacks ? `attacks ${String(r.attacks).padStart(5)}  rules ${pct(r.before, r.attacks).padStart(6)} -> with classifier ${pct(r.after, r.attacks).padStart(6)}` : ''.padEnd(55), r.benign ? `  benign flagged ${r.fpBefore}/${r.benign} -> ${r.fpAfter}/${r.benign}` : '');
}
console.log('avg ms per text (classifier on)', ((Date.now() - t0) / calls).toFixed(2));
for (const r of rows) for (const f of r.fps) console.log('  FP', r.set, '|', f);
writeFileSync('' + DATA + '/final-report.json', JSON.stringify(rows, null, 1));
