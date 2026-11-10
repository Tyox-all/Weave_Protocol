import { readFileSync } from 'node:fs';
const { scan } = await import('' + new URL('../dist/index.js', import.meta.url).href + '');
const rows = JSON.parse(readFileSync('' + (process.env.MUND_TRAINING_DATA ?? new URL('./data', import.meta.url).pathname) + '/sec/security.json', 'utf8'));
const ACT = new Set(['medium', 'high', 'critical']);
const types = process.argv[2] ? { types: [process.argv[2]] } : {};
const hits = {}; let n = 0;
for (const r of rows) { const iss = (await scan(r.text, types)).issues.filter((i) => ACT.has(i.severity)); if (iss.length) { n++; for (const id of new Set(iss.map((i) => i.rule_id))) (hits[id] ??= []).push(r.src + ' ' + r.name + ' :: ' + r.text.slice(0, 90).replace(/\n/g, ' ')); } }
console.log('flagged', n, '/', rows.length);
for (const [k, v] of Object.entries(hits).sort((a, b) => b[1].length - a[1].length)) { console.log(k, v.length); for (const x of v.slice(0, 3)) console.log('   ', x); }
