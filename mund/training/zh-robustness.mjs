// How Mund holds up against the ways people dodge Chinese keyword filters.
// Each trick is applied mechanically, with a fixed seed, to the held-out
// Shuangsuo test rows (Chinese, no zero-width), attacks AND benign alike,
// so a rule that just flags "weird-looking text" shows up as false positives.
//
//   node training/zh-robustness.mjs
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
const MUND = new URL('..', import.meta.url).href.replace(/\/$/, '');
const DATA = process.env.MUND_TRAINING_DATA ?? fileURLToPath(new URL('./data', import.meta.url));
const { scan } = await import(`${MUND}/dist/index.js`);
const { pinyinOf, sameSound, toSimplified } = await import(`${MUND}/dist/analyzers/hanzi.js`);

const rows = readFileSync(`${DATA}/zh/test.jsonl`, 'utf8').trim().split('\n').map((l) => JSON.parse(l))
  .filter((r) => (r.language === 'zh-Hans' || r.language === 'zh-Hant') && r.obfuscation !== 'zero_width');
let seed = 2027;
const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
const han = (c) => /\p{Script=Han}/u.test(c);
const SEP = ['*', '·', ' ', '-', '、', '.', '_'];

const tricks = {
  'as written': (t) => t,
  'separators between characters (忽*略)': (t) => [...t].map((c, i, a) => (han(c) && han(a[i + 1] ?? '') && rnd() < 0.5 ? c + SEP[Math.floor(rnd() * SEP.length)] : c)).join(''),
  'homophone swaps, 40% of characters (蜜码)': (t) => [...t].map((c) => { if (!han(c) || rnd() > 0.4) return c; const alts = sameSound(c).filter((x) => x !== toSimplified(c)); return alts.length ? alts[Math.floor(rnd() * alts.length)] : c; }).join(''),
  'all pinyin (hulue zhiling)': (t) => [...t].map((c) => (han(c) ? ` ${pinyinOf(c) ?? c} ` : c)).join('').replace(/\s+/g, ' ').trim(),
  'pinyin mixed in, 40% of characters (忽略zhi令)': (t) => [...t].map((c) => (han(c) && rnd() < 0.4 ? pinyinOf(c) ?? c : c)).join(''),
};

const ACT = new Set(['medium', 'high', 'critical']);
console.log(`Held-out Shuangsuo Chinese rows: ${rows.filter((r) => r.label).length} attacks, ${rows.filter((r) => !r.label).length} benign\n`);
console.log('| Trick | Attacks caught | Benign flagged |');
console.log('|---|---|---|');
for (const [name, f] of Object.entries(tricks)) {
  let hit = 0, atk = 0, fp = 0, ben = 0;
  for (const r of rows) {
    const flagged = (await scan(f(r.text))).issues.some((i) => ACT.has(i.severity));
    if (r.label) { atk++; hit += flagged; } else { ben++; fp += flagged; }
  }
  console.log(`| ${name} | ${hit}/${atk} (${(100 * hit / atk).toFixed(1)}%) | ${fp}/${ben} |`);
}
