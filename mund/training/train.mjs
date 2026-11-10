import { fileURLToPath as __f } from 'node:url';
const MUND = new URL('..', import.meta.url).href.replace(/\/$/, '');
const DATA = process.env.MUND_TRAINING_DATA ?? __f(new URL('./data', import.meta.url));
import { writeFileSync } from 'node:fs';
import { loadSplits } from './split.mjs';
const C = await import('' + MUND + '/dist/analyzers/classifier.js');
const { train, val, test } = loadSplits('' + DATA + '');
const args = Object.fromEntries(process.argv.slice(2).map((a) => a.replace(/^--/, '').split('=')));
const EPOCHS = +(args.epochs ?? 12), L2 = +(args.l2 ?? 1e-6), LR = +(args.lr ?? 0.5), MAXFP = +(args.maxfp ?? 0.005);
console.log('train', train.length, 'attacks', train.filter((r) => r.label).length, '| val', val.length, 'attacks', val.filter((r) => r.label).length);
const X = train.map((r) => [C.featurize(r.text), r.label]);
const pos = train.filter((r) => r.label).length, neg = train.length - pos;
const wPos = train.length / (2 * pos), wNeg = train.length / (2 * neg);
const w = new Float64Array(1 << C.FEATURE_BITS), g2 = new Float64Array(1 << C.FEATURE_BITS);
let bias = 0, gb = 0;
let seed = 42; const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
for (let e = 0; e < EPOCHS; e++) {
  const order = X.map((_, i) => i).sort(() => rnd() - 0.5);
  for (const i of order) {
    const [f, y] = X[i];
    let z = bias; for (const [k, x] of f) z += w[k] * x;
    const p = 1 / (1 + Math.exp(-z));
    const err = (p - y) * (y ? wPos : wNeg);
    for (const [k, x] of f) { const g = err * x + L2 * w[k]; g2[k] += g * g; w[k] -= LR * g / Math.sqrt(g2[k] + 1e-8); }
    gb += err * err; bias -= LR * err / Math.sqrt(gb + 1e-8);
  }
}
let weights = new Map(); w.forEach((v, k) => { if (Math.abs(v) > 1e-4) weights.set(k, v); });
if (args.prune) weights = new Map([...weights.entries()].sort((a, b) => Math.abs(b[1]) - Math.abs(a[1])).slice(0, +args.prune));
const enc = C.encodeModel({ version: 'mund-injection-1', bias, threshold: 0.5, weights });
const model = C.decodeModel(enc);
// Threshold: lowest that keeps benign false positives on VALIDATION at or below MAXFP
const vs = val.map((r) => [C.scoreInjection(r.text, model).score, r.label]);
const benS = vs.filter(([, y]) => !y).map(([s]) => s).sort((a, b) => b - a);
const allowed = Math.floor(benS.length * MAXFP);
const threshold = Math.max(0.5, (benS[allowed] ?? 0) + 1e-6);
const atFp = (fp) => { const t = Math.max(0.5, (benS[Math.floor(benS.length * fp)] ?? 0) + 1e-6); return (100 * vs.filter(([s, y]) => y && s >= t).length / vs.filter(([, y]) => y).length).toFixed(1) + '%'; };
console.log('val detection at FP<=0.1%', atFp(0.001), '0.25%', atFp(0.0025), '0.5%', atFp(0.005), '1%', atFp(0.01));
const valDet = vs.filter(([s, y]) => y && s >= threshold).length / vs.filter(([, y]) => y).length;
console.log('weights', weights.size, 'encoded KB', (enc.data.length / 1024).toFixed(0), '| threshold', threshold.toFixed(4), '| val detection', (100 * valDet).toFixed(1) + '%', 'val benign FP', benS.filter((s) => s >= threshold).length + '/' + benS.length);
writeFileSync(args.out ?? '' + DATA + '/model.json', JSON.stringify({ ...enc, threshold }));
