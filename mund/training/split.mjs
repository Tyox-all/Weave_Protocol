// Fixed, deterministic splits. Nothing in TEST is used for training or for choosing the threshold.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
const h = (s) => parseInt(createHash('sha256').update(s).digest('hex').slice(0, 8), 16) / 0xffffffff;
const norm = (t) => t.normalize('NFKC').toLowerCase().replace(/\s+/g, ' ').trim();
export function loadSplits(dataDir) {
  const sets = JSON.parse(readFileSync(`${dataDir}/sets.json`, 'utf8'));
  const oasst = JSON.parse(readFileSync(`${dataDir}/oasst1.json`, 'utf8')).map((r) => ({ text: r.text, label: 0, tree: r.tree, split: r.split }));
  let assistant = [];
  try { assistant = JSON.parse(readFileSync(`${dataDir}/oasst1_assistant.json`, 'utf8')).map((r) => ({ text: r.text, label: 0, tree: r.tree })); } catch {}
  const pkgOf = (f) => f.split('/').slice(0, f.startsWith('@') ? 2 : 1).join('/');
  const readmesA = sets.readmes.filter((r) => h('pkg:' + pkgOf(r.file)) < 0.6);
  const readmesB = sets.readmes.filter((r) => h('pkg:' + pkgOf(r.file)) >= 0.6);
  const tagged = (rows, src) => rows.map((r) => ({ ...r, src }));
  const inVal = (r) => h('val:' + norm(r.text)) < 0.15;
  const trainPool = [
    ...tagged(sets.deepset_train, 'deepset'), ...tagged(sets.gandalf_train, 'gandalf'), ...tagged(sets.jackhhao_train, 'jackhhao'),
    ...tagged(oasst.filter((r) => r.split === 'train' && h('tree:' + r.tree) >= 0.15), 'oasst'),
    ...tagged(readmesA.filter((r) => h('pkgv:' + pkgOf(r.file)) >= 0.25), 'readmes'),
    ...tagged(JSON.parse(readFileSync(`${dataDir}/hardneg.json`, 'utf8')), 'hardneg'),
    ...tagged(assistant.filter((r) => h('tree:' + r.tree) >= 0.15), 'oasst'),
  ];
  const keep = (r) => r.src === 'oasst' || r.src === 'readmes' || r.src === 'hardneg';
  const train = trainPool.filter((r) => !inVal(r) || keep(r));
  const val = [
    ...trainPool.filter((r) => inVal(r) && !keep(r)),
    ...tagged(sets.gandalf_validation, 'gandalf'),
    ...tagged(oasst.filter((r) => r.split === 'train' && h('tree:' + r.tree) < 0.15), 'oasst'),
    ...tagged(assistant.filter((r) => h('tree:' + r.tree) < 0.15), 'oasst'),
    ...tagged(readmesA.filter((r) => h('pkgv:' + pkgOf(r.file)) < 0.25), 'readmes'),
  ];
  const ia = (kind) => ['dh', 'ds'].flatMap((t) => JSON.parse(readFileSync(`${dataDir}/injecagent/test_cases_${t}_${kind}.json`, 'utf8')));
  const uniq = (rows) => [...new Map(rows.map((r) => [r.text, r])).values()];
  const iaAttack = (kind) => uniq(ia(kind).map((c) => ({ text: String(c['Tool Response']).replace(/^"|"$/g, ''), label: 1 })));
  const FILLERS = ['Works as described, would buy again.', 'Thanks for the update, see you at the meeting on Thursday.', 'The package arrived on time and in good condition.', 'Please review the attached quarterly report before Friday.', 'Remember to water the plants while I am away.'];
  const iaBenign = uniq(ia('base').map((c, i) => ({ text: String(c['Tool Response Template']).replace('<Attacker Instruction>', FILLERS[i % FILLERS.length]), label: 0 })));
  const iaUser = uniq(ia('base').map((c) => ({ text: c['User Instruction'], label: 0 })));
  const seen = new Set(train.map((r) => norm(r.text)));
  const dedupe = (rows) => { const out = rows.filter((r) => !seen.has(norm(r.text))); return { rows: out, dropped: rows.length - out.length }; };
  const test = {
    'deepset test': dedupe(sets.deepset_test), 'gandalf test': dedupe(sets.gandalf_test), 'jackhhao test': dedupe(sets.jackhhao_test),
    'SPML (unseen source)': dedupe(sets.spml), 'Mosscap (unseen source)': dedupe(sets.mosscap),
    'InjecAgent base (indirect)': dedupe(iaAttack('base')), 'InjecAgent enhanced (indirect)': dedupe(iaAttack('enhanced')),
    'InjecAgent tool outputs (benign)': dedupe(iaBenign), 'InjecAgent user requests (benign)': dedupe(iaUser),
    'oasst validation (benign)': dedupe(oasst.filter((r) => r.split === 'validation')),
    'READMEs, unseen packages (benign)': dedupe(readmesB), 'Mund benign corpus': dedupe(sets.mund_benign),
  };
  return { train, val, test };
}
