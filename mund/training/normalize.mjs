import { readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
const [data, root] = process.argv.slice(2);
const L = (f) => JSON.parse(readFileSync(join(data, f + '.json'), 'utf8'));
const sets = {};
const add = (name, rows) => { sets[name] = rows.filter((r) => r.text && r.text.trim()); };
for (const s of ['train', 'test']) add(`deepset_${s}`, L(`prompt-injections_${s}`).map((r) => ({ text: r.text, label: r.label })));
for (const s of ['train', 'validation', 'test']) add(`gandalf_${s}`, L(`gandalf_ignore_instructions_${s}`).map((r) => ({ text: r.text, label: 1 })));
for (const s of ['train', 'test']) add(`jackhhao_${s}`, L(`jailbreak-classification_${s}`).map((r) => ({ text: r.prompt, label: r.type === 'jailbreak' ? 1 : 0 })));
add('spml', L('SPML_Chatbot_Prompt_Injection_train').map((r) => ({ text: r['User Prompt'], label: r['Prompt injection'] ? 1 : 0 })));
add('mosscap', L('mosscap_prompt_injection_test').map((r) => ({ text: r.prompt, label: 1, level: r.level })));
// Realistic benign agent content: README paragraphs from installed packages (not ours)
const docs = [];
const nm = join(root, 'mund', 'node_modules');
const walk = (d, depth = 0) => {
  for (const e of readdirSync(d)) {
    if (e === '@weave_protocol' || e === '.bin') continue;
    const p = join(d, e);
    let st; try { st = statSync(p); } catch { continue; }
    if (st.isDirectory() && depth < 2) walk(p, depth + 1);
    else if (/^readme\.md$/i.test(e)) docs.push(p);
  }
};
walk(nm);
const paras = [];
for (const f of docs) {
  const t = readFileSync(f, 'utf8');
  for (const chunk of t.split(/\n{2,}/)) if (chunk.length > 200 && chunk.length < 4000) paras.push({ text: chunk, label: 0, file: f.slice(nm.length + 1) });
}
add('readmes', paras);
add('mund_benign', JSON.parse(readFileSync(join(root, 'mund/tests/fixtures/benign/corpus.json'), 'utf8')).map((b) => ({ text: b.text, label: 0, id: b.id })));
writeFileSync(join(data, 'sets.json'), JSON.stringify(sets));
for (const [k, v] of Object.entries(sets)) console.log(k.padEnd(16), 'n', String(v.length).padStart(5), 'attacks', v.filter((r) => r.label).length);
