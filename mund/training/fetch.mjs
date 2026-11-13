import { writeFileSync } from 'node:fs';
const out = process.argv[2] ?? new URL('./data', import.meta.url).pathname;
import { mkdirSync } from 'node:fs';
mkdirSync(`${out}/injecagent`, { recursive: true });
const enc = encodeURIComponent;
const get = async (url) => { for (let a = 0; a < 5; a++) { try { const r = await fetch(url); if (r.ok) return r.json(); } catch {} await new Promise((s) => setTimeout(s, 2000 + a * 3000)); } return null; };
const plan = [
  ['deepset/prompt-injections', 'train'], ['deepset/prompt-injections', 'test'],
  ['Lakera/gandalf_ignore_instructions', 'train'], ['Lakera/gandalf_ignore_instructions', 'validation'], ['Lakera/gandalf_ignore_instructions', 'test'],
  ['jackhhao/jailbreak-classification', 'train'], ['jackhhao/jailbreak-classification', 'test'],
  ['reshabhs/SPML_Chatbot_Prompt_Injection', 'train', 30], ['Lakera/mosscap_prompt_injection', 'test', 10],
];
for (const [ds, split, pages] of plan) {
  const sz = await get(`https://datasets-server.huggingface.co/size?dataset=${enc(ds)}`);
  const n = sz.size.splits.find((s) => s.split === split).num_rows;
  let offs = [];
  if (!pages) for (let o = 0; o < n; o += 100) offs.push(o);
  else { const step = Math.max(100, Math.floor(n / pages / 100) * 100); for (let o = 0; o < n && offs.length < pages; o += step) offs.push(o); }
  const rows = [];
  for (const off of offs) {
    const o = await get(`https://datasets-server.huggingface.co/rows?dataset=${enc(ds)}&config=default&split=${split}&offset=${off}&length=100`);
    if (!o?.rows?.length) break;
    rows.push(...o.rows.map((x) => x.row));
  }
  const name = `${ds.split('/')[1]}_${split}`;
  writeFileSync(`${out}/${name}.json`, JSON.stringify(rows));
  console.log(name, n, 'fetched', rows.length, Object.keys(rows[0] ?? {}));
}

// Benign user prompts: OpenAssistant oasst1 (Apache-2.0), prompter messages only
{
  const rows = [];
  for (const [split, n] of [['train', 84437], ['validation', 4401]]) {
    const pages = split === 'train' ? 60 : 10; const step = Math.floor(n / pages / 100) * 100;
    for (let i = 0; i < pages; i++) {
      const o = await get(`https://datasets-server.huggingface.co/rows?dataset=OpenAssistant%2Foasst1&config=default&split=${split}&offset=${i * step}&length=100`);
      for (const x of o?.rows ?? []) if (x.row.role === 'prompter') rows.push({ text: x.row.text, lang: x.row.lang, split, tree: x.row.message_tree_id });
    }
  }
  writeFileSync(`${out}/oasst1.json`, JSON.stringify(rows));
  // Assistant replies (benign prose full of advice and imperatives), train split, offsets shifted by 50
  const replies = [];
  const step2 = Math.floor(84437 / 60 / 100) * 100;
  for (let i = 0; i < 60; i++) {
    const o = await get(`https://datasets-server.huggingface.co/rows?dataset=OpenAssistant%2Foasst1&config=default&split=train&offset=${i * step2 + 50}&length=100`);
    for (const x of o?.rows ?? []) if (x.row.role === 'assistant') replies.push({ text: x.row.text, lang: x.row.lang, tree: x.row.message_tree_id });
  }
  writeFileSync(`${out}/oasst1_assistant.json`, JSON.stringify(replies));
  console.log('oasst1 prompter messages', rows.length);
}
// Indirect injection in tool outputs: InjecAgent (MIT), evaluation only
for (const f of ['test_cases_dh_base', 'test_cases_ds_base', 'test_cases_dh_enhanced', 'test_cases_ds_enhanced']) {
  const r = await fetch(`https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data/${f}.json`);
  writeFileSync(`${out}/injecagent/${f}.json`, await r.text());
  console.log('InjecAgent', f);
}
// Benign security writing (evaluation only): MITRE ATT&CK descriptions and OWASP Cheat Sheet Series (CC BY-SA 4.0)
{
  mkdirSync(`${out}/sec/owasp`, { recursive: true });
  writeFileSync(`${out}/sec/attack.json`, await (await fetch('https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json')).text());
  const list = await (await fetch('https://api.github.com/repos/OWASP/CheatSheetSeries/contents/cheatsheets')).json();
  for (const f of list.filter((f) => f.name.endsWith('.md'))) writeFileSync(`${out}/sec/owasp/${f.name}`, await (await fetch(f.download_url)).text());
  console.log('security writing: ATT&CK + OWASP cheat sheets');
}

// Chinese (Mund 0.7.0). Shuangsuo bilingual prompts (CC BY 4.0) for training and testing,
// Safety-Prompts instruction attacks (Apache-2.0, test only), OpenAssistant Chinese
// messages (Apache-2.0) and Chinese Wikipedia paragraphs (CC BY-SA, test only).
{
  mkdirSync(`${out}/zh`, { recursive: true });
  for (const f of ['train', 'validation', 'test']) writeFileSync(`${out}/zh/${f}.jsonl`, await (await fetch(`https://huggingface.co/datasets/Za1d3v/shuanguo-prompts/resolve/main/${f}.jsonl`)).text());
  writeFileSync(`${out}/zh/safety_instruction_attacks.json`, await (await fetch('https://huggingface.co/datasets/thu-coai/Safety-Prompts/resolve/main/instruction_attack_scenarios.json')).text());
  const where = encodeURIComponent(`"lang"='zh'`);
  const oz = [];
  for (const split of ['train', 'validation']) {
    for (let off = 0; ; off += 100) {
      const o = await get(`https://datasets-server.huggingface.co/filter?dataset=OpenAssistant%2Foasst1&config=default&split=${split}&where=${where}&offset=${off}&length=100`);
      if (!o?.rows?.length) break;
      for (const x of o.rows) oz.push({ text: x.row.text, role: x.row.role, tree: x.row.message_tree_id, split });
      if (o.rows.length < 100) break;
    }
  }
  writeFileSync(`${out}/zh/oasst_zh.json`, JSON.stringify(oz));
  const wiki = [];
  const n = 1380000;
  for (let i = 0; i < 12; i++) {
    const o = await get(`https://datasets-server.huggingface.co/rows?dataset=wikimedia%2Fwikipedia&config=20231101.zh&split=train&offset=${Math.floor((n / 12) * i)}&length=50`);
    for (const x of o?.rows ?? []) for (const p of x.row.text.split(/\n+/)) if (p.length > 80 && p.length < 2000) wiki.push({ text: p, title: x.row.title });
  }
  writeFileSync(`${out}/zh/wiki_zh.json`, JSON.stringify(wiki));
  console.log('Chinese: Shuangsuo, Safety-Prompts, OpenAssistant zh', oz.length, 'Wikipedia zh', wiki.length);
}
