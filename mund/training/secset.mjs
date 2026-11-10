import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
const dir = process.argv[2];
const b = JSON.parse(readFileSync(`${dir}/attack.json`, 'utf8'));
const out = [];
for (const o of b.objects) {
  if (!['attack-pattern', 'malware', 'tool'].includes(o.type) || o.revoked || o.x_mitre_deprecated || !o.description) continue;
  const text = o.description.replace(/\(Citation:[^)]*\)/g, '').replace(/\s+\n/g, '\n').trim();
  if (text.length > 120) out.push({ text, label: 0, src: `attack:${o.type}`, name: o.name });
}
for (const f of readdirSync(`${dir}/owasp`)) {
  for (const chunk of readFileSync(`${dir}/owasp/${f}`, 'utf8').split(/\n{2,}/)) if (chunk.length > 200 && chunk.length < 4000) out.push({ text: chunk, label: 0, src: 'owasp', name: f });
}
writeFileSync(`${dir}/security.json`, JSON.stringify(out));
const by = {}; for (const r of out) by[r.src] = (by[r.src] ?? 0) + 1;
console.log(out.length, by);
