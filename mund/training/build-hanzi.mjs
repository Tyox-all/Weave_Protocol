// Regenerate the tables in src/analyzers/hanzi.ts from their upstream sources:
//   OpenCC TSCharacters.txt (Apache-2.0) -> PAIRS (Traditional -> Simplified)
//   pinyin-data pinyin.txt (MIT)        -> PINYIN (syllable -> characters)
//
//   node training/build-hanzi.mjs [--from=dir-with-both-files]
import { readFileSync, writeFileSync } from 'node:fs';
const flags = Object.fromEntries(process.argv.slice(2).map((a) => a.replace(/^--/, '').split('=')));
const src = new URL('../src/analyzers/hanzi.ts', import.meta.url);
const read = async (name, url) => (flags.from ? readFileSync(`${flags.from}/${name}`, 'utf8') : (await fetch(url)).text());

const ts = await read('TSCharacters.txt', 'https://raw.githubusercontent.com/BYVoid/OpenCC/master/data/dictionary/TSCharacters.txt');
const pairs = [];
for (const line of ts.split('\n')) {
  if (!line || line.startsWith('#')) continue;
  const [k, v] = line.split('\t');
  if (!v) continue;
  const s = v.split(' ')[0];
  if ([...k].length === 1 && [...s].length === 1 && k !== s) pairs.push(k + s);
}

const py = await read('pinyin.txt', 'https://raw.githubusercontent.com/mozillazg/pinyin-data/master/pinyin.txt');
const bySyl = new Map();
for (const line of py.split('\n')) {
  const m = /^U\+([0-9A-F]+):\s*([^#\s,]+)/.exec(line);
  if (!m) continue;
  const cp = parseInt(m[1], 16);
  if (!((cp >= 0x4e00 && cp <= 0x9fff) || (cp >= 0x3400 && cp <= 0x4dbf))) continue;
  const syl = m[2].normalize('NFD').replace(/\p{M}/gu, '').replace(/ü/g, 'u').toLowerCase();
  if (!/^[a-z]+$/.test(syl)) continue;
  bySyl.set(syl, (bySyl.get(syl) ?? '') + String.fromCodePoint(cp));
}
const pinyin = [...bySyl.entries()].map(([s, c]) => `${s}:${c}`).join('|');

let code = readFileSync(src, 'utf8');
code = code.replace(/const PAIRS = ".*";/, () => `const PAIRS = ${JSON.stringify(pairs.join(''))};`);
code = code.replace(/const PINYIN = ".*";/, () => `const PINYIN = ${JSON.stringify(pinyin)};`);
writeFileSync(src, code);
console.log(`hanzi.ts: ${pairs.length} Traditional->Simplified pairs, ${bySyl.size} syllables`);
