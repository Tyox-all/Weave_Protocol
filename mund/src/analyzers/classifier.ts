/**
 * Mund - local prompt-injection classifier (Mund 0.6.0)
 *
 * A small linear model over hashed word and character n-grams. It runs
 * offline in microseconds, needs no API key or download, and catches
 * paraphrased injections that no fixed pattern names. It backs up the
 * rules; it never replaces them.
 *
 * The same featurizer is used to train the shipped weights and to score at
 * runtime, so the two can't drift apart.
 */

export const FEATURE_BITS = 18;
const DIM = 1 << FEATURE_BITS;

export interface InjectionModel {
  version: string;
  bits: number;
  bias: number;
  /** Decision threshold on the probability, chosen on validation data */
  threshold: number;
  /** Sparse weights: feature index -> weight */
  weights: Map<number, number>;
}

/** FNV-1a 32-bit */
function hash(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

export function normalizeForModel(text: string): string {
  return text
    .normalize('NFKC')
    .replace(/[​-‍⁠﻿­]/g, '')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Features of a text: word unigrams and bigrams, and character 3-5-grams
 * within words. Binary, L2-normalized, hashed into 2^18 buckets.
 */
export function featurize(text: string): Map<number, number> {
  const t = normalizeForModel(text);
  const words = t.match(/[\p{L}\p{N}']+/gu) ?? [];
  const keys = new Set<number>();
  const add = (k: string) => keys.add(hash(k) & (DIM - 1));
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    add(`w:${w}`);
    if (i + 1 < words.length) add(`b:${w} ${words[i + 1]}`);
    const padded = ` ${w} `;
    if (padded.length <= 40) {
      for (let n = 3; n <= 5; n++) for (let j = 0; j + n <= padded.length; j++) add(`c:${padded.slice(j, j + n)}`);
    }
  }
  const v = new Map<number, number>();
  if (!keys.size) return v;
  const x = 1 / Math.sqrt(keys.size);
  for (const k of keys) v.set(k, x);
  return v;
}

const sigmoid = (z: number) => 1 / (1 + Math.exp(-z));

/** Probability that one window of text is a prompt injection. */
export function scoreWindow(text: string, model: InjectionModel): number {
  let z = model.bias;
  for (const [k, x] of featurize(text)) z += (model.weights.get(k) ?? 0) * x;
  return sigmoid(z);
}

/**
 * Long content (a web page, a tool result) is scored in windows of about
 * 800 characters, cut at paragraph or sentence breaks; the highest window
 * counts, so an injection buried in a long document isn't averaged away.
 */
export function windows(text: string, size = 800): string[] {
  if (text.length <= size * 1.5) return [text];
  const parts = text.split(/(?<=\n\s*\n)|(?<=[.!?])\s+/);
  const out: string[] = [];
  let cur = '';
  for (const p of parts) {
    if (cur && cur.length + p.length > size) { out.push(cur); cur = ''; }
    cur += (cur ? ' ' : '') + p;
    while (cur.length > size * 2) { out.push(cur.slice(0, size)); cur = cur.slice(size); }
  }
  if (cur.trim()) out.push(cur);
  return out;
}

/**
 * Sentences (and pairs of neighbours) inside a window, so an injection
 * appended to an innocent question isn't diluted by it.
 */
export function sentences(text: string): string[] {
  const parts = text.split(/(?<=[.!?])\s+|\n+|(?<=\?)(?=\S)/).map((s) => s.trim()).filter((s) => s.length >= 12);
  if (parts.length < 2) return [];
  const out = [...parts];
  for (let i = 0; i + 1 < parts.length; i++) out.push(`${parts[i]} ${parts[i + 1]}`);
  return out;
}

export function scoreInjection(text: string, model: InjectionModel, opts: { sentences?: boolean } = {}): { score: number; window: string } {
  let best = { score: 0, window: '' };
  for (const w of windows(text)) {
    for (const piece of [w, ...(opts.sentences === false ? [] : sentences(w))]) {
      const score = scoreWindow(piece, model);
      if (score > best.score) best = { score, window: piece };
    }
  }
  return best;
}

/**
 * Decode the shipped model: base64 of [u32 count][u32 index, i8 weight]...
 * with a float scale, kept compact so the package stays small.
 */
export function decodeModel(encoded: { version: string; bits: number; bias: number; threshold: number; scale: number; data: string }): InjectionModel {
  const buf = Buffer.from(encoded.data, 'base64');
  const weights = new Map<number, number>();
  let prev = 0;
  let i = 0;
  while (i < buf.length) {
    // delta-encoded index (varint), then an int8 weight
    let delta = 0, shift = 0, b: number;
    do { b = buf[i++]; delta |= (b & 0x7f) << shift; shift += 7; } while (b & 0x80);
    prev += delta;
    const q = buf.readInt8(i++);
    weights.set(prev, q * encoded.scale);
  }
  return { version: encoded.version, bits: encoded.bits, bias: encoded.bias, threshold: encoded.threshold, weights };
}

export function encodeModel(model: { version: string; bias: number; threshold: number; weights: Map<number, number> }): { version: string; bits: number; bias: number; threshold: number; scale: number; data: string } {
  const entries = [...model.weights.entries()].filter(([, w]) => w !== 0).sort((a, b) => a[0] - b[0]);
  const max = entries.reduce((m, [, w]) => Math.max(m, Math.abs(w)), 1e-9);
  const scale = max / 127;
  const bytes: number[] = [];
  let prev = 0;
  for (const [k, w] of entries) {
    const q = Math.round(w / scale);
    if (q === 0) continue;
    let delta = k - prev;
    prev = k;
    do { let b = delta & 0x7f; delta >>>= 7; if (delta) b |= 0x80; bytes.push(b); } while (delta);
    bytes.push(q & 0xff);
  }
  return { version: model.version, bits: FEATURE_BITS, bias: model.bias, threshold: model.threshold, scale, data: Buffer.from(bytes).toString('base64') };
}
