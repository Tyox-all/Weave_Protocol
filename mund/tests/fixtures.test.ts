/**
 * Fixture library: one fixture per case, each with its expected verdict.
 * Add a file/folder under tests/fixtures/ and it is picked up here.
 */
import { readdirSync, readFileSync } from 'fs';
import { join } from 'path';
import { describe, expect, it } from 'vitest';
import { CanaryRegistry } from '../src/canary.js';
import { diffManifest, fingerprintManifest } from '../src/rugpull.js';

const dir = (p: string) => join(__dirname, 'fixtures', p);
const json = (p: string) => JSON.parse(readFileSync(p, 'utf8'));

describe('canary fixtures', () => {
  for (const file of readdirSync(dir('canary'))) {
    const fx = json(join(dir('canary'), file));
    it(`${file}: ${fx.description}`, () => {
      const registry = new CanaryRegistry();
      registry.register(fx.canary);
      const hits = registry.find(fx.content);
      expect(hits.length > 0).toBe(fx.expected.detected);
      if (fx.expected.kind) expect(hits[0].kind).toBe(fx.expected.kind);
    });
  }
});

describe('rug-pull fixtures', () => {
  for (const name of readdirSync(dir('rugpull'))) {
    const base = join(dir('rugpull'), name);
    const expected = json(join(base, 'expected.json'));
    it(`${name}: ${expected.description}`, async () => {
      const baseline = fingerprintManifest('fixture', json(join(base, 'baseline.json')));
      const changes = await diffManifest(baseline, json(join(base, 'current.json')));
      expect(changes.length > 0 ? 'changed' : 'unchanged').toBe(expected.status);
      expect(changes.map(c => ({ kind: c.kind, tool: c.tool, severity: c.severity, ...(c.escalated ? { escalated: true } : {}) })))
        .toEqual(expect.arrayContaining(expected.changes));
      expect(changes).toHaveLength(expected.changes.length);
    });
  }
});
