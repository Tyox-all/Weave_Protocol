// Dōmere storage: MemoryStorage and SqliteStorage behave the same, and a
// SQLite-backed thread (with hops) survives a restart and still verifies.
import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { MemoryStorage, SqliteStorage, DomereToolHandler, createStorage } from '../dist/index.js';

const thread = (id, created, extra = {}) => ({
  id, status: 'active', origin: { type: 'human', identity: 'alice' }, intent: { raw: 'x' },
  hops: [], created_at: new Date(created), updated_at: new Date(created), ...extra,
});
const hop = (id, n) => ({ hop_id: id, hop_number: n, agent_id: `a${n}` });

for (const [name, make] of [['memory', () => new MemoryStorage()], ['sqlite', () => new SqliteStorage(':memory:')]]) {
  describe(`${name} storage contract`, () => {
    test('threads keep their hops, in order, once each', async () => {
      const s = make();
      await s.saveThread(thread('t1', '2026-01-01T00:00:00.000Z', { hops: [hop('h1', 1)] }));
      await s.addHop('t1', hop('h2', 2));
      await s.addHop('t1', hop('h2', 2));
      const t = await s.getThread('t1');
      assert.deepEqual(t.hops.map((h) => h.hop_id), ['h1', 'h2']);
      assert.ok(t.created_at instanceof Date);
      await s.updateThread({ ...t, status: 'closed' });
      assert.equal((await s.getThread('t1')).status, 'closed');
      assert.equal(await s.getThread('nope'), null);
    });

    test('listThreads filters, sorts newest first and paginates', async () => {
      const s = make();
      await s.saveThread(thread('a', '2026-01-01T00:00:00.000Z'));
      await s.saveThread(thread('b', '2026-01-03T00:00:00.000Z', { status: 'closed' }));
      await s.saveThread(thread('c', '2026-01-02T00:00:00.000Z'));
      assert.deepEqual((await s.listThreads()).map((t) => t.id), ['b', 'c', 'a']);
      assert.deepEqual((await s.listThreads({ status: 'active' })).map((t) => t.id), ['c', 'a']);
      assert.deepEqual((await s.listThreads({ offset: 1, limit: 1 })).map((t) => t.id), ['c']);
    });

    test('cases come back with their evidence; anchors and results per thread', async () => {
      const s = make();
      await s.saveCase({ id: 'k1', thread_id: 't1', status: 'open', dispute: { type: 'drift' }, created_at: new Date() });
      await s.saveEvidence({ case_id: 'k1', note: 'e1' });
      await s.saveEvidence({ case_id: 'k1', note: 'e2' });
      assert.deepEqual((await s.getCase('k1')).evidence.map((e) => e.note), ['e1', 'e2']);
      await s.saveAnchor('t1', { tx: '0x1' });
      assert.equal((await s.getAnchors('t1')).length, 1);
      await s.saveComplianceResult({ thread_id: 't1', passed: true });
      assert.equal((await s.getComplianceResults('t1')).length, 1);
    });
  });
}

describe('sqlite persistence', () => {
  const dir = mkdtempSync(join(tmpdir(), 'domere-sqlite-'));
  const db = join(dir, 'domere.sqlite');
  after(() => rmSync(dir, { recursive: true, force: true }));
  const run = (code) => execFileSync(process.execPath, ['--no-warnings', '--input-type=module', '-e', `
    const d = await import(${JSON.stringify(resolve('dist/index.js'))});
    const t = new d.DomereToolHandler(d.createStorage('sqlite', { path: ${JSON.stringify(db)} }));
    ${code}`], { encoding: 'utf8' }).trim();

  test('a thread with hops survives a restart and still verifies', () => {
    const id = run(`
      const { thread_id } = await t.handleTool('domere_create_thread', { origin_type: 'human', origin_identity: 'alice', intent: 'Summarize the report' });
      await t.handleTool('domere_add_hop', { thread_id, agent_id: 'a1', agent_type: 'llm', received_intent: 'Summarize the report', actions: [] });
      console.log(thread_id);`);
    const v = JSON.parse(run(`console.log(JSON.stringify(await t.handleTool('domere_verify_thread', { thread_id: '${id}' })))`));
    assert.equal(v.valid, true, JSON.stringify(v));
    assert.equal(v.total_hops, 1);
    assert.equal(statSync(db).mode & 0o777, 0o600);
  });

  test('unknown storage types fail loudly', () => {
    assert.throws(() => createStorage('postgres'), /Unknown storage type/);
  });
});
