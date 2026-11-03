// GDPR and CCPA records persist in SQLite (Dōmere 1.6.0): they survive a
// restart, in-place updates are saved, erasure removes the data from disk,
// and the checkpoint chains detect edited records. Before 1.6.0 these
// records lived in memory only, and chain checks never recomputed hashes.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { GDPRManager, CCPAManager, SqliteRecordStore, PersistentMap } from '../dist/index.js';

const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite');
const dbPath = () => join(mkdtempSync(join(tmpdir(), 'domere-records-')), 'domere.sqlite');
const CONTROLLER = { name: 'Test Co', email: 'privacy@test.example' };
const BUSINESS = {
  id: 'b', name: 'Test Co', address: 'x', privacyPolicyUrl: 'x', doNotSellUrl: 'x', contactEmail: 'x',
  meetsThreshold: true, createdAt: new Date(), updatedAt: new Date(),
};
const gdprAt = (path) => new GDPRManager(CONTROLLER, { store: new SqliteRecordStore(path) });
const ccpaAt = (path) => new CCPAManager(BUSINESS, { store: new SqliteRecordStore(path) });
const tick = () => new Promise((r) => setImmediate(r));

describe('PersistentMap', () => {
  test('writes through, saves in-place changes, keeps order and Dates', async () => {
    const path = dbPath();
    const m = new PersistentMap(new SqliteRecordStore(path), 'c');
    m.set('b', { n: 1, at: new Date('2026-01-02T03:04:05.000Z') });
    m.set('a', { n: 2 });
    m.get('b').n = 99; // in place
    await tick();
    m.delete('a');

    const again = new PersistentMap(new SqliteRecordStore(path), 'c');
    assert.deepEqual([...again.keys()], ['b']);
    assert.equal(again.get('b').n, 99);
    assert.ok(again.get('b').at instanceof Date);
  });

  test('collections are separate', () => {
    const store = new SqliteRecordStore(':memory:');
    new PersistentMap(store, 'x').set('1', { v: 'x' });
    assert.equal(new PersistentMap(store, 'y').size, 0);
  });
});

describe('GDPR records', () => {
  test('survive a restart, including in-place status changes', () => {
    const path = dbPath();
    const g = gdprAt(path);
    const subject = g.registerSubject({ email: 'ann@example.com' });
    g.recordConsent({ subjectId: subject.id, purpose: 'marketing', legalBasis: 'consent', granted: true, source: 'web_form', version: '1' });
    const dsar = g.createDSAR({ subjectId: subject.id, type: 'access' });
    g.verifyDSAR(dsar.id, 'dpo');
    g.flush();

    const after = gdprAt(path);
    assert.equal(after.getSubject(subject.id).email, 'ann@example.com');
    assert.equal(after.hasValidConsent(subject.id, 'marketing'), true);
    assert.equal(after.getDSAR(dsar.id).status, 'verified');
    assert.ok(after.getDSAR(dsar.id).requestedAt instanceof Date);
    assert.deepEqual(after.verifyCheckpointChain().valid, true);
  });

  test('the chain keeps growing correctly across restarts', () => {
    const path = dbPath();
    gdprAt(path).registerSubject({ email: 'a@example.com' });
    const g = gdprAt(path);
    const s = g.registerSubject({ email: 'b@example.com' });
    g.recordConsent({ subjectId: s.id, purpose: 'analytics', legalBasis: 'consent', granted: true, source: 'web_form', version: '1' });
    g.recordConsent({ subjectId: s.id, purpose: 'marketing', legalBasis: 'consent', granted: true, source: 'web_form', version: '1' });
    const v = gdprAt(path).verifyCheckpointChain();
    assert.equal(v.valid, true);
    assert.ok(v.checked >= 2);
  });

  test('an edited checkpoint in the database breaks the chain', () => {
    const path = dbPath();
    const g = gdprAt(path);
    const s = g.registerSubject({ email: 'c@example.com' });
    g.recordConsent({ subjectId: s.id, purpose: 'marketing', legalBasis: 'consent', granted: true, source: 'web_form', version: '1' });
    g.recordConsent({ subjectId: s.id, purpose: 'analytics', legalBasis: 'consent', granted: false, source: 'web_form', version: '1' });

    const db = new DatabaseSync(path);
    const row = db.prepare("SELECT id, json FROM compliance_records WHERE collection = 'gdpr.checkpoints' ORDER BY seq LIMIT 1").get();
    const cp = JSON.parse(row.json);
    cp.actor = 'someone-else';
    db.prepare("UPDATE compliance_records SET json = ? WHERE collection = 'gdpr.checkpoints' AND id = ?").run(JSON.stringify(cp), row.id);
    db.close();

    const v = gdprAt(path).verifyCheckpointChain();
    assert.equal(v.valid, false);
    assert.equal(v.reason, 'hash does not match contents');
  });

  test('erasure removes the subject\'s personal data from the database file', async () => {
    const path = dbPath();
    const g = gdprAt(path);
    const email = 'erase-me-7f3a@example.com';
    const s = g.registerSubject({ email });
    g.recordConsent({ subjectId: s.id, purpose: 'marketing', legalBasis: 'consent', granted: true, source: 'web_form', version: '1' });
    const result = await g.executeErasure(s.id, 'subject request');
    assert.equal(result.success, true);
    g.flush();

    assert.equal(gdprAt(path).getSubject(s.id), undefined);
    for (const file of [path, `${path}-wal`]) {
      if (existsSync(file)) assert.equal(readFileSync(file).includes(Buffer.from(email)), false, `${file} still contains the email`);
    }
    assert.equal(gdprAt(path).verifyCheckpointChain().valid, true, 'erasure keeps the chain intact');
  });
});

describe('CCPA records', () => {
  test('survive a restart and detect tampering', () => {
    const path = dbPath();
    const c = ccpaAt(path);
    const consumer = c.registerConsumer({ email: 'bob@example.com', californiaResident: true });
    c.recordOptOut({ consumerId: consumer.id, optOutType: 'sale', source: 'web_form' });
    c.recordOptOut({ consumerId: consumer.id, optOutType: 'sharing', source: 'web_form' });
    c.recordOptOut({ consumerId: consumer.id, optOutType: 'sensitive_use', source: 'web_form' });
    c.flush();

    const after = ccpaAt(path);
    assert.equal(after.hasActiveOptOut(consumer.id, 'sale'), true);
    assert.equal(after.verifyCheckpointChain().valid, true);

    const db = new DatabaseSync(path);
    const rows = db.prepare("SELECT seq FROM compliance_records WHERE collection = 'ccpa.checkpoints' ORDER BY seq").all();
    assert.ok(rows.length >= 3);
    db.prepare('DELETE FROM compliance_records WHERE seq = ?').run(rows[1].seq);
    db.close();
    const v = ccpaAt(path).verifyCheckpointChain();
    assert.equal(v.valid, false, 'a deleted checkpoint breaks the links');
    assert.equal(v.reason, 'does not link to the previous checkpoint');
  });
});

test('MCP server: records persist across restarts with DOMERE_STORAGE=sqlite', async () => {
  const path = dbPath();
  const start = async () => {
    const client = new Client({ name: 'test', version: '1' });
    await client.connect(new StdioClientTransport({
      command: process.execPath, args: ['dist/server.js'], stderr: 'ignore',
      env: { PATH: process.env.PATH, DOMERE_STORAGE: 'sqlite', DOMERE_DATABASE_URL: path },
    }));
    return client;
  };
  const call = async (client, name, args = {}) => JSON.parse((await client.callTool({ name, arguments: args })).content[0].text);

  const first = await start();
  const d = await call(first, 'domere_gdpr_handle_dsar', { action: 'create', subject_id: 's1', type: 'access' });
  await call(first, 'domere_gdpr_handle_dsar', { action: 'verify', dsar_id: d.dsar_id, verification_method: 'email', assigned_to: 'dpo' });
  await first.close();

  const second = await start();
  const processed = await call(second, 'domere_gdpr_handle_dsar', { action: 'process', dsar_id: d.dsar_id, assigned_to: 'dpo' });
  assert.notEqual(processed.success, false, 'the verified DSAR from the first run is still there');
  const chain = await call(second, 'domere_gdpr_verify_chain');
  assert.equal(chain.valid, true);
  await second.close();
});
