// Dashboard data is real (API 1.4.0): the snapshot is built from events
// surfaces report to POST /api/v1/events, and the legacy status endpoints
// return live data instead of invented numbers.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';

const KEY = 'test-key-not-a-secret';

async function withServer(fn) {
  const port = 40000 + Math.floor(Math.random() * 20000);
  const child = spawn(process.execPath, ['dist/index.js'], {
    env: { PATH: process.env.PATH, WEAVE_PORT: String(port), WEAVE_API_KEY: KEY },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  await new Promise((resolve, reject) => {
    child.stdout.on('data', (d) => { out += d; if (out.includes('Weave Protocol API')) resolve(); });
    child.stderr.on('data', (d) => { out += d; });
    child.on('exit', (code) => reject(new Error(`exited ${code}: ${out}`)));
    setTimeout(() => reject(new Error(`timeout: ${out}`)), 10000);
  });
  const call = (path, init = {}) => fetch(`http://127.0.0.1:${port}${path}`, {
    ...init, headers: { 'X-API-Key': KEY, 'Content-Type': 'application/json', ...(init.headers || {}) },
  });
  try { await fn(call); } finally { child.kill(); }
}

const post = (call, body) => call('/api/v1/events', { method: 'POST', body: JSON.stringify(body) });

test('with nothing reported, every surface is off and nothing is invented', async () => {
  await withServer(async (call) => {
    const snap = await (await call('/api/dashboard/snapshot')).json();
    assert.equal(snap.surfaces.length, 10);
    assert.deepEqual(snap.surfaces.slice(5).map((s) => s.id), ['gemini-cli', 'codex', 'opencode', 'cursor', 'qwen-code']);
    for (const s of snap.surfaces) {
      assert.equal(s.status, 'off', s.id);
      assert.equal(s.eventsToday, 0, s.id);
    }
    assert.deepEqual(snap.events, []);
    assert.equal(snap.stats.decisions, 0);
    assert.match(snap.notes.dataSource, /WEAVE_DASHBOARD_URL/);
  });
});

test('reported events drive the snapshot', async () => {
  await withServer(async (call) => {
    assert.equal((await post(call, { surface: 'claude-code', decision: 'deny', subject: 'Bash', reason: 'Denied by network rule' })).status, 201);
    await post(call, { surface: 'claude-code', decision: 'allow', subject: 'Read' });
    await post(call, { surface: 'browser', decision: 'ipi_detected', subject: 'https://blog.example/p', reason: 'high risk: trigger_phrase' });
    await post(call, { surface: 'msaf', decision: 'require_approval', subject: 'SendEmail', timestamp: Date.now() - 2 * 60 * 60 * 1000 });
    await post(call, { surface: 'codex', decision: 'deny', subject: 'Bash', reason: 'Denied by filesystem rule' });

    const snap = await (await call('/api/dashboard/snapshot')).json();
    const byId = Object.fromEntries(snap.surfaces.map((s) => [s.id, s]));
    assert.equal(byId['claude-code'].status, 'live');
    assert.equal(byId['claude-code'].eventsToday, 2);
    assert.equal(byId.msaf.status, 'idle', 'reported earlier today, not in the last 5 minutes');
    assert.equal(byId.msaf.lastHour, 0);
    assert.equal(byId.antigravity.status, 'off');
    assert.equal(byId.codex.status, 'live', 'new adapters report too');
    assert.equal(byId.cursor.status, 'off');
    assert.deepEqual(snap.stats, { decisions: 5, allows: 1, denies: 2, approvalsRequested: 1, ipiDetected: 1, urlsScanned: 1 });
    assert.equal(snap.events[1].kind, 'ipi_detected', 'newest first');
    assert.match(snap.notes.dataSource, /^Live/);
  });
});

test('bad events are rejected; the endpoint needs the key', async () => {
  await withServer(async (call) => {
    assert.equal((await post(call, { surface: 'nope', decision: 'allow', subject: 'x' })).status, 400);
    assert.equal((await post(call, { surface: 'mcp', decision: 'maybe', subject: 'x' })).status, 400);
    assert.equal((await post(call, { surface: 'mcp', decision: 'allow' })).status, 400);
    const anon = await call('/api/v1/events', { method: 'POST', body: '{}', headers: { 'X-API-Key': '' } });
    assert.equal(anon.status, 401);
    const long = await post(call, { surface: 'mcp', decision: 'allow', subject: 'x'.repeat(5000) });
    assert.equal(long.status, 201);
    const { events } = await (await call('/api/v1/events?limit=1')).json();
    assert.equal(events[0].subject.length, 200, 'subject capped');
  });
});

test('legacy status endpoints return real data', async () => {
  await withServer(async (call) => {
    const intel = await (await call('/mund/intel-status')).json();
    assert.equal(intel.initialized, true);
    assert.ok(intel.patterns.total > 0);
    const compliance = await (await call('/domere/compliance/status')).json();
    assert.deepEqual(compliance.checkpoints, {}, 'no checkpoints recorded yet');
    assert.ok(Array.isArray(await (await call('/hundredmen/servers')).json()));
  });
});
