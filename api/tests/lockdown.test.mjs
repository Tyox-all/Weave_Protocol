// API lockdown: starts the real server (dist/index.js) with different env and
// checks auth, bind address, CORS and demo-endpoint gating over HTTP.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';

const KEY = 'test-key-not-a-secret';

function start(env) {
  const port = 40000 + Math.floor(Math.random() * 20000);
  const child = spawn(process.execPath, ['dist/index.js'], {
    env: { PATH: process.env.PATH, WEAVE_PORT: String(port), ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  const ready = new Promise((resolve, reject) => {
    const onData = (d) => { out += d; if (out.includes('Weave Protocol API')) resolve(); };
    child.stdout.on('data', onData);
    child.stderr.on('data', (d) => { out += d; });
    child.on('exit', (code) => reject(Object.assign(new Error(`exited ${code}: ${out}`), { code, out })));
    setTimeout(() => reject(new Error(`timeout: ${out}`)), 10000);
  });
  const url = (path) => `http://127.0.0.1:${port}${path}`;
  return { child, ready, url, stop: () => child.kill() };
}

async function withServer(env, fn) {
  const s = start(env);
  try { await s.ready; await fn(s.url); } finally { s.stop(); }
}

describe('fail closed', () => {
  test('refuses a non-loopback bind without an API key', async () => {
    const s = start({ WEAVE_HOST: '0.0.0.0' });
    const err = await s.ready.then(() => null, (e) => e);
    s.stop();
    assert.equal(err?.code, 1);
    assert.match(err.out, /Refusing to listen on 0\.0\.0\.0 without WEAVE_API_KEY/);
  });

  test('defaults: local only, no CORS, no demo endpoints', async () => {
    await withServer({}, async (url) => {
      assert.equal((await fetch(url('/health'))).status, 200);
      assert.equal((await fetch(url('/test/threat'), { method: 'POST' })).status, 404);
      assert.equal((await fetch(url('/reset'), { method: 'POST' })).status, 404);
      const r = await fetch(url('/api/dashboard/snapshot'), { headers: { Origin: 'https://evil.example' } });
      assert.equal(r.status, 200);
      assert.equal(r.headers.get('access-control-allow-origin'), null);
      const index = await (await fetch(url('/api'))).json();
      assert.equal(index.test, undefined);
    });
  });
});

describe('with WEAVE_API_KEY', () => {
  test('every route needs the key except /health and the dashboard page', async () => {
    await withServer({ WEAVE_API_KEY: KEY, WEAVE_DEMO: '1' }, async (url) => {
      assert.equal((await fetch(url('/health'))).status, 200);
      assert.equal((await fetch(url('/dashboard'))).status, 200);
      for (const [path, method] of [['/api/dashboard/snapshot', 'GET'], ['/stats', 'GET'], ['/feed', 'GET'], ['/reset', 'POST'], ['/test/threat', 'POST'], ['/api/v1/functions', 'GET']]) {
        assert.equal((await fetch(url(path), { method })).status, 401, `${method} ${path} without key`);
        assert.equal((await fetch(url(path), { method, headers: { 'X-API-Key': 'wrong' } })).status, 403, `${method} ${path} wrong key`);
        assert.equal((await fetch(url(path), { method, headers: { 'X-API-Key': KEY } })).status, 200, `${method} ${path} with key`);
      }
      assert.equal((await fetch(url('/stats'), { headers: { Authorization: `Bearer ${KEY}` } })).status, 200, 'Bearer works too');
    });
  });

  test('a keyed server may bind publicly', async () => {
    await withServer({ WEAVE_API_KEY: KEY, WEAVE_HOST: '0.0.0.0' }, async (url) => {
      assert.equal((await fetch(url('/health'))).status, 200);
    });
  });
});

test('CORS allows only listed origins', async () => {
  await withServer({ WEAVE_CORS_ORIGINS: 'https://app.example' }, async (url) => {
    const ok = await fetch(url('/health'), { headers: { Origin: 'https://app.example' } });
    assert.equal(ok.headers.get('access-control-allow-origin'), 'https://app.example');
    const no = await fetch(url('/health'), { headers: { Origin: 'https://evil.example' } });
    assert.equal(no.headers.get('access-control-allow-origin'), null);
  });
});
