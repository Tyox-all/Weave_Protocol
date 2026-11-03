// reportEvent (Ward 0.3.0): sends a minimal summary to a local dashboard
// when one is configured, and never throws or blocks for long.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { reportEvent, dashboardUrl } from '../dist/index.js';

let server, url;
const received = [];
let delayMs = 0;
before(async () => {
  server = createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      received.push({ path: req.url, key: req.headers['x-api-key'], body: JSON.parse(raw) });
      setTimeout(() => { res.writeHead(201); res.end('{}'); }, delayMs);
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  url = `http://127.0.0.1:${server.address().port}/`;
});
after(() => server.close());

test('off unless a dashboard URL is configured', async () => {
  const prev = process.env.WEAVE_DASHBOARD_URL;
  delete process.env.WEAVE_DASHBOARD_URL;
  received.length = 0;
  await reportEvent({ surface: 'mcp', decision: 'allow', subject: 'read_file' });
  assert.equal(received.length, 0);
  assert.equal(dashboardUrl(), undefined);
  if (prev !== undefined) process.env.WEAVE_DASHBOARD_URL = prev;
});

test('sends a summary with the key, and strips argument contents', async () => {
  received.length = 0;
  await reportEvent({
    surface: 'claude-code', decision: 'deny', subject: 'Bash',
    reason: 'Denied by filesystem rule: read /workspace/secrets/** (read /workspace/secrets/key)',
  }, { url, apiKey: 'k' });
  await reportEvent({ surface: 'browser', decision: 'allow', subject: 'https://docs.example.com/a?token=SECRET#frag' }, { url });
  assert.equal(received[0].path, '/api/v1/events');
  assert.equal(received[0].key, 'k');
  assert.deepEqual({ ...received[0].body, timestamp: 0 }, {
    surface: 'claude-code', decision: 'deny', subject: 'Bash',
    reason: 'Denied by filesystem rule: read /workspace/secrets/**', timestamp: 0,
  });
  assert.equal(received[1].body.subject, 'https://docs.example.com/a', 'query string and fragment dropped');
});

test('a slow or missing dashboard costs at most the timeout and never throws', async () => {
  delayMs = 2000;
  const t0 = Date.now();
  await reportEvent({ surface: 'mcp', decision: 'allow', subject: 'x' }, { url, timeoutMs: 100 });
  assert.ok(Date.now() - t0 < 1000, `took ${Date.now() - t0}ms`);
  delayMs = 0;
  await reportEvent({ surface: 'mcp', decision: 'allow', subject: 'x' }, { url: 'http://127.0.0.1:1', timeoutMs: 100 });
});
