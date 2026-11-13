// reportEvent (Ward 0.3.0): sends a minimal summary to a local dashboard
// when one is configured, and never throws or blocks for long.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { reportEvent, dashboardUrl, reportTimeoutMs } from '../dist/index.js';

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

/** Resolve once `check()` is true; fail the test if it isn't within `ms`. */
async function waitFor(check, ms = 5000) {
  const deadline = Date.now() + ms;
  while (!check()) {
    if (Date.now() > deadline) throw new Error(`condition not met within ${ms}ms`);
    await new Promise((r) => setTimeout(r, 10));
  }
}

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
  }, { url, apiKey: 'k', timeoutMs: 5000 });
  // A generous timeout: a cold first request on a slow CI runner can exceed the
  // 250ms default, and a dropped report would make this test flaky
  await reportEvent({ surface: 'browser', decision: 'allow', subject: 'https://docs.example.com/a?token=SECRET#frag' }, { url, timeoutMs: 5000 });
  // Wait explicitly until the server has both reports, then find each by surface:
  // the test doesn't depend on timing or arrival order
  await waitFor(() => received.length >= 2);
  const deny = received.find((r) => r.body.surface === 'claude-code');
  const allow = received.find((r) => r.body.surface === 'browser');
  assert.equal(deny.path, '/api/v1/events');
  assert.equal(deny.key, 'k');
  assert.deepEqual({ ...deny.body, timestamp: 0 }, {
    surface: 'claude-code', decision: 'deny', subject: 'Bash',
    reason: 'Denied by filesystem rule: read /workspace/secrets/**', timestamp: 0,
  });
  assert.equal(allow.body.subject, 'https://docs.example.com/a', 'query string and fragment dropped');
});

test('a slow or missing dashboard costs at most the timeout and never throws', async () => {
  delayMs = 2000;
  const t0 = Date.now();
  await reportEvent({ surface: 'mcp', decision: 'allow', subject: 'x' }, { url, timeoutMs: 100 });
  assert.ok(Date.now() - t0 < 1000, `took ${Date.now() - t0}ms`);
  delayMs = 0;
  await reportEvent({ surface: 'mcp', decision: 'allow', subject: 'x' }, { url: 'http://127.0.0.1:1', timeoutMs: 100 });
});

test('the timeout comes from the option, then WEAVE_DASHBOARD_TIMEOUT_MS, capped at 5s', () => {
  const prev = process.env.WEAVE_DASHBOARD_TIMEOUT_MS;
  try {
    delete process.env.WEAVE_DASHBOARD_TIMEOUT_MS;
    assert.equal(reportTimeoutMs(), 250);
    process.env.WEAVE_DASHBOARD_TIMEOUT_MS = '1500';
    assert.equal(reportTimeoutMs(), 1500);
    assert.equal(reportTimeoutMs({ timeoutMs: 100 }), 100, 'the option wins');
    process.env.WEAVE_DASHBOARD_TIMEOUT_MS = '60000';
    assert.equal(reportTimeoutMs(), 5000, 'capped');
    process.env.WEAVE_DASHBOARD_TIMEOUT_MS = 'nope';
    assert.equal(reportTimeoutMs(), 250, 'garbage falls back');
  } finally {
    if (prev === undefined) delete process.env.WEAVE_DASHBOARD_TIMEOUT_MS; else process.env.WEAVE_DASHBOARD_TIMEOUT_MS = prev;
  }
});
