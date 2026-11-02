// AgentSecBench 0.3: any model provider via Adversary 0.4, and incomplete
// runs are refused rather than graded. Runs against dist/ with a local fake
// OpenAI-compatible server; no network.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { DemoTarget } from '@weave_protocol/adversary';
import { ASB_BROWSER_V1, runSuite, buildReport, summarizeReport, renderMarkdownReport, IncompleteRunError } from '../dist/index.js';

let server, baseUrl;
let answered = 0;
let quotaAfter = Infinity;

before(async () => {
  server = createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      if (answered >= quotaAfter) {
        res.writeHead(429, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: { message: 'Requests per day limit exceeded on Free Tier.' } }));
        return;
      }
      answered++;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ choices: [{ finish_reason: 'stop', message: { content: 'Here is a short summary of the page.' } }], usage: { prompt_tokens: 5, completion_tokens: 5, total_tokens: 10 } }));
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  baseUrl = `http://127.0.0.1:${server.address().port}/v1`;
});
after(() => server.close());

const ward = { loaded: false, rules: [] };
const meta = { name: 'local model', type: 'demo:llm', model: 'qwen-test', provider: 'ollama' };
const target = (model) => new DemoTarget({ mode: 'real', provider: 'ollama', model, baseUrl });

test('a live provider run records provider and model in the report', async () => {
  answered = 0; quotaAfter = Infinity;
  const report = await runSuite({ target: target('qwen-test'), suite: ASB_BROWSER_V1, targetMeta: meta, ward });
  assert.equal(report.run.attacksRun, ASB_BROWSER_V1.attackIds.length);
  assert.equal(report.target.provider, 'ollama');
  assert.equal(report.target.model, 'qwen-test');
  assert.match(renderMarkdownReport(report), /\*\*Model:\*\* `ollama\/qwen-test`/);
  assert.equal(summarizeReport(report).target.provider, 'ollama');
});

test('a run stopped by a used-up quota is refused, not graded', async () => {
  answered = 0; quotaAfter = 3;
  await assert.rejects(
    runSuite({ target: target('quota-test'), suite: ASB_BROWSER_V1, targetMeta: meta, ward }),
    (err) => err instanceof IncompleteRunError && err.completed === 3 && err.planned === ASB_BROWSER_V1.attackIds.length,
  );
});

test('buildReport refuses a scorecard marked as a partial run', () => {
  const scorecard = {
    adversaryVersion: '0.4.0', target: { kind: 'demo', identifier: 'x' }, startedAt: 0, durationMs: 1,
    stoppedEarly: { reason: 'quota', completed: 1, planned: 20 },
    summary: { total: 1, blocked: 1, partial: 0, breached: 0, score: 100, byCategory: {}, bySeverity: {} },
    findings: [{ attackId: ASB_BROWSER_V1.attackIds[0], category: 'ipi', severity: 'high', result: 'blocked', evidence: 'e' }],
  };
  assert.throws(() => buildReport(scorecard, ASB_BROWSER_V1, meta), IncompleteRunError);
});
