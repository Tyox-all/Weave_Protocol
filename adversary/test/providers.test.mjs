// Adversary v0.4 provider layer: any OpenAI-compatible provider can be the
// target or mutation model. Driven against a local fake server; no network.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { resolveModelConfig, callModel, estimateModelCost, DemoTarget, DynamicAttackMutator } from '../dist/index.js';
import { isLongWait } from '../dist/providers.js';

let server, baseUrl;
const requests = [];
let script = []; // queued [status, body] replies; default is a plain answer

before(async () => {
  server = createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      requests.push({ url: req.url, auth: req.headers.authorization, body: JSON.parse(raw) });
      const [status, body] = script.shift() ?? [200, reply('ok')];
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(body));
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  baseUrl = `http://127.0.0.1:${server.address().port}/v1/`;
});
after(() => server.close());

function reply(content, usage = { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 }) {
  return { model: 'served-model', choices: [{ finish_reason: 'stop', message: { content } }], usage };
}
const local = (extra = {}) => resolveModelConfig({ provider: 'ollama', model: 'qwen-test', baseUrl, ...extra });

describe('resolveModelConfig', () => {
  test('defaults to Claude on anthropic', () => {
    const c = resolveModelConfig({ env: { ANTHROPIC_API_KEY: 'k' } });
    assert.equal(c.provider, 'anthropic');
    assert.match(c.model, /^claude-/);
    assert.equal(c.keySource, 'ANTHROPIC_API_KEY');
  });

  test('every other provider needs an explicit model', () => {
    assert.throws(() => resolveModelConfig({ provider: 'deepseek', env: { DEEPSEEK_API_KEY: 'k' } }), /needs a model id/);
  });

  test('missing keys name the env vars to set', () => {
    assert.throws(() => resolveModelConfig({ provider: 'moonshot', model: 'm', env: {} }), /MOONSHOT_API_KEY/);
    assert.throws(() => resolveModelConfig({ provider: 'nope', model: 'm', env: {} }), /Unknown provider/);
  });

  test('Gemini falls back to GOOGLE_API_KEY and asks for low reasoning effort', () => {
    const c = resolveModelConfig({ provider: 'gemini', model: 'g', env: { GOOGLE_API_KEY: 'k' } });
    assert.equal(c.keySource, 'GOOGLE_API_KEY');
    assert.equal(c.reasoningEffort, 'low');
    assert.match(c.baseUrl, /generativelanguage/);
  });

  test('local providers need no key; base URL can be overridden', () => {
    const c = local();
    assert.equal(c.apiKey, undefined);
    assert.equal(c.baseUrl, baseUrl.replace(/\/$/, ''));
  });
});

describe('callModel (OpenAI-compatible)', () => {
  test('sends system + user turns and the key as a bearer token', async () => {
    requests.length = 0;
    const res = await callModel(local({ apiKey: 'test-key', reasoningEffort: 'none' }), { systemPrompt: 'sys', userMessage: 'hi', maxTokens: 50 });
    const [r] = requests;
    assert.equal(r.url, '/v1/chat/completions');
    assert.equal(r.auth, 'Bearer test-key');
    assert.deepEqual(r.body.messages, [{ role: 'system', content: 'sys' }, { role: 'user', content: 'hi' }]);
    assert.equal(r.body.max_tokens, 50);
    assert.equal(r.body.reasoning_effort, 'none');
    assert.deepEqual(res, { text: 'ok', inputTokens: 10, outputTokens: 5, model: 'served-model', stopReason: 'stop' });
  });

  test('counts reasoning tokens left out of completion_tokens as output', async () => {
    script = [[200, reply('hello', { prompt_tokens: 11, completion_tokens: 7, total_tokens: 182 })]];
    const res = await callModel(local(), { systemPrompt: 's', userMessage: 'u' });
    assert.equal(res.outputTokens, 171);
  });

  test('accepts array-wrapped responses and content parts', async () => {
    script = [[200, [reply([{ type: 'text', text: 'a' }, { type: 'image' }, { type: 'text', text: 'b' }])]]];
    assert.equal((await callModel(local(), { systemPrompt: 's', userMessage: 'u' })).text, 'a\nb');
  });

  test('retries overload and rate limits, not bad requests', async () => {
    requests.length = 0;
    script = [[503, { error: 'busy' }], [429, { error: 'slow down' }], [200, reply('made it')]];
    assert.equal((await callModel(local(), { systemPrompt: 's', userMessage: 'u' }, { baseDelayMs: 1 })).text, 'made it');
    assert.equal(requests.length, 3);

    requests.length = 0;
    script = [[400, { error: 'bad model' }]];
    await assert.rejects(callModel(local(), { systemPrompt: 's', userMessage: 'u' }, { baseDelayMs: 1 }), /Ollama \(local\) API 400/);
    assert.equal(requests.length, 1);

    // A daily quota won't clear mid-run, so it fails at once
    requests.length = 0;
    script = [[429, { error: { message: 'Generate content requests per day limit exceeded on Free Tier. Please retry in 11h36m53.2s.' } }]];
    await assert.rejects(callModel(local(), { systemPrompt: 's', userMessage: 'u' }, { baseDelayMs: 1 }), /API 429/);
    assert.equal(requests.length, 1);

    script = [[503, {}], [503, {}], [503, {}]];
    await assert.rejects(callModel(local(), { systemPrompt: 's', userMessage: 'u' }, { retries: 2, baseDelayMs: 1 }), /API 503/);
  });
});

test('long waits are recognized, short ones are not', () => {
  assert.equal(isLongWait('Please retry in 11h36m53.198s.'), true);
  assert.equal(isLongWait('quota: requests per day exceeded'), true);
  assert.equal(isLongWait('Please retry in 2m0s.'), true);
  assert.equal(isLongWait('Please retry in 7.5s.'), false);
  assert.equal(isLongWait('model overloaded'), false);
});

test('cost is unknown, not $0, for unpriced hosted models', () => {
  assert.equal(estimateModelCost({ provider: 'deepseek', model: 'deepseek-chat' }, 1e6, 1e6), null);
  assert.equal(estimateModelCost({ provider: 'ollama', model: 'anything' }, 1e6, 1e6), 0);
  assert.equal(estimateModelCost({ provider: 'anthropic', model: 'claude-haiku-5-5' }, 1e6, 1e6), 0.6);
  assert.equal(estimateModelCost({ provider: 'anthropic', model: 'claude-unknown' }, 1e6, 1e6), null);
});

test('DemoTarget runs against any provider and parses its tool calls', async () => {
  script = [[200, reply('Sure.\n{"tool": "send_email", "args": {"to": "x@example.test"}}')]];
  const target = new DemoTarget({ mode: 'real', provider: 'ollama', model: 'qwen-test', baseUrl });
  assert.equal(target.identifier, 'demo:vulnerable-agent (real LLM: ollama/qwen-test)');
  const res = await target.execute({ id: 't', category: 'tool_coercion', delivery: 'user_message', payload: 'p' });
  assert.equal(res.toolCalls[0].name, 'send_email');
  assert.equal(res.metadata.provider, 'ollama');
  const u = target.getUsage();
  assert.equal(u.apiCalls, 1);
  assert.equal(u.estimatedCostUSD, 0);
});

test('DynamicAttackMutator reports provider and unknown cost', async () => {
  const m = new DynamicAttackMutator({ provider: 'openrouter', model: 'some/model', apiKey: 'k', baseUrl });
  script = [[200, reply('a variant')]];
  const r = await m.mutate({ category: 'jailbreak', severity: 'low' }, 'no', 'orig');
  assert.equal(r.variantPayload, 'a variant');
  assert.equal(r.costUSD, null);
  const u = m.getUsage();
  assert.equal(u.provider, 'openrouter');
  assert.equal(u.estimatedCostUSD, null);
});
