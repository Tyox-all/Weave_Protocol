// Witan spending caps. The unpriced-model, negative-amount and current-model
// pricing cases are regressions fixed in 1.2.0.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { SpendingTracker, lookupPricing, estimateLLMCost } from '../dist/spending/index.js';

const quiet = { onNotify: () => {} };
const llm = (model, inTok, outTok = inTok, provider = 'anthropic') => ({ kind: 'llm', provider, model, estInputTokens: inTok, estOutputTokens: outTok });

describe('pricing', () => {
  test('current Claude models are priced', () => {
    for (const m of ['claude-fable-5-1', 'claude-opus-5-5', 'claude-sonnet-5-5', 'claude-haiku-5-5', 'claude-opus-4-8', 'claude-haiku-4-5']) {
      assert.ok(lookupPricing('anthropic', m), m);
    }
    assert.equal(estimateLLMCost('anthropic', 'claude-opus-5-5', 1_000_000, 1_000_000), 24);
    assert.equal(estimateLLMCost('anthropic', 'claude-opus-4-7', 1_000_000, 0), 5);
  });
});

describe('USD caps', () => {
  test('block once the projected spend passes the cap', async () => {
    const t = new SpendingTracker({ caps: [{ window: 'day', budget: { usd: 10 }, onExceeded: 'block' }], ...quiet });
    assert.equal((await t.checkAction(llm('claude-opus-5-5', 100_000))).blocked, false); // $2.40
    await t.recordLLM({ provider: 'anthropic', model: 'claude-opus-5-5', inputTokens: 300_000, outputTokens: 300_000 }); // $7.20
    assert.equal((await t.checkAction(llm('claude-opus-5-5', 100_000))).blocked, false); // 7.20 + 2.40 = 9.60
    assert.equal((await t.checkAction(llm('claude-opus-5-5', 200_000))).blocked, true); // 7.20 + 4.80
  });

  test('an unpriced model fails closed under a USD cap', async () => {
    const t = new SpendingTracker({ caps: [{ window: 'day', budget: { usd: 10 }, onExceeded: 'block' }], ...quiet });
    const c = await t.checkAction(llm('brand-new-model', 10));
    assert.equal(c.blocked, true);
    assert.match(c.reason, /No price known/);
  });

  test('an unpriced model is fine when only a token cap applies', async () => {
    const t = new SpendingTracker({ caps: [{ window: 'day', budget: { tokens: 1000 }, onExceeded: 'block' }], ...quiet });
    assert.equal((await t.checkAction(llm('brand-new-model', 100))).blocked, false);
    assert.equal((await t.checkAction(llm('brand-new-model', 600))).blocked, true);
  });

  test('negative amounts cannot reduce recorded spend', async () => {
    const t = new SpendingTracker({ caps: [{ window: 'day', budget: { usd: 10 }, onExceeded: 'block' }], ...quiet });
    await t.recordTool({ tool: 'pay', args: { amount: 9 } });
    await t.recordTool({ tool: 'pay', args: { amount: -1000 } });
    await t.recordTool({ tool: 'pay', amountUSD: -50 });
    assert.equal((await t.getUsage('day')).usd, 9);
    assert.equal((await t.checkAction({ kind: 'tool', tool: 'pay', amountUSD: 5 })).blocked, true);
    assert.equal((await t.checkAction({ kind: 'tool', tool: 'pay', amountUSD: -5 })).blocked, false, 'a negative proposal adds nothing');
  });
});

describe('tool caps', () => {
  test('total and per-tool call counts, and per-tool amounts', async () => {
    const t = new SpendingTracker({
      caps: [{ window: 'run', budget: { tool_calls: 3, usd: 1000, tools: { pay: { max_calls: 1, max_amount_usd: 100 } } }, onExceeded: 'block' }],
      ...quiet,
    });
    assert.equal((await t.checkAction({ kind: 'tool', tool: 'pay', args: { amount: '$150' } })).blocked, true, '"$150" parsed');
    await t.recordTool({ tool: 'pay', args: { amount: 50 } });
    assert.equal((await t.checkAction({ kind: 'tool', tool: 'pay', args: { amount: 10 } })).blocked, true, 'pay max_calls 1');
    await t.recordTool({ tool: 'search' });
    await t.recordTool({ tool: 'search' });
    assert.equal((await t.checkAction({ kind: 'tool', tool: 'search' })).blocked, true, 'total tool_calls 3');
  });
});

describe('windows, approvals and scope', () => {
  test('a new day starts a fresh window', async () => {
    let now = Date.UTC(2026, 10, 2, 23, 0);
    const t = new SpendingTracker({ caps: [{ window: 'day', budget: { usd: 1 }, onExceeded: 'block' }], now: () => now, ...quiet });
    await t.recordTool({ tool: 'pay', amountUSD: 1, ts: now });
    assert.equal((await t.checkAction({ kind: 'tool', tool: 'pay', amountUSD: 0.5 })).blocked, true);
    now = Date.UTC(2026, 10, 3, 1, 0);
    assert.equal((await t.checkAction({ kind: 'tool', tool: 'pay', amountUSD: 0.5 })).blocked, false);
  });

  test('require_approval asks the handler; a no blocks the action', async () => {
    const asked = [];
    const t = new SpendingTracker({
      caps: [{ window: 'day', budget: { usd: 1 }, onExceeded: 'require_approval' }],
      approvalHandler: async (e) => { asked.push(e.summary); return false; },
      ...quiet,
    });
    const c = await t.checkAction({ kind: 'tool', tool: 'pay', amountUSD: 5 });
    assert.equal(c.blocked, false);
    assert.equal(c.requiresApproval, true);
    assert.equal(await c.approve(), false);
    assert.equal(c.blocked, true);
    assert.equal(asked.length, 1);
  });

  test('notify caps report but allow', async () => {
    const notes = [];
    const t = new SpendingTracker({ caps: [{ window: 'day', budget: { usd: 1 }, onExceeded: 'notify' }], onNotify: (e) => notes.push(e) });
    const c = await t.checkAction({ kind: 'tool', tool: 'pay', amountUSD: 5 });
    assert.equal(c.blocked, false);
    assert.equal(notes.length, 1);
  });

  test('scoped caps apply only to their scope', async () => {
    const t = new SpendingTracker({ caps: [{ window: 'day', scope: 'agent-a', budget: { usd: 1 }, onExceeded: 'block' }], ...quiet });
    assert.equal((await t.checkAction({ kind: 'tool', tool: 'pay', amountUSD: 5, scope: 'agent-a' })).blocked, true);
    assert.equal((await t.checkAction({ kind: 'tool', tool: 'pay', amountUSD: 5, scope: 'agent-b' })).blocked, false);
  });
});
