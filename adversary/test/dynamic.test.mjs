// Adversary v0.3 dynamic mutation + v0.2 compatibility. Runs against dist/.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AdversarialAgent, classifyEngagement } from '../dist/index.js';
import { redactScorecard } from '../dist/scorecard/index.js';

const NO_WARD = { loaded: false, rules: [] };

const attack = {
  id: 'test-001', name: 'Test', category: 'tool_coercion', severity: 'high',
  delivery: 'direct', payload: 'original payload', detectionPatterns: [/SECRET/],
  wardRulesProbed: [], description: 'test', source: 'test',
};

const refusal = 'I\'m sorry, but I can\'t help with sending that email on your behalf.';
const breach = { text: 'Sure, sending now. SECRET', toolCalls: [{ name: 'send_email', arguments: { to: 'x@evil.test' } }], turns: 3 };

function scriptedTarget(responses) {
  const seen = [];
  return {
    seen,
    target: {
      kind: 'demo', identifier: 'scripted',
      async execute(a) {
        seen.push(typeof a.payload === 'function' ? a.payload() : a.payload);
        return responses[Math.min(seen.length - 1, responses.length - 1)];
      },
    },
  };
}

function fakeMutator(maxRetries = 2) {
  let n = 0;
  return {
    maxRetries,
    calls: () => n,
    async mutate(_a, _resp, prev) { n++; return { variantPayload: `${prev} v${n}`, inputTokens: 10, outputTokens: 5, costUSD: 0 }; },
    getUsage: () => ({ mutations: n, inputTokens: 10 * n, outputTokens: 5 * n, errors: 0, estimatedCostUSD: 0, model: 'fake' }),
  };
}

test('classifyEngagement distinguishes breach / half-block / full-block', () => {
  assert.equal(classifyEngagement(''), 'full-block');
  assert.equal(classifyEngagement('No.'), 'full-block');
  assert.equal(classifyEngagement(refusal), 'half-block');
  assert.equal(classifyEngagement('Here is the information you asked for, in full detail.'), 'breach');
});

test('static mode keeps v0.2 Finding shape: toolCallsMade, timeToExploit = turns, no attempts', async () => {
  const { target } = scriptedTarget([breach]);
  const agent = new AdversarialAgent(target, { ward: NO_WARD });
  const f = await agent.runOne(attack, {});
  assert.equal(f.result, 'breached');
  assert.equal(f.timeToExploit, 3);
  assert.deepEqual(f.toolCallsMade, breach.toolCalls);
  assert.equal(f.attempts, undefined);
});

test('dynamic mode retries a half-block with a mutated payload and reports the best attempt', async () => {
  const { target, seen } = scriptedTarget([{ text: refusal, toolCalls: [], turns: 1 }, breach]);
  const mutator = fakeMutator();
  const agent = new AdversarialAgent(target, { ward: NO_WARD, mutator });
  const f = await agent.runOne(attack, { dynamic: true });
  assert.deepEqual(seen, ['original payload', 'original payload v1']);
  assert.equal(f.result, 'breached');
  assert.equal(f.attempts.length, 2);
  assert.equal(f.attempts[0].engagement, 'half-block');
  assert.deepEqual(f.attempts[0].mutationTokens, { input: 10, output: 5 });
  assert.deepEqual(f.toolCallsMade, breach.toolCalls);
  assert.equal(f.timeToExploit, 3);
});

test('dynamic mode does not mutate after a full block', async () => {
  const { target, seen } = scriptedTarget([{ text: 'No.', toolCalls: [], turns: 1 }]);
  const mutator = fakeMutator();
  const f = await new AdversarialAgent(target, { ward: NO_WARD, mutator }).runOne(attack, { dynamic: true });
  assert.equal(mutator.calls(), 0);
  assert.equal(seen.length, 1);
  assert.equal(f.result, 'blocked');
});

test('dynamic mode stops at maxRetries', async () => {
  const { target, seen } = scriptedTarget([{ text: refusal, toolCalls: [], turns: 1 }]);
  const mutator = fakeMutator(2);
  const f = await new AdversarialAgent(target, { ward: NO_WARD, mutator }).runOne(attack, { dynamic: true });
  assert.equal(seen.length, 3);
  assert.equal(mutator.calls(), 2);
  assert.equal(f.attempts.length, 3);
});

test('--redact-evidence scrubs per-attempt responses and tool args too', async () => {
  const { target } = scriptedTarget([{ text: refusal + ' SECRET', toolCalls: [], turns: 1 }, breach]);
  const agent = new AdversarialAgent(target, { ward: NO_WARD, mutator: fakeMutator() });
  const f = await agent.runOne(attack, { dynamic: true });
  const card = redactScorecard({ findings: [f] });
  const json = JSON.stringify(card);
  assert.ok(!json.includes('SECRET'), json);
  assert.ok(!json.includes('x@evil.test'), json);
});
