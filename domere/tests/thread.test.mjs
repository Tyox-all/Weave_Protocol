// Dōmere threads: hops are recorded once and a thread verifies after hops are added.
// (Before 1.3.8 every hop was stored twice, so any thread with a hop failed verification.)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DomereToolHandler, createStorage } from '../dist/index.js';

const tools = () => new DomereToolHandler(createStorage('memory'));
const hop = (thread_id, n) => ({ thread_id, agent_id: `agent-${n}`, agent_type: 'llm', received_intent: 'Summarize the report', actions: [{ type: 'read', target: 'report.pdf' }] });

test('a thread verifies after each added hop', async () => {
  const t = tools();
  const { thread_id } = await t.handleTool('domere_create_thread', { origin_type: 'human', origin_identity: 'alice', intent: 'Summarize the report' });
  for (let n = 1; n <= 3; n++) {
    await t.handleTool('domere_add_hop', hop(thread_id, n));
    const v = await t.handleTool('domere_verify_thread', { thread_id });
    assert.equal(v.valid, true, JSON.stringify(v));
    assert.equal(v.total_hops, n);
  }
});

test('get_thread counts each hop once', async () => {
  const t = tools();
  const { thread_id } = await t.handleTool('domere_create_thread', { origin_type: 'human', origin_identity: 'alice', intent: 'Summarize the report' });
  await t.handleTool('domere_add_hop', hop(thread_id, 1));
  await t.handleTool('domere_add_hop', hop(thread_id, 2));
  assert.equal((await t.handleTool('domere_get_thread', { thread_id })).hop_count, 2);
});
