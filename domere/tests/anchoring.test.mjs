// Dōmere anchoring: prepared data is correct for each chain, and Dōmere never
// claims to have submitted or verified anything on-chain. (Before 1.4.1,
// preparing crashed, selectors used SHA-256, the Solana PDA was a placeholder,
// and submit/verify returned invented transaction ids and valid: true.)
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { DomereToolHandler, AnchoringService, createStorage } from '../dist/index.js';
import { findProgramAddress, anchorDiscriminator } from '../dist/anchoring/solana.js';

const hex = (b) => Buffer.from(b).toString('hex');

async function preparedThread() {
  const tools = new DomereToolHandler(createStorage('memory'));
  const { thread_id } = await tools.handleTool('domere_create_thread', { origin_type: 'human', origin_identity: 'alice', intent: 'Summarize the report' });
  await tools.handleTool('domere_add_hop', { thread_id, agent_id: 'a1', agent_type: 'llm', received_intent: 'Summarize the report', actions: [] });
  return { tools, thread_id };
}

describe('Ethereum', () => {
  test('calldata uses the real Keccak-256 selector and ABI-encodes five static args', async () => {
    const { tools, thread_id } = await preparedThread();
    const r = await tools.handleTool('domere_prepare_anchor', { thread_id, network: 'ethereum' });
    const data = r.transaction_data.data;
    const selector = hex(keccak_256(new TextEncoder().encode('anchorThread(bytes32,bytes32,uint256,bytes32,bool)'))).slice(0, 8);
    assert.equal(data.slice(2, 10), selector);
    assert.equal((data.length - 2) / 2, 4 + 5 * 32);
    assert.match(data.slice(-64), /^0{63}[01]$/, 'trailing bool word');
  });
});

describe('Solana', () => {
  test('PDA derivation matches @solana/web3.js (reference vector)', () => {
    const threadId = createHash('sha256').update('thr_vector').digest();
    const [pda, bump] = findProgramAddress([new TextEncoder().encode('thread_anchor'), Uint8Array.from(threadId)], 'BeCYVJYfbUu3k2TPGmh9VoGWeJwzm2hg2NdtnvbdBNCj');
    assert.equal(pda, 'HKY5frQQuSMV8rp2DAdNxAUQBhDURminDhGWhecmfHZS');
    assert.equal(bump, 255);
  });

  test('prepare returns a real instruction: discriminator + Borsh args, derived PDA', async () => {
    const { tools, thread_id } = await preparedThread();
    const r = await tools.handleTool('domere_prepare_anchor', { thread_id, network: 'solana' });
    const [ix] = r.transaction_data.instructions;
    const data = Buffer.from(ix.data_base64, 'base64');
    assert.equal(data.length, 8 + 32 + 32 + 8 + 32 + 1);
    assert.equal(hex(data.subarray(0, 8)), hex(anchorDiscriminator('anchor_thread')));
    assert.equal(hex(anchorDiscriminator('anchor_thread')), createHash('sha256').update('global:anchor_thread').digest('hex').slice(0, 16));
    assert.equal(data.readBigUInt64LE(72), 1n, 'hop_count');
    assert.ok(!ix.accounts[1].pubkey.startsWith('PDA_'), 'real PDA, not a placeholder');
    assert.equal(ix.accounts[3].pubkey, '11111111111111111111111111111111');
  });
});

describe('no invented chain results', () => {
  for (const network of ['solana', 'ethereum']) {
    test(`${network}: submit and verify say they are not implemented`, async () => {
      const svc = new AnchoringService();
      await assert.rejects(svc.submitSignedTransaction(network, 'signed'), /does not broadcast/);
      await assert.rejects(svc.verifyAnchor(network, 'thr_x', '00'.repeat(32)), /does not broadcast/);
    });
  }
});
