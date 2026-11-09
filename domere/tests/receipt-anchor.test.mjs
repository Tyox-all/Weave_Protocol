// Dōmere 1.7.0: anchoring Ward receipt checkpoints.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, createPublicKey, sign } from 'node:crypto';
import { existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DomereToolHandler, createStorage, prepareReceiptAnchor, verifyReceiptAnchorBundle, verifyReceiptCheckpoint } from '../dist/index.js';

const sha256 = (d) => createHash('sha256').update(d).digest('hex');
const canonical = (v) => v === null || typeof v !== 'object' ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canonical).join(',')}]`
  : `{${Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;

// Ward's checkpoint format, signed here so the test doesn't need Ward
function checkpoint(agent, seq, { privateKey } = generateKeyPairSync('ed25519')) {
  const spki = createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  const body = { type: 'checkpoint', v: 1, agent, seq, head: 'sha256:' + sha256(`${agent}${seq}`), at: new Date().toISOString(), keyId: sha256(spki).slice(0, 16), publicKey: spki.toString('base64') };
  return { ...body, sig: sign(null, Buffer.from(`ward-checkpoint/v1:${sha256(canonical(body))}`), privateKey).toString('base64') };
}

describe('receipt anchors', () => {
  test('a batch commits to every checkpoint, in any input order', () => {
    const cps = [checkpoint('build-bot', 12), checkpoint('reviewer', 3)];
    assert.ok(cps.every(verifyReceiptCheckpoint));
    const a = prepareReceiptAnchor(cps, 'solana');
    const b = prepareReceiptAnchor([...cps].reverse(), 'solana');
    assert.equal(a.bundle.merkle_root, b.bundle.merkle_root);
    assert.match(a.bundle.merkle_root, /^[0-9a-f]{64}$/);
    assert.equal(a.bundle.receipts, 15);
    assert.equal(a.request.thread_id, a.bundle.anchor_id);
    assert.equal(a.request.hop_count, 15);
    assert.equal(a.request.intent_hash, a.bundle.manifest_hash);
    assert.equal(verifyReceiptAnchorBundle(JSON.parse(JSON.stringify(a.bundle))).ok, true);
  });

  test('a changed, dropped or forged checkpoint breaks the bundle', () => {
    const { bundle } = prepareReceiptAnchor([checkpoint('a', 5), checkpoint('b', 7)], 'ethereum');
    const edited = structuredClone(bundle); edited.checkpoints[0].seq = 4;
    assert.match(verifyReceiptAnchorBundle(edited).problems.join(), /invalid signature/);
    const dropped = structuredClone(bundle); dropped.checkpoints.pop();
    assert.match(verifyReceiptAnchorBundle(dropped).problems.join(), /merkle_root does not match/);
    const swapped = structuredClone(bundle); swapped.checkpoints[1] = checkpoint('b', 7);
    assert.match(verifyReceiptAnchorBundle(swapped).problems.join(), /merkle_root does not match/);
    assert.throws(() => prepareReceiptAnchor([{ ...checkpoint('a', 1), seq: 2 }], 'solana'), /invalid signature/);
    assert.throws(() => prepareReceiptAnchor([], 'solana'), /No checkpoints/);
  });

  test('MCP: domere_anchor_receipts returns the bundle and an unsigned transaction', async () => {
    const tools = new DomereToolHandler(createStorage('memory'));
    for (const network of ['solana', 'ethereum']) {
      const r = await tools.handleTool('domere_anchor_receipts', { checkpoints: [checkpoint('x', 2)], network });
      assert.equal(r.bundle.type, 'ward-receipt-anchor');
      assert.ok(r.transaction.transaction_data);
      assert.ok(r.bundle.merkle_root && r.next.includes('--checkpoints'));
      const v = await tools.handleTool('domere_verify_receipt_anchor', { bundle: r.bundle });
      assert.equal(v.ok, true);
    }
    const ix = (await tools.handleTool('domere_anchor_receipts', { checkpoints: [checkpoint('x', 2)], network: 'solana' })).transaction.transaction_data.instructions[0];
    const data = Buffer.from(ix.data_base64, 'base64');
    assert.equal(data.readBigUInt64LE(72), 2n, 'receipt count on-chain');
  });
});

// With Ward built alongside (the monorepo), check against real Ward checkpoints
const wardDist = new URL('../../ward/dist/receipts/index.js', import.meta.url);
test('real Ward checkpoints anchor, and Ward reads the bundle back', { skip: !existsSync(wardDist) && 'Ward not built' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'domere-ward-'));
  process.env.WEAVE_RECEIPT_DIR = join(dir, 'r');
  process.env.WEAVE_RECEIPT_KEY_FILE = join(dir, 'k.pem');
  const ward = await import(wardDist.href);
  const { parseWard } = await import(new URL('../../ward/dist/index.js', import.meta.url).href);
  const policy = parseWard('---\nward: "1.0"\nagent: anchored\n---\n\n## Capabilities\n\ndefault: allow\n');
  for (let i = 0; i < 3; i++) ward.appendReceipt({ agent: 'anchored', tool: 't', capability: 't', decision: 'allow', reasons: [], args: { i }, policy });
  const log = ward.receiptLogPath('anchored');
  const { bundle } = prepareReceiptAnchor([ward.createCheckpoint(log)], 'solana');
  assert.equal(verifyReceiptAnchorBundle(bundle).ok, true);
  const r = ward.verifyReceiptLog(log, { checkpoints: ward.readCheckpoints(JSON.stringify(bundle)) });
  assert.equal(r.ok, true);
  assert.equal(r.checkpointedSeq, 3);
});
