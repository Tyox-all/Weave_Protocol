/**
 * Dōmere - anchoring Ward receipt checkpoints (Dōmere 1.7.0)
 *
 * Ward's decision receipts form a signed hash chain, but a chain can't show
 * that its newest receipts were cut off. `weave-ward receipts checkpoint`
 * signs a log's head; this batches checkpoints from any number of agents
 * into one Merkle root and prepares the transaction that anchors it on
 * Solana or Ethereum (the user's wallet signs and sends it; Dōmere never
 * broadcasts). The returned bundle is what verifiers keep:
 *
 *   weave-ward receipts verify <log> --checkpoints=<bundle.json>
 *
 * checks the log against the bundle's checkpoints, and
 * verifyReceiptAnchorBundle recomputes the root to compare with the value
 * stored on-chain under the bundle's anchor id.
 */

import { createHash, createPublicKey, verify } from 'node:crypto';
import type { AnchorRequest, BlockchainNetwork } from '../types.js';
import { AnchoringError } from '../types.js';
import { MerkleTree } from './merkle.js';

/** A Ward receipt checkpoint (see @weave_protocol/ward/receipts). */
export interface ReceiptCheckpoint {
  type: 'checkpoint';
  v: 1;
  agent: string;
  seq: number;
  head: string;
  at: string;
  keyId: string;
  publicKey: string;
  sig: string;
}

export interface ReceiptAnchorBundle {
  type: 'ward-receipt-anchor';
  v: 1;
  created: string;
  network: BlockchainNetwork;
  /** Id the anchor is stored under on-chain (Dōmere's thread_id) */
  anchor_id: string;
  /** Merkle root over the checkpoints, hex */
  merkle_root: string;
  /** SHA-256 of the canonical checkpoint list, hex (stored as intent_hash) */
  manifest_hash: string;
  /** Total receipts the checkpoints cover (stored as hop_count) */
  receipts: number;
  checkpoints: ReceiptCheckpoint[];
}

const sha256 = (data: string | Buffer) => createHash('sha256').update(data).digest('hex');

/** Same canonical JSON as Ward: keys sorted at every level. */
function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
}

/** Is a checkpoint signed by the key it names? (Same check as Ward's verifyCheckpoint.) */
export function verifyReceiptCheckpoint(cp: ReceiptCheckpoint): boolean {
  try {
    if (cp?.type !== 'checkpoint' || cp.v !== 1 || !Number.isInteger(cp.seq) || cp.seq < 1) return false;
    const spki = Buffer.from(cp.publicKey, 'base64');
    if (sha256(spki).slice(0, 16) !== cp.keyId) return false;
    const { sig: _s, ...body } = cp;
    const message = Buffer.from(`ward-checkpoint/v1:${sha256(canonicalJson(body))}`);
    return verify(null, message, createPublicKey({ key: spki, format: 'der', type: 'spki' }), Buffer.from(cp.sig, 'base64'));
  } catch {
    return false;
  }
}

// Order checkpoints so the same set always gives the same root
const order = (cps: ReceiptCheckpoint[]) =>
  [...cps].sort((a, b) => (a.agent < b.agent ? -1 : a.agent > b.agent ? 1 : a.seq - b.seq || (a.keyId < b.keyId ? -1 : a.keyId > b.keyId ? 1 : 0)));

function commitments(cps: ReceiptCheckpoint[]) {
  const leaves = cps.map((cp) => createHash('sha256').update(`ward-checkpoint-leaf/v1:${canonicalJson(cp)}`).digest());
  return {
    merkle_root: new MerkleTree(leaves).getRootHex(),
    manifest_hash: sha256(canonicalJson(cps)),
    receipts: cps.reduce((n, cp) => n + cp.seq, 0),
  };
}

/**
 * Build the anchor bundle and the on-chain request for a set of checkpoints.
 * Throws if any checkpoint's signature is invalid, or the set is empty.
 */
export function prepareReceiptAnchor(checkpoints: ReceiptCheckpoint[], network: BlockchainNetwork): {
  bundle: ReceiptAnchorBundle;
  request: AnchorRequest;
} {
  if (!Array.isArray(checkpoints) || !checkpoints.length) throw new AnchoringError('No checkpoints to anchor. Make one with: weave-ward receipts checkpoint');
  const bad = checkpoints.findIndex((cp) => !verifyReceiptCheckpoint(cp));
  if (bad >= 0) throw new AnchoringError(`Checkpoint ${bad + 1} has an invalid signature`);
  const cps = order(checkpoints);
  const c = commitments(cps);
  const anchor_id = `ward-receipts:${c.merkle_root.slice(0, 32)}`;
  const bundle: ReceiptAnchorBundle = {
    type: 'ward-receipt-anchor', v: 1, created: new Date().toISOString(), network, anchor_id, ...c, checkpoints: cps,
  };
  return {
    bundle,
    request: { thread_id: anchor_id, merkle_root: c.merkle_root, hop_count: c.receipts, intent_hash: c.manifest_hash, compliant: true, network },
  };
}

/**
 * Check a bundle offline: every checkpoint signature, and the root, manifest
 * hash and receipt count recompute. Compare `merkle_root` with the value
 * on-chain under `anchor_id` to finish the check (Dōmere doesn't read chains).
 */
export function verifyReceiptAnchorBundle(bundle: ReceiptAnchorBundle): {
  ok: boolean;
  anchor_id?: string;
  merkle_root?: string;
  checkpoints: number;
  problems: string[];
} {
  const problems: string[] = [];
  if (bundle?.type !== 'ward-receipt-anchor' || bundle.v !== 1 || !Array.isArray(bundle.checkpoints) || !bundle.checkpoints.length) {
    return { ok: false, checkpoints: 0, problems: ['not a Ward receipt anchor bundle'] };
  }
  bundle.checkpoints.forEach((cp, i) => { if (!verifyReceiptCheckpoint(cp)) problems.push(`checkpoint ${i + 1} (${cp?.agent} #${cp?.seq}) has an invalid signature`); });
  const c = commitments(order(bundle.checkpoints));
  if (c.merkle_root !== bundle.merkle_root) problems.push('merkle_root does not match the checkpoints');
  if (c.manifest_hash !== bundle.manifest_hash) problems.push('manifest_hash does not match the checkpoints');
  if (c.receipts !== bundle.receipts) problems.push('receipt count does not match the checkpoints');
  if (bundle.anchor_id !== `ward-receipts:${c.merkle_root.slice(0, 32)}`) problems.push('anchor_id does not match the checkpoints');
  return { ok: !problems.length, anchor_id: bundle.anchor_id, merkle_root: c.merkle_root, checkpoints: bundle.checkpoints.length, problems };
}
