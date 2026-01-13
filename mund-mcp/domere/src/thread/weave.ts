/**
 * Dōmere - The Judge Protocol
 * Weave Signature - Cryptographic thread verification
 */

import * as crypto from 'crypto';
import type { ThreadOrigin, ThreadIntent, AgentInfo, HopAction } from '../types.js';

// ============================================================================
// Weave Signature
// ============================================================================

export class WeaveSignature {
  private algorithm: string = 'sha256';
  
  /**
   * Create initial thread signature
   */
  createInitial(data: {
    threadId: string;
    origin: ThreadOrigin;
    intent: ThreadIntent;
  }): string {
    const canonical = this.canonicalize({
      type: 'thread_init',
      thread_id: data.threadId,
      origin: {
        type: data.origin.type,
        identity: data.origin.identity,
        timestamp: data.origin.timestamp.toISOString(),
      },
      intent: {
        hash: data.intent.hash,
        classification: data.intent.classification,
        constraints: data.intent.constraints,
      },
    });
    
    return this.hash(canonical);
  }
  
  /**
   * Sign a hop
   */
  signHop(data: {
    hopId: string;
    agent: AgentInfo;
    received_intent: string;
    actions: HopAction[];
    timestamp: Date;
  }, previousHash: string): string {
    const canonical = this.canonicalize({
      type: 'hop',
      hop_id: data.hopId,
      previous_hash: previousHash,
      agent: {
        id: data.agent.id,
        type: data.agent.type,
      },
      received_intent_hash: this.hash(data.received_intent),
      actions_hash: this.hashActions(data.actions),
      timestamp: data.timestamp.toISOString(),
    });
    
    return this.hash(canonical);
  }
  
  /**
   * Compute cumulative hash
   */
  computeCumulativeHash(previousHash: string, currentSignature: string): string {
    return this.hash(`${previousHash}:${currentSignature}`);
  }
  
  /**
   * Verify a signature chain
   */
  verifyChain(signatures: string[]): boolean {
    if (signatures.length < 2) return true;
    const unique = new Set(signatures);
    return unique.size === signatures.length;
  }
  
  /**
   * Generate Merkle root from hop signatures
   */
  generateMerkleRoot(signatures: string[]): string {
    if (signatures.length === 0) {
      return this.hash('empty');
    }
    
    let hashes = [...signatures];
    
    while (hashes.length > 1) {
      const newLevel: string[] = [];
      for (let i = 0; i < hashes.length; i += 2) {
        if (i + 1 < hashes.length) {
          newLevel.push(this.hash(hashes[i] + hashes[i + 1]));
        } else {
          newLevel.push(hashes[i]);
        }
      }
      hashes = newLevel;
    }
    
    return hashes[0];
  }
  
  /**
   * Generate Merkle proof for a specific leaf
   */
  generateMerkleProof(signatures: string[], leafIndex: number): string[] {
    if (leafIndex < 0 || leafIndex >= signatures.length) {
      return [];
    }
    
    const proof: string[] = [];
    let hashes = [...signatures];
    let index = leafIndex;
    
    while (hashes.length > 1) {
      const newLevel: string[] = [];
      
      for (let i = 0; i < hashes.length; i += 2) {
        if (i + 1 < hashes.length) {
          if (i === index || i + 1 === index) {
            const siblingIndex = i === index ? i + 1 : i;
            proof.push(hashes[siblingIndex]);
          }
          newLevel.push(this.hash(hashes[i] + hashes[i + 1]));
        } else {
          newLevel.push(hashes[i]);
        }
      }
      
      index = Math.floor(index / 2);
      hashes = newLevel;
    }
    
    return proof;
  }
  
  /**
   * Verify Merkle proof
   */
  verifyMerkleProof(
    leaf: string,
    proof: string[],
    root: string,
    leafIndex: number
  ): boolean {
    let hash = leaf;
    let index = leafIndex;
    
    for (const sibling of proof) {
      if (index % 2 === 0) {
        hash = this.hash(hash + sibling);
      } else {
        hash = this.hash(sibling + hash);
      }
      index = Math.floor(index / 2);
    }
    
    return hash === root;
  }
  
  /**
   * Create a thread summary hash for anchoring
   */
  createAnchorHash(data: {
    threadId: string;
    merkleRoot: string;
    hopCount: number;
    intentHash: string;
    compliant: boolean;
    closedAt: Date;
  }): string {
    const canonical = this.canonicalize({
      type: 'anchor',
      thread_id: data.threadId,
      merkle_root: data.merkleRoot,
      hop_count: data.hopCount,
      intent_hash: data.intentHash,
      compliant: data.compliant,
      closed_at: data.closedAt.toISOString(),
    });
    
    return this.hash(canonical);
  }
  
  private hash(data: string): string {
    return crypto.createHash(this.algorithm).update(data).digest('hex');
  }
  
  private canonicalize(obj: unknown): string {
    return JSON.stringify(obj, Object.keys(obj as object).sort());
  }
  
  private hashActions(actions: HopAction[]): string {
    const actionStrings = actions.map(a => 
      `${a.type}:${a.target || ''}:${a.description}`
    );
    return this.hash(actionStrings.join('|'));
  }
}
