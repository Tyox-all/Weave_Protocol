/**
 * Dōmere - The Judge Protocol
 * Merkle Tree Utilities
 */

import * as crypto from 'crypto';

// ============================================================================
// Merkle Tree
// ============================================================================

export class MerkleTree {
  private leaves: Buffer[];
  private layers: Buffer[][];
  private root: Buffer | null = null;
  
  constructor(leaves: (string | Buffer)[]) {
    this.leaves = leaves.map(leaf => 
      typeof leaf === 'string' ? this.hashLeaf(leaf) : leaf
    );
    this.layers = [this.leaves];
    this.buildTree();
  }
  
  /**
   * Build the Merkle tree
   */
  private buildTree(): void {
    let currentLayer = this.leaves;
    
    while (currentLayer.length > 1) {
      const newLayer: Buffer[] = [];
      
      for (let i = 0; i < currentLayer.length; i += 2) {
        if (i + 1 < currentLayer.length) {
          // Sort pair for consistent ordering
          const [left, right] = this.sortPair(currentLayer[i], currentLayer[i + 1]);
          newLayer.push(this.hashPair(left, right));
        } else {
          // Promote odd node
          newLayer.push(currentLayer[i]);
        }
      }
      
      this.layers.push(newLayer);
      currentLayer = newLayer;
    }
    
    this.root = currentLayer.length > 0 ? currentLayer[0] : this.hashLeaf('empty');
  }
  
  /**
   * Get the Merkle root
   */
  getRoot(): Buffer {
    return this.root!;
  }
  
  /**
   * Get root as hex string
   */
  getRootHex(): string {
    return this.root!.toString('hex');
  }
  
  /**
   * Get root as 32-byte array (for blockchain)
   */
  getRootBytes32(): number[] {
    return Array.from(this.root!);
  }
  
  /**
   * Get proof for a leaf at given index
   */
  getProof(index: number): {
    proof: Buffer[];
    proofHex: string[];
    positions: number[];  // 0 = left, 1 = right
  } {
    if (index < 0 || index >= this.leaves.length) {
      throw new Error('Index out of bounds');
    }
    
    const proof: Buffer[] = [];
    const positions: number[] = [];
    let currentIndex = index;
    
    for (let i = 0; i < this.layers.length - 1; i++) {
      const layer = this.layers[i];
      const isRight = currentIndex % 2 === 1;
      const siblingIndex = isRight ? currentIndex - 1 : currentIndex + 1;
      
      if (siblingIndex < layer.length) {
        proof.push(layer[siblingIndex]);
        positions.push(isRight ? 0 : 1);  // Sibling position
      }
      
      currentIndex = Math.floor(currentIndex / 2);
    }
    
    return {
      proof,
      proofHex: proof.map(p => p.toString('hex')),
      positions,
    };
  }
  
  /**
   * Verify a proof
   */
  static verify(
    leaf: string | Buffer,
    proof: Buffer[],
    positions: number[],
    root: Buffer
  ): boolean {
    let current = typeof leaf === 'string' 
      ? crypto.createHash('sha256').update(leaf).digest()
      : leaf;
    
    for (let i = 0; i < proof.length; i++) {
      const [left, right] = positions[i] === 0 
        ? [proof[i], current]
        : [current, proof[i]];
      
      current = crypto.createHash('sha256')
        .update(Buffer.concat([left, right]))
        .digest();
    }
    
    return current.equals(root);
  }
  
  /**
   * Get all layers (for debugging)
   */
  getLayers(): Buffer[][] {
    return this.layers;
  }
  
  /**
   * Get leaf count
   */
  getLeafCount(): number {
    return this.leaves.length;
  }
  
  /**
   * Hash a leaf
   */
  private hashLeaf(data: string): Buffer {
    return crypto.createHash('sha256').update(data).digest();
  }
  
  /**
   * Hash a pair of nodes
   */
  private hashPair(left: Buffer, right: Buffer): Buffer {
    return crypto.createHash('sha256')
      .update(Buffer.concat([left, right]))
      .digest();
  }
  
  /**
   * Sort pair for consistent ordering
   */
  private sortPair(a: Buffer, b: Buffer): [Buffer, Buffer] {
    return Buffer.compare(a, b) <= 0 ? [a, b] : [b, a];
  }
}

// ============================================================================
// Batch Anchoring
// ============================================================================

export class BatchAnchor {
  private items: Map<string, { data: string; index: number }> = new Map();
  private tree: MerkleTree | null = null;
  
  /**
   * Add item to batch
   */
  add(id: string, data: string): void {
    if (this.tree) {
      throw new Error('Batch already finalized');
    }
    this.items.set(id, { data, index: this.items.size });
  }
  
  /**
   * Finalize batch and build tree
   */
  finalize(): string {
    if (this.items.size === 0) {
      throw new Error('Cannot finalize empty batch');
    }
    
    const leaves = Array.from(this.items.values())
      .sort((a, b) => a.index - b.index)
      .map(item => item.data);
    
    this.tree = new MerkleTree(leaves);
    return this.tree.getRootHex();
  }
  
  /**
   * Get proof for specific item
   */
  getProof(id: string): {
    proof: string[];
    positions: number[];
    root: string;
  } | null {
    if (!this.tree) {
      throw new Error('Batch not finalized');
    }
    
    const item = this.items.get(id);
    if (!item) {
      return null;
    }
    
    const { proofHex, positions } = this.tree.getProof(item.index);
    
    return {
      proof: proofHex,
      positions,
      root: this.tree.getRootHex(),
    };
  }
  
  /**
   * Get root
   */
  getRoot(): string {
    if (!this.tree) {
      throw new Error('Batch not finalized');
    }
    return this.tree.getRootHex();
  }
  
  /**
   * Get item count
   */
  getCount(): number {
    return this.items.size;
  }
  
  /**
   * Get all item IDs
   */
  getItemIds(): string[] {
    return Array.from(this.items.keys());
  }
}
