/**
 * Dōmere - The Judge Protocol
 * Anchoring Module
 */

export { MerkleTree, BatchAnchor } from './merkle.js';
export { SolanaAnchorClient, SOLANA_PROGRAM_IDL } from './solana.js';
export { EthereumAnchorClient, ETHEREUM_CONTRACT_ABI, ETHEREUM_CONTRACT_SOURCE } from './ethereum.js';

import type { 
  AnchorRequest, 
  AnchorResult, 
  AnchorVerification, 
  BlockchainNetwork,
  Thread,
} from '../types.js';
import { AnchoringError } from '../types.js';
import { SolanaAnchorClient } from './solana.js';
import { EthereumAnchorClient } from './ethereum.js';
import { MerkleTree, BatchAnchor } from './merkle.js';

// ============================================================================
// Unified Anchoring Service
// ============================================================================

export class AnchoringService {
  private solana: SolanaAnchorClient;
  private ethereum: EthereumAnchorClient;
  private pendingBatch: BatchAnchor | null = null;
  
  constructor(config?: {
    solana?: { rpc_url?: string; program_id?: string };
    ethereum?: { rpc_url?: string; contract_address?: string };
  }) {
    this.solana = new SolanaAnchorClient(config?.solana);
    this.ethereum = new EthereumAnchorClient(config?.ethereum);
  }
  
  /**
   * Prepare thread for anchoring
   */
  prepareThreadAnchor(thread: Thread): AnchorRequest {
    // Build Merkle tree from hop signatures
    const hopSignatures = thread.hops.map(hop => hop.hop_signature);
    const tree = new MerkleTree(hopSignatures.length > 0 ? hopSignatures : ['empty']);
    
    return {
      thread_id: thread.id,
      merkle_root: tree.getRootHex(),
      hop_count: thread.hops.length,
      intent_hash: thread.intent.hash,
      compliant: thread.status !== 'violated',
      network: 'solana',  // Default to Solana
    };
  }
  
  /**
   * Estimate anchoring cost
   */
  async estimateCost(network: BlockchainNetwork): Promise<{
    network: BlockchainNetwork;
    network_fee: string;
    protocol_fee: string;
    total: string;
    currency: string;
  }> {
    if (network === 'solana' || network === 'solana-devnet') {
      const cost = await this.solana.estimateCost();
      return {
        network,
        network_fee: cost.network_fee_sol,
        protocol_fee: cost.protocol_fee_sol,
        total: cost.total_sol,
        currency: 'SOL',
      };
    } else {
      const cost = await this.ethereum.estimateGas();
      return {
        network,
        network_fee: cost.estimated_eth,
        protocol_fee: cost.protocol_fee_eth,
        total: cost.total_eth,
        currency: 'ETH',
      };
    }
  }
  
  /**
   * Create anchor transaction (unsigned)
   */
  async createAnchorTransaction(request: AnchorRequest): Promise<{
    network: BlockchainNetwork;
    transaction_data: unknown;
    estimated_cost: unknown;
    instructions: string;
  }> {
    if (request.network === 'solana' || request.network === 'solana-devnet') {
      const tx = await this.solana.createAnchorTransaction(request);
      return {
        network: request.network,
        transaction_data: tx.unsigned_transaction,
        estimated_cost: tx.estimated_cost,
        instructions: `Sign this transaction with your Solana wallet to anchor thread ${request.thread_id}`,
      };
    } else {
      const tx = await this.ethereum.createAnchorTransaction(request);
      return {
        network: request.network,
        transaction_data: tx,
        estimated_cost: tx.estimated_cost,
        instructions: `Sign this transaction with your Ethereum wallet to anchor thread ${request.thread_id}`,
      };
    }
  }
  
  /**
   * Submit signed transaction
   */
  async submitSignedTransaction(
    network: BlockchainNetwork,
    signedTransaction: string
  ): Promise<AnchorResult> {
    if (network === 'solana' || network === 'solana-devnet') {
      return this.solana.submitSignedTransaction(signedTransaction);
    } else {
      return this.ethereum.submitSignedTransaction(signedTransaction);
    }
  }
  
  /**
   * Verify anchor on-chain
   */
  async verifyAnchor(
    network: BlockchainNetwork,
    threadId: string,
    expectedMerkleRoot: string
  ): Promise<AnchorVerification> {
    if (network === 'solana' || network === 'solana-devnet') {
      return this.solana.verifyAnchor(threadId, expectedMerkleRoot);
    } else {
      return this.ethereum.verifyAnchor(threadId, expectedMerkleRoot);
    }
  }
  
  /**
   * Start a batch for efficient anchoring
   */
  startBatch(): void {
    if (this.pendingBatch) {
      throw new AnchoringError('Batch already in progress');
    }
    this.pendingBatch = new BatchAnchor();
  }
  
  /**
   * Add thread to batch
   */
  addToBatch(thread: Thread): void {
    if (!this.pendingBatch) {
      throw new AnchoringError('No batch in progress');
    }
    
    const hopSignatures = thread.hops.map(hop => hop.hop_signature);
    const tree = new MerkleTree(hopSignatures.length > 0 ? hopSignatures : ['empty']);
    
    this.pendingBatch.add(thread.id, JSON.stringify({
      thread_id: thread.id,
      merkle_root: tree.getRootHex(),
      intent_hash: thread.intent.hash,
      compliant: thread.status !== 'violated',
    }));
  }
  
  /**
   * Finalize batch and get root
   */
  finalizeBatch(): {
    root: string;
    count: number;
    thread_ids: string[];
  } {
    if (!this.pendingBatch) {
      throw new AnchoringError('No batch in progress');
    }
    
    const root = this.pendingBatch.finalize();
    const threadIds = this.pendingBatch.getItemIds();
    const count = this.pendingBatch.getCount();
    
    return { root, count, thread_ids: threadIds };
  }
  
  /**
   * Get proof for specific thread in batch
   */
  getBatchProof(threadId: string): {
    proof: string[];
    positions: number[];
    root: string;
  } | null {
    if (!this.pendingBatch) {
      throw new AnchoringError('No batch in progress');
    }
    
    return this.pendingBatch.getProof(threadId);
  }
  
  /**
   * Clear batch
   */
  clearBatch(): void {
    this.pendingBatch = null;
  }
  
  /**
   * Get explorer URL for transaction
   */
  getExplorerUrl(network: BlockchainNetwork, txHash: string): string {
    if (network === 'solana' || network === 'solana-devnet') {
      return this.solana.getExplorerUrl(txHash);
    } else {
      return this.ethereum.getExplorerUrl(txHash);
    }
  }
  
  /**
   * Get client for direct access
   */
  getClient(network: BlockchainNetwork): SolanaAnchorClient | EthereumAnchorClient {
    if (network === 'solana' || network === 'solana-devnet') {
      return this.solana;
    } else {
      return this.ethereum;
    }
  }
}
