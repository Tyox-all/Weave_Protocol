/**
 * Dōmere - The Judge Protocol
 * Solana Anchoring Client
 * 
 * Note: This is the client interface. The actual Solana program
 * should be deployed separately using Anchor framework.
 */

import type { 
  AnchorRequest, 
  AnchorResult, 
  AnchorVerification,
  BlockchainNetwork 
} from '../types.js';
import { createHash } from 'node:crypto';
import { sha256 } from '@noble/hashes/sha2.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { base58 } from '@scure/base';
import { AnchoringError } from '../types.js';
import { DEFAULT_CONFIG, PROTOCOL_FEES } from '../constants.js';

// ============================================================================
// Solana Client Interface
// ============================================================================

export interface SolanaConfig {
  rpc_url: string;
  program_id: string;
  treasury?: string;
}

export interface SolanaAnchorData {
  thread_id: number[];      // [u8; 32]
  merkle_root: number[];    // [u8; 32]
  hop_count: number;        // u64
  intent_hash: number[];    // [u8; 32]
  compliant: boolean;
}

// ============================================================================
// Solana Anchoring Client
// ============================================================================

export class SolanaAnchorClient {
  private config: SolanaConfig;
  private isDevnet: boolean;
  
  constructor(config?: Partial<SolanaConfig>) {
    this.config = {
      rpc_url: config?.rpc_url ?? DEFAULT_CONFIG.anchoring.solana_rpc,
      program_id: config?.program_id ?? DEFAULT_CONFIG.anchoring.solana_program_id,
      treasury: config?.treasury ?? DEFAULT_CONFIG.anchoring.solana_treasury,
    };
    this.isDevnet = this.config.rpc_url.includes('devnet');
  }
  
  /**
   * Prepare anchor data for Solana
   */
  prepareAnchorData(request: AnchorRequest): SolanaAnchorData {
    return {
      thread_id: this.stringToBytes32(request.thread_id),
      merkle_root: this.hexToBytes32(request.merkle_root),
      hop_count: request.hop_count,
      intent_hash: this.hexToBytes32(request.intent_hash),
      compliant: request.compliant,
    };
  }
  
  /**
   * Estimate transaction cost
   */
  async estimateCost(): Promise<{
    network_fee_lamports: number;
    network_fee_sol: string;
    protocol_fee_lamports: number;
    protocol_fee_sol: string;
    total_lamports: number;
    total_sol: string;
  }> {
    // Base transaction fee on Solana is ~5000 lamports
    // Account rent for storing anchor data is ~2039280 lamports (for first anchor)
    // We assume account already exists for subsequent anchors
    
    const baseFee = 5000;  // lamports
    const protocolFee = PROTOCOL_FEES.solana.base_lamports;
    const total = baseFee + protocolFee;
    
    return {
      network_fee_lamports: baseFee,
      network_fee_sol: (baseFee / 1_000_000_000).toFixed(9),
      protocol_fee_lamports: protocolFee,
      protocol_fee_sol: (protocolFee / 1_000_000_000).toFixed(9),
      total_lamports: total,
      total_sol: (total / 1_000_000_000).toFixed(9),
    };
  }
  
  /**
   * Anchor thread to Solana
   * 
   * Note: This returns the transaction data needed for signing.
   * Actual signing must be done client-side with the user's wallet.
   */
  async createAnchorTransaction(request: AnchorRequest): Promise<{
    unsigned_transaction: null;
    message: string;
    instructions: SolanaInstruction[];
    estimated_cost: any;
  }> {
    const data = this.prepareAnchorData(request);
    const cost = await this.estimateCost();
    const [pda] = this.findThreadAnchorPda(data.thread_id);

    // Anchor instruction data: 8-byte discriminator, then Borsh-encoded args
    // (thread_id [u8;32], merkle_root [u8;32], hop_count u64 LE, intent_hash [u8;32], compliant bool).
    const hopCount = Buffer.alloc(8);
    hopCount.writeBigUInt64LE(BigInt(data.hop_count));
    const ixData = Buffer.concat([
      Buffer.from(anchorDiscriminator('anchor_thread')),
      Buffer.from(data.thread_id),
      Buffer.from(data.merkle_root),
      hopCount,
      Buffer.from(data.intent_hash),
      Buffer.from([data.compliant ? 1 : 0]),
    ]);

    const instruction: SolanaInstruction = {
      program_id: this.config.program_id,
      accounts: [
        { pubkey: '<payer: your wallet>', isSigner: true, isWritable: true },
        { pubkey: pda, isSigner: false, isWritable: true },
        { pubkey: this.config.treasury ?? DEFAULT_CONFIG.anchoring.solana_treasury, isSigner: false, isWritable: true },
        { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
      ],
      data_base64: ixData.toString('base64'),
    };

    return {
      // Building the transaction needs a recent blockhash from an RPC node, which
      // Dōmere does not contact: add this instruction with your wallet/client.
      unsigned_transaction: null,
      message: `Anchor thread ${request.thread_id} to Solana: add this instruction to a transaction, then sign and send it with your wallet.`,
      instructions: [instruction],
      estimated_cost: cost,
    };
  }
  
  /**
   * Submit signed transaction
   * 
   * Note: In production, this would use @solana/web3.js to submit
   * the signed transaction to the network.
   */
  async submitSignedTransaction(_signedTransaction: string): Promise<AnchorResult> {
    throw new AnchoringError('Dōmere prepares anchors but does not broadcast or read blockchains. Sign and submit the prepared transaction with your own wallet/RPC client, then verify it there.');
  }
  
  /**
   * Verify an anchor on-chain (not implemented: Dōmere does not read chains)
   */
  async verifyAnchor(_threadId: string, _expectedMerkleRoot: string): Promise<AnchorVerification> {
    throw new AnchoringError('Dōmere prepares anchors but does not broadcast or read blockchains. Sign and submit the prepared transaction with your own wallet/RPC client, then verify it there.');
  }
  
  /**
   * Get explorer URL for transaction
   */
  getExplorerUrl(signature: string): string {
    const cluster = this.isDevnet ? '?cluster=devnet' : '';
    return `https://solscan.io/tx/${signature}${cluster}`;
  }
  
  /**
   * Get program address
   */
  getProgramId(): string {
    return this.config.program_id;
  }
  
  /**
   * Derive PDA for thread anchor
   */
  deriveThreadAnchorPda(threadId: string): string {
    return this.findThreadAnchorPda(this.stringToBytes32(threadId))[0];
  }

  /** PDA for seeds ["thread_anchor", thread_id], as the program derives it. */
  findThreadAnchorPda(threadIdBytes: number[]): [string, number] {
    return findProgramAddress([new TextEncoder().encode('thread_anchor'), Uint8Array.from(threadIdBytes)], this.config.program_id);
  }
  
  // ============================================================================
  // Utility Methods
  // ============================================================================
  
  /**
   * Convert string to 32-byte array
   */
  private stringToBytes32(str: string): number[] {
    const hash = createHash('sha256').update(str).digest();
    return Array.from(hash);
  }
  
  /**
   * Convert hex string to 32-byte array
   */
  private hexToBytes32(hex: string): number[] {
    // Remove 0x prefix if present
    const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
    
    // Pad to 64 characters (32 bytes)
    const padded = cleanHex.padStart(64, '0');
    
    const bytes: number[] = [];
    for (let i = 0; i < 64; i += 2) {
      bytes.push(parseInt(padded.slice(i, i + 2), 16));
    }
    
    return bytes;
  }
}

// ============================================================================
// Solana Program IDL (for reference)
// ============================================================================

// ============================================================================
// Solana helpers (no @solana/web3.js dependency)
// ============================================================================

export interface SolanaInstruction {
  program_id: string;
  accounts: { pubkey: string; isSigner: boolean; isWritable: boolean }[];
  data_base64: string;
}

export const SYSTEM_PROGRAM_ID = '11111111111111111111111111111111';

/** Anchor's instruction discriminator: first 8 bytes of sha256("global:<name>"). */
export function anchorDiscriminator(name: string): Uint8Array {
  return sha256(new TextEncoder().encode(`global:${name}`)).slice(0, 8);
}

function isOnCurve(bytes: Uint8Array): boolean {
  try {
    ed25519.Point.fromBytes(bytes);
    return true;
  } catch {
    return false;
  }
}

/**
 * Same as @solana/web3.js PublicKey.findProgramAddressSync: the first bump
 * (255 down) whose sha256(seeds, bump, programId, "ProgramDerivedAddress")
 * is off the ed25519 curve.
 */
export function findProgramAddress(seeds: Uint8Array[], programId: string): [string, number] {
  const program = base58.decode(programId);
  const marker = new TextEncoder().encode('ProgramDerivedAddress');
  for (let bump = 255; bump >= 0; bump--) {
    const parts = [...seeds, Uint8Array.of(bump), program, marker];
    const buf = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) { buf.set(p, o); o += p.length; }
    const hash = sha256(buf);
    if (!isOnCurve(hash)) return [base58.encode(hash), bump];
  }
  throw new AnchoringError('Unable to find a viable program address bump seed');
}

export const SOLANA_PROGRAM_IDL = `
// Anchor program for Dōmere anchoring
// Deploy using: anchor build && anchor deploy

use anchor_lang::prelude::*;

declare_id!("WeaveXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");

#[program]
pub mod domere_anchor {
    use super::*;
    
    pub const PROTOCOL_FEE: u64 = 100_000; // 0.0001 SOL
    
    pub fn anchor_thread(
        ctx: Context<AnchorThread>,
        thread_id: [u8; 32],
        merkle_root: [u8; 32],
        hop_count: u64,
        intent_hash: [u8; 32],
        compliant: bool,
    ) -> Result<()> {
        let anchor = &mut ctx.accounts.thread_anchor;
        
        anchor.thread_id = thread_id;
        anchor.merkle_root = merkle_root;
        anchor.hop_count = hop_count;
        anchor.intent_hash = intent_hash;
        anchor.compliant = compliant;
        anchor.timestamp = Clock::get()?.unix_timestamp;
        anchor.anchorer = ctx.accounts.payer.key();
        
        // Transfer protocol fee to treasury
        let cpi_context = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: ctx.accounts.payer.to_account_info(),
                to: ctx.accounts.treasury.to_account_info(),
            },
        );
        anchor_lang::system_program::transfer(cpi_context, PROTOCOL_FEE)?;
        
        emit!(ThreadAnchored {
            thread_id,
            merkle_root,
            anchorer: ctx.accounts.payer.key(),
            timestamp: anchor.timestamp,
        });
        
        Ok(())
    }
    
    pub fn verify_anchor(
        ctx: Context<VerifyAnchor>,
        thread_id: [u8; 32],
        expected_merkle_root: [u8; 32],
    ) -> Result<bool> {
        let anchor = &ctx.accounts.thread_anchor;
        
        Ok(anchor.thread_id == thread_id && 
           anchor.merkle_root == expected_merkle_root)
    }
}

#[derive(Accounts)]
#[instruction(thread_id: [u8; 32])]
pub struct AnchorThread<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    
    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + ThreadAnchor::INIT_SPACE,
        seeds = [b"thread_anchor", thread_id.as_ref()],
        bump
    )]
    pub thread_anchor: Account<'info, ThreadAnchor>,
    
    /// CHECK: Treasury account for protocol fees
    #[account(mut)]
    pub treasury: AccountInfo<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(thread_id: [u8; 32])]
pub struct VerifyAnchor<'info> {
    #[account(
        seeds = [b"thread_anchor", thread_id.as_ref()],
        bump
    )]
    pub thread_anchor: Account<'info, ThreadAnchor>,
}

#[account]
#[derive(InitSpace)]
pub struct ThreadAnchor {
    pub thread_id: [u8; 32],
    pub merkle_root: [u8; 32],
    pub hop_count: u64,
    pub intent_hash: [u8; 32],
    pub compliant: bool,
    pub timestamp: i64,
    pub anchorer: Pubkey,
}

#[event]
pub struct ThreadAnchored {
    pub thread_id: [u8; 32],
    pub merkle_root: [u8; 32],
    pub anchorer: Pubkey,
    pub timestamp: i64,
}
`;
