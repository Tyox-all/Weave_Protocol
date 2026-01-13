// Weave Protocol - Solana Program
// Thread anchoring for AI agent verification

use anchor_lang::prelude::*;

declare_id!("WeaveXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");

// Protocol fee: 0.0001 SOL
pub const PROTOCOL_FEE_LAMPORTS: u64 = 100_000;

#[program]
pub mod weave_protocol {
    use super::*;

    /// Anchor a thread to Solana
    pub fn anchor_thread(
        ctx: Context<AnchorThread>,
        thread_id: [u8; 32],
        merkle_root: [u8; 32],
        hop_count: u64,
        intent_hash: [u8; 32],
        compliant: bool,
    ) -> Result<()> {
        let anchor = &mut ctx.accounts.thread_anchor;
        let clock = Clock::get()?;

        // Set anchor data
        anchor.thread_id = thread_id;
        anchor.merkle_root = merkle_root;
        anchor.hop_count = hop_count;
        anchor.intent_hash = intent_hash;
        anchor.compliant = compliant;
        anchor.timestamp = clock.unix_timestamp;
        anchor.anchorer = ctx.accounts.payer.key();
        anchor.bump = ctx.bumps.thread_anchor;

        // Transfer protocol fee to treasury
        let cpi_context = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: ctx.accounts.payer.to_account_info(),
                to: ctx.accounts.treasury.to_account_info(),
            },
        );
        anchor_lang::system_program::transfer(cpi_context, PROTOCOL_FEE_LAMPORTS)?;

        emit!(ThreadAnchored {
            thread_id,
            merkle_root,
            hop_count,
            intent_hash,
            compliant,
            timestamp: clock.unix_timestamp,
            anchorer: ctx.accounts.payer.key(),
        });

        Ok(())
    }

    /// Anchor a batch of threads (merkle root of multiple threads)
    pub fn anchor_batch(
        ctx: Context<AnchorBatch>,
        batch_id: [u8; 32],
        merkle_root: [u8; 32],
        thread_count: u64,
    ) -> Result<()> {
        let batch = &mut ctx.accounts.batch_anchor;
        let clock = Clock::get()?;

        batch.batch_id = batch_id;
        batch.merkle_root = merkle_root;
        batch.thread_count = thread_count;
        batch.timestamp = clock.unix_timestamp;
        batch.anchorer = ctx.accounts.payer.key();
        batch.bump = ctx.bumps.batch_anchor;

        // Transfer protocol fee (discounted for batches)
        let fee = PROTOCOL_FEE_LAMPORTS / 2; // 50% discount for batches
        let cpi_context = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: ctx.accounts.payer.to_account_info(),
                to: ctx.accounts.treasury.to_account_info(),
            },
        );
        anchor_lang::system_program::transfer(cpi_context, fee)?;

        emit!(BatchAnchored {
            batch_id,
            merkle_root,
            thread_count,
            timestamp: clock.unix_timestamp,
            anchorer: ctx.accounts.payer.key(),
        });

        Ok(())
    }

    /// Record a violation (for audit trail)
    pub fn record_violation(
        ctx: Context<RecordViolation>,
        thread_id: [u8; 32],
        violation_type: u8,
        severity: u8,
        description_hash: [u8; 32],
    ) -> Result<()> {
        let violation = &mut ctx.accounts.violation;
        let clock = Clock::get()?;

        violation.thread_id = thread_id;
        violation.violation_type = violation_type;
        violation.severity = severity;
        violation.description_hash = description_hash;
        violation.timestamp = clock.unix_timestamp;
        violation.reporter = ctx.accounts.payer.key();
        violation.resolved = false;
        violation.bump = ctx.bumps.violation;

        emit!(ViolationRecorded {
            thread_id,
            violation_type,
            severity,
            timestamp: clock.unix_timestamp,
            reporter: ctx.accounts.payer.key(),
        });

        Ok(())
    }

    /// Mark violation as resolved
    pub fn resolve_violation(
        ctx: Context<ResolveViolation>,
        resolution_hash: [u8; 32],
    ) -> Result<()> {
        let violation = &mut ctx.accounts.violation;
        let clock = Clock::get()?;

        violation.resolved = true;
        violation.resolution_hash = Some(resolution_hash);
        violation.resolved_at = Some(clock.unix_timestamp);
        violation.resolver = Some(ctx.accounts.resolver.key());

        emit!(ViolationResolved {
            thread_id: violation.thread_id,
            resolution_hash,
            timestamp: clock.unix_timestamp,
            resolver: ctx.accounts.resolver.key(),
        });

        Ok(())
    }
}

// ============================================================================
// Accounts
// ============================================================================

#[derive(Accounts)]
#[instruction(thread_id: [u8; 32])]
pub struct AnchorThread<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + ThreadAnchor::INIT_SPACE,
        seeds = [b"thread", thread_id.as_ref()],
        bump
    )]
    pub thread_anchor: Account<'info, ThreadAnchor>,
    
    #[account(mut)]
    pub payer: Signer<'info>,
    
    /// CHECK: Treasury account for protocol fees
    #[account(mut)]
    pub treasury: AccountInfo<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(batch_id: [u8; 32])]
pub struct AnchorBatch<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + BatchAnchor::INIT_SPACE,
        seeds = [b"batch", batch_id.as_ref()],
        bump
    )]
    pub batch_anchor: Account<'info, BatchAnchor>,
    
    #[account(mut)]
    pub payer: Signer<'info>,
    
    /// CHECK: Treasury account for protocol fees
    #[account(mut)]
    pub treasury: AccountInfo<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(thread_id: [u8; 32])]
pub struct RecordViolation<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + Violation::INIT_SPACE,
        seeds = [b"violation", thread_id.as_ref(), &[violation_count(thread_id)]],
        bump
    )]
    pub violation: Account<'info, Violation>,
    
    #[account(mut)]
    pub payer: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ResolveViolation<'info> {
    #[account(mut)]
    pub violation: Account<'info, Violation>,
    
    pub resolver: Signer<'info>,
}

// ============================================================================
// State
// ============================================================================

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
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct BatchAnchor {
    pub batch_id: [u8; 32],
    pub merkle_root: [u8; 32],
    pub thread_count: u64,
    pub timestamp: i64,
    pub anchorer: Pubkey,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct Violation {
    pub thread_id: [u8; 32],
    pub violation_type: u8,
    pub severity: u8,
    pub description_hash: [u8; 32],
    pub timestamp: i64,
    pub reporter: Pubkey,
    pub resolved: bool,
    pub resolution_hash: Option<[u8; 32]>,
    pub resolved_at: Option<i64>,
    pub resolver: Option<Pubkey>,
    pub bump: u8,
}

// ============================================================================
// Events
// ============================================================================

#[event]
pub struct ThreadAnchored {
    pub thread_id: [u8; 32],
    pub merkle_root: [u8; 32],
    pub hop_count: u64,
    pub intent_hash: [u8; 32],
    pub compliant: bool,
    pub timestamp: i64,
    pub anchorer: Pubkey,
}

#[event]
pub struct BatchAnchored {
    pub batch_id: [u8; 32],
    pub merkle_root: [u8; 32],
    pub thread_count: u64,
    pub timestamp: i64,
    pub anchorer: Pubkey,
}

#[event]
pub struct ViolationRecorded {
    pub thread_id: [u8; 32],
    pub violation_type: u8,
    pub severity: u8,
    pub timestamp: i64,
    pub reporter: Pubkey,
}

#[event]
pub struct ViolationResolved {
    pub thread_id: [u8; 32],
    pub resolution_hash: [u8; 32],
    pub timestamp: i64,
    pub resolver: Pubkey,
}

// ============================================================================
// Helpers
// ============================================================================

fn violation_count(_thread_id: [u8; 32]) -> u8 {
    // In production, this would query existing violations
    // For now, return 0 (first violation)
    0
}
