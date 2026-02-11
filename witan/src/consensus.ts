/**
 * Witan - Consensus Engine
 * 
 * Multi-agent voting, proposals, and quorum-based decision making.
 * Enables coordinated decisions across distributed AI agent swarms.
 */

import * as crypto from 'crypto';

// =============================================================================
// Types
// =============================================================================

export type ProposalStatus = 'draft' | 'open' | 'passed' | 'rejected' | 'expired' | 'vetoed' | 'executed';
export type VoteChoice = 'approve' | 'reject' | 'abstain';

export interface Proposal {
  id: string;
  thread_id?: string;
  
  // Content
  title: string;
  description: string;
  proposal_type: 'action' | 'policy' | 'resource' | 'emergency' | 'governance';
  payload?: any;
  
  // Proposer
  proposer_id: string;
  proposer_type: 'agent' | 'orchestrator' | 'human';
  
  // Voting config
  voting_config: VotingConfig;
  eligible_voters: string[];
  
  // Status
  status: ProposalStatus;
  created_at: Date;
  voting_starts_at: Date;
  voting_ends_at: Date;
  decided_at?: Date;
  executed_at?: Date;
  
  // Results
  votes: Map<string, Vote>;
  result?: ProposalResult;
  
  // Metadata
  tags: string[];
  metadata: Record<string, any>;
}

export interface VotingConfig {
  quorum: number;           // 0-1, minimum participation required
  threshold: number;        // 0-1, approval threshold
  voting_duration_ms: number;
  allow_abstain: boolean;
  weighted_voting: boolean;
  weights?: Map<string, number>;  // voter_id -> weight
  veto_enabled: boolean;
  veto_holders?: string[];  // IDs that can veto
  require_unanimous?: boolean;
}

export interface Vote {
  voter_id: string;
  choice: VoteChoice;
  weight: number;
  reason?: string;
  voted_at: Date;
  signature: string;
}

export interface ProposalResult {
  decision: 'approved' | 'rejected' | 'no_quorum' | 'vetoed';
  total_votes: number;
  approve_votes: number;
  reject_votes: number;
  abstain_votes: number;
  approve_weight: number;
  reject_weight: number;
  participation_rate: number;
  quorum_met: boolean;
  threshold_met: boolean;
  vetoed_by?: string;
}

export interface ConsensusConfig {
  default_quorum: number;
  default_threshold: number;
  default_voting_duration_ms: number;
  max_open_proposals: number;
  proposal_cooldown_ms: number;
  auto_execute: boolean;
}

export interface ProposalEvent {
  type: 'created' | 'opened' | 'vote_cast' | 'quorum_reached' | 'passed' | 'rejected' | 'expired' | 'vetoed' | 'executed';
  proposal_id: string;
  timestamp: Date;
  details?: Record<string, any>;
}

// =============================================================================
// Consensus Engine
// =============================================================================

export class ConsensusEngine {
  private proposals: Map<string, Proposal> = new Map();
  private proposalsByProposer: Map<string, string[]> = new Map();
  private signingKey: Buffer;
  private config: ConsensusConfig;
  private eventCallbacks: ((event: ProposalEvent) => void)[] = [];
  private expiryTimers: Map<string, NodeJS.Timeout> = new Map();
  
  constructor(signingKey: string, config?: Partial<ConsensusConfig>) {
    this.signingKey = crypto.scryptSync(signingKey, 'witan-consensus', 32);
    this.config = {
      default_quorum: 0.5,
      default_threshold: 0.5,
      default_voting_duration_ms: 300000, // 5 minutes
      max_open_proposals: 100,
      proposal_cooldown_ms: 60000, // 1 minute between proposals
      auto_execute: false,
      ...config,
    };
  }
  
  /**
   * Create a new proposal
   */
  async createProposal(params: {
    title: string;
    description: string;
    proposal_type: Proposal['proposal_type'];
    payload?: any;
    proposer_id: string;
    proposer_type?: Proposal['proposer_type'];
    eligible_voters: string[];
    voting_config?: Partial<VotingConfig>;
    voting_delay_ms?: number;
    thread_id?: string;
    tags?: string[];
    metadata?: Record<string, any>;
  }): Promise<Proposal> {
    // Check open proposal limit
    const openCount = Array.from(this.proposals.values()).filter(p => p.status === 'open').length;
    if (openCount >= this.config.max_open_proposals) {
      throw new Error(`Maximum open proposals (${this.config.max_open_proposals}) reached`);
    }
    
    // Check cooldown
    const proposerProposals = this.proposalsByProposer.get(params.proposer_id) || [];
    if (proposerProposals.length > 0) {
      const lastProposal = this.proposals.get(proposerProposals[proposerProposals.length - 1]);
      if (lastProposal) {
        const timeSince = Date.now() - lastProposal.created_at.getTime();
        if (timeSince < this.config.proposal_cooldown_ms) {
          throw new Error(`Proposal cooldown: wait ${Math.ceil((this.config.proposal_cooldown_ms - timeSince) / 1000)}s`);
        }
      }
    }
    
    const id = `prop_${crypto.randomUUID()}`;
    const now = new Date();
    const votingDelay = params.voting_delay_ms || 0;
    const votingDuration = params.voting_config?.voting_duration_ms || this.config.default_voting_duration_ms;
    
    const votingConfig: VotingConfig = {
      quorum: this.config.default_quorum,
      threshold: this.config.default_threshold,
      voting_duration_ms: votingDuration,
      allow_abstain: true,
      weighted_voting: false,
      veto_enabled: false,
      ...params.voting_config,
    };
    
    const proposal: Proposal = {
      id,
      thread_id: params.thread_id,
      
      title: params.title,
      description: params.description,
      proposal_type: params.proposal_type,
      payload: params.payload,
      
      proposer_id: params.proposer_id,
      proposer_type: params.proposer_type || 'agent',
      
      voting_config: votingConfig,
      eligible_voters: params.eligible_voters,
      
      status: votingDelay > 0 ? 'draft' : 'open',
      created_at: now,
      voting_starts_at: new Date(now.getTime() + votingDelay),
      voting_ends_at: new Date(now.getTime() + votingDelay + votingDuration),
      
      votes: new Map(),
      
      tags: params.tags || [],
      metadata: params.metadata || {},
    };
    
    this.proposals.set(id, proposal);
    
    // Track by proposer
    proposerProposals.push(id);
    this.proposalsByProposer.set(params.proposer_id, proposerProposals);
    
    this.emitEvent({ type: 'created', proposal_id: id, timestamp: now });
    
    // Set up voting start if delayed
    if (votingDelay > 0) {
      setTimeout(() => {
        proposal.status = 'open';
        this.emitEvent({ type: 'opened', proposal_id: id, timestamp: new Date() });
      }, votingDelay);
    }
    
    // Set up expiry timer
    this.setupExpiryTimer(proposal);
    
    return proposal;
  }
  
  /**
   * Cast a vote
   */
  async vote(proposalId: string, voterId: string, choice: VoteChoice, reason?: string): Promise<Vote> {
    const proposal = this.proposals.get(proposalId);
    if (!proposal) throw new Error(`Proposal ${proposalId} not found`);
    
    if (proposal.status !== 'open') {
      throw new Error(`Proposal ${proposalId} is ${proposal.status}, not open for voting`);
    }
    
    if (!proposal.eligible_voters.includes(voterId)) {
      throw new Error(`${voterId} is not eligible to vote on this proposal`);
    }
    
    if (proposal.votes.has(voterId)) {
      throw new Error(`${voterId} has already voted on this proposal`);
    }
    
    if (!proposal.voting_config.allow_abstain && choice === 'abstain') {
      throw new Error('Abstaining is not allowed on this proposal');
    }
    
    const now = new Date();
    if (now < proposal.voting_starts_at) {
      throw new Error('Voting has not started yet');
    }
    if (now > proposal.voting_ends_at) {
      throw new Error('Voting has ended');
    }
    
    // Calculate weight
    let weight = 1;
    if (proposal.voting_config.weighted_voting && proposal.voting_config.weights) {
      weight = proposal.voting_config.weights.get(voterId) || 1;
    }
    
    // Create vote
    const voteData = `${proposalId}:${voterId}:${choice}:${now.toISOString()}`;
    const signature = this.sign(voteData);
    
    const vote: Vote = {
      voter_id: voterId,
      choice,
      weight,
      reason,
      voted_at: now,
      signature,
    };
    
    proposal.votes.set(voterId, vote);
    
    this.emitEvent({
      type: 'vote_cast',
      proposal_id: proposalId,
      timestamp: now,
      details: { voter_id: voterId, choice }
    });
    
    // Check if quorum reached
    const participation = proposal.votes.size / proposal.eligible_voters.length;
    if (participation >= proposal.voting_config.quorum) {
      this.emitEvent({
        type: 'quorum_reached',
        proposal_id: proposalId,
        timestamp: now,
        details: { participation }
      });
    }
    
    // Check if unanimous required and someone rejected
    if (proposal.voting_config.require_unanimous && choice === 'reject') {
      await this.finalizeProposal(proposalId);
    }
    
    // Check if all votes are in
    if (proposal.votes.size === proposal.eligible_voters.length) {
      await this.finalizeProposal(proposalId);
    }
    
    return vote;
  }
  
  /**
   * Veto a proposal
   */
  async veto(proposalId: string, vetoerId: string, reason?: string): Promise<void> {
    const proposal = this.proposals.get(proposalId);
    if (!proposal) throw new Error(`Proposal ${proposalId} not found`);
    
    if (!proposal.voting_config.veto_enabled) {
      throw new Error('Veto is not enabled for this proposal');
    }
    
    if (!proposal.voting_config.veto_holders?.includes(vetoerId)) {
      throw new Error(`${vetoerId} does not have veto power`);
    }
    
    if (proposal.status !== 'open' && proposal.status !== 'passed') {
      throw new Error(`Cannot veto proposal in ${proposal.status} status`);
    }
    
    proposal.status = 'vetoed';
    proposal.decided_at = new Date();
    proposal.result = {
      decision: 'vetoed',
      total_votes: proposal.votes.size,
      approve_votes: 0,
      reject_votes: 0,
      abstain_votes: 0,
      approve_weight: 0,
      reject_weight: 0,
      participation_rate: proposal.votes.size / proposal.eligible_voters.length,
      quorum_met: false,
      threshold_met: false,
      vetoed_by: vetoerId,
    };
    
    this.clearExpiryTimer(proposalId);
    
    this.emitEvent({
      type: 'vetoed',
      proposal_id: proposalId,
      timestamp: new Date(),
      details: { vetoed_by: vetoerId, reason }
    });
  }
  
  /**
   * Finalize a proposal (count votes, determine result)
   */
  async finalizeProposal(proposalId: string): Promise<ProposalResult> {
    const proposal = this.proposals.get(proposalId);
    if (!proposal) throw new Error(`Proposal ${proposalId} not found`);
    
    if (proposal.result) return proposal.result;
    
    // Count votes
    let approveVotes = 0, rejectVotes = 0, abstainVotes = 0;
    let approveWeight = 0, rejectWeight = 0;
    
    for (const vote of proposal.votes.values()) {
      switch (vote.choice) {
        case 'approve':
          approveVotes++;
          approveWeight += vote.weight;
          break;
        case 'reject':
          rejectVotes++;
          rejectWeight += vote.weight;
          break;
        case 'abstain':
          abstainVotes++;
          break;
      }
    }
    
    const totalVotes = proposal.votes.size;
    const participationRate = totalVotes / proposal.eligible_voters.length;
    const quorumMet = participationRate >= proposal.voting_config.quorum;
    
    // Calculate threshold based on non-abstaining votes
    const votingVotes = approveVotes + rejectVotes;
    const totalWeight = approveWeight + rejectWeight;
    const approvalRate = proposal.voting_config.weighted_voting
      ? (totalWeight > 0 ? approveWeight / totalWeight : 0)
      : (votingVotes > 0 ? approveVotes / votingVotes : 0);
    const thresholdMet = approvalRate >= proposal.voting_config.threshold;
    
    // Determine decision
    let decision: ProposalResult['decision'];
    if (!quorumMet) {
      decision = 'no_quorum';
    } else if (proposal.voting_config.require_unanimous && rejectVotes > 0) {
      decision = 'rejected';
    } else if (thresholdMet) {
      decision = 'approved';
    } else {
      decision = 'rejected';
    }
    
    const result: ProposalResult = {
      decision,
      total_votes: totalVotes,
      approve_votes: approveVotes,
      reject_votes: rejectVotes,
      abstain_votes: abstainVotes,
      approve_weight: approveWeight,
      reject_weight: rejectWeight,
      participation_rate: participationRate,
      quorum_met: quorumMet,
      threshold_met: thresholdMet,
    };
    
    proposal.result = result;
    proposal.decided_at = new Date();
    proposal.status = decision === 'approved' ? 'passed' : 
                      decision === 'no_quorum' ? 'expired' : 'rejected';
    
    this.clearExpiryTimer(proposalId);
    
    const eventType = decision === 'approved' ? 'passed' : 
                      decision === 'no_quorum' ? 'expired' : 'rejected';
    this.emitEvent({
      type: eventType,
      proposal_id: proposalId,
      timestamp: new Date(),
      details: result
    });
    
    // Auto-execute if enabled
    if (decision === 'approved' && this.config.auto_execute) {
      await this.executeProposal(proposalId);
    }
    
    return result;
  }
  
  /**
   * Execute a passed proposal
   */
  async executeProposal(proposalId: string): Promise<void> {
    const proposal = this.proposals.get(proposalId);
    if (!proposal) throw new Error(`Proposal ${proposalId} not found`);
    
    if (proposal.status !== 'passed') {
      throw new Error(`Cannot execute proposal in ${proposal.status} status`);
    }
    
    proposal.status = 'executed';
    proposal.executed_at = new Date();
    
    this.emitEvent({
      type: 'executed',
      proposal_id: proposalId,
      timestamp: new Date(),
      details: { payload: proposal.payload }
    });
  }
  
  /**
   * Get proposal by ID
   */
  getProposal(proposalId: string): Proposal | undefined {
    return this.proposals.get(proposalId);
  }
  
  /**
   * Get proposals by status
   */
  getProposalsByStatus(status: ProposalStatus): Proposal[] {
    return Array.from(this.proposals.values()).filter(p => p.status === status);
  }
  
  /**
   * Get proposals for a voter
   */
  getProposalsForVoter(voterId: string, onlyOpen: boolean = true): Proposal[] {
    return Array.from(this.proposals.values()).filter(p => {
      if (onlyOpen && p.status !== 'open') return false;
      return p.eligible_voters.includes(voterId) && !p.votes.has(voterId);
    });
  }
  
  /**
   * Get voting power for an agent
   */
  getVotingPower(proposalId: string, voterId: string): number {
    const proposal = this.proposals.get(proposalId);
    if (!proposal) return 0;
    
    if (!proposal.eligible_voters.includes(voterId)) return 0;
    
    if (proposal.voting_config.weighted_voting && proposal.voting_config.weights) {
      return proposal.voting_config.weights.get(voterId) || 1;
    }
    
    return 1;
  }
  
  /**
   * Subscribe to events
   */
  onEvent(callback: (event: ProposalEvent) => void): () => void {
    this.eventCallbacks.push(callback);
    return () => {
      const index = this.eventCallbacks.indexOf(callback);
      if (index !== -1) this.eventCallbacks.splice(index, 1);
    };
  }
  
  /**
   * Get statistics
   */
  getStats(): {
    total_proposals: number;
    by_status: Record<ProposalStatus, number>;
    avg_participation: number;
    approval_rate: number;
  } {
    const proposals = Array.from(this.proposals.values());
    
    const byStatus: Record<ProposalStatus, number> = {
      draft: 0, open: 0, passed: 0, rejected: 0, expired: 0, vetoed: 0, executed: 0
    };
    
    let totalParticipation = 0;
    let decidedCount = 0;
    let approvedCount = 0;
    
    for (const p of proposals) {
      byStatus[p.status]++;
      
      if (p.result) {
        totalParticipation += p.result.participation_rate;
        decidedCount++;
        if (p.result.decision === 'approved') approvedCount++;
      }
    }
    
    return {
      total_proposals: proposals.length,
      by_status: byStatus,
      avg_participation: decidedCount > 0 ? totalParticipation / decidedCount : 0,
      approval_rate: decidedCount > 0 ? approvedCount / decidedCount : 0,
    };
  }
  
  // ===========================================================================
  // Private Methods
  // ===========================================================================
  
  private sign(data: string): string {
    const hmac = crypto.createHmac('sha256', this.signingKey);
    hmac.update(data);
    return hmac.digest('hex');
  }
  
  private emitEvent(event: ProposalEvent): void {
    for (const cb of this.eventCallbacks) {
      try {
        cb(event);
      } catch (e) {
        // Ignore
      }
    }
  }
  
  private setupExpiryTimer(proposal: Proposal): void {
    const timeUntilExpiry = proposal.voting_ends_at.getTime() - Date.now();
    
    if (timeUntilExpiry > 0) {
      const timer = setTimeout(async () => {
        if (proposal.status === 'open') {
          await this.finalizeProposal(proposal.id);
        }
      }, timeUntilExpiry);
      
      this.expiryTimers.set(proposal.id, timer);
    }
  }
  
  private clearExpiryTimer(proposalId: string): void {
    const timer = this.expiryTimers.get(proposalId);
    if (timer) {
      clearTimeout(timer);
      this.expiryTimers.delete(proposalId);
    }
  }
}

export default ConsensusEngine;
