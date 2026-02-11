/**
 * Witan - Council Protocol
 * 
 * Multi-agent consensus, communication, governance, and recovery
 * for AI orchestration systems. Built on Dōmere primitives.
 */

// Export all components
export * from './consensus.js';
export * from './bus.js';
export * from './policy.js';
export * from './recovery.js';

import { ConsensusEngine, Proposal, ProposalEvent } from './consensus.js';
import { CommunicationBus, Message, Channel, BusEvent } from './bus.js';
import { PolicyEngine, Policy, EnforcementDecision, EvaluationContext } from './policy.js';
import { RecoveryManager, Checkpoint, Transaction, RecoveryEvent } from './recovery.js';

// Import Dōmere components
import { 
  Orchestrator, 
  TaskScheduler, 
  AgentRegistry, 
  StateManager 
} from '@weave_protocol/domere';

// =============================================================================
// Types
// =============================================================================

export interface WitanConfig {
  // Signing keys
  signing_key: string;
  
  // Orchestration
  max_agents?: number;
  
  // Consensus
  default_quorum?: number;
  default_threshold?: number;
  default_voting_duration_ms?: number;
  
  // Communication
  default_message_ttl_ms?: number;
  max_pending_messages?: number;
  
  // Policy
  enable_rate_limiting?: boolean;
  enable_quota_enforcement?: boolean;
  
  // Recovery
  auto_checkpoint_interval_ms?: number;
  max_checkpoints?: number;
  enable_auto_recovery?: boolean;
}

export interface WitanStats {
  orchestration: {
    agents: number;
    agents_ready: number;
    tasks_queued: number;
    tasks_running: number;
  };
  consensus: {
    proposals_open: number;
    proposals_total: number;
    avg_participation: number;
  };
  communication: {
    messages_pending: number;
    channels: number;
    agents_connected: number;
  };
  policy: {
    policies_active: number;
    violations_last_hour: number;
  };
  recovery: {
    checkpoints: number;
    active_transactions: number;
  };
}

export interface WitanEvent {
  source: 'consensus' | 'bus' | 'policy' | 'recovery' | 'orchestrator';
  event: ProposalEvent | BusEvent | RecoveryEvent | any;
  timestamp: Date;
}

// =============================================================================
// Witan Council
// =============================================================================

/**
 * Witan Council - Unified multi-agent coordination
 * 
 * Combines Dōmere orchestration primitives with:
 * - Consensus: Voting and proposals
 * - Communication: Agent-to-agent messaging
 * - Policy: Governance and rate limits
 * - Recovery: Checkpoints and rollback
 */
export class WitanCouncil {
  // Dōmere components
  public readonly orchestrator: Orchestrator;
  public readonly scheduler: TaskScheduler;
  public readonly registry: AgentRegistry;
  public readonly state: StateManager;
  
  // Witan components
  public readonly consensus: ConsensusEngine;
  public readonly bus: CommunicationBus;
  public readonly policy: PolicyEngine;
  public readonly recovery: RecoveryManager;
  
  private config: WitanConfig;
  private eventCallbacks: ((event: WitanEvent) => void)[] = [];
  private running: boolean = false;
  
  constructor(config: WitanConfig) {
    this.config = config;
    
    // Initialize Dōmere orchestrator
    this.orchestrator = new Orchestrator({
      max_agents: config.max_agents || 10,
      auto_reassign_on_failure: true,
    });
    
    // Get references to internal components
    this.scheduler = this.orchestrator.scheduler;
    this.registry = this.orchestrator.registry;
    this.state = this.orchestrator.state;
    
    // Initialize Witan components
    this.consensus = new ConsensusEngine(config.signing_key, {
      default_quorum: config.default_quorum,
      default_threshold: config.default_threshold,
      default_voting_duration_ms: config.default_voting_duration_ms,
    });
    
    this.bus = new CommunicationBus(config.signing_key, {
      default_ttl_ms: config.default_message_ttl_ms,
      max_pending_messages: config.max_pending_messages,
    });
    
    this.policy = new PolicyEngine();
    
    this.recovery = new RecoveryManager(config.signing_key, {
      auto_checkpoint_interval_ms: config.auto_checkpoint_interval_ms,
      max_checkpoints: config.max_checkpoints,
      enable_auto_recovery: config.enable_auto_recovery,
    });
    
    // Wire up event handlers
    this.setupEventHandlers();
    this.setupRecoveryAccessors();
  }
  
  // ===========================================================================
  // Lifecycle
  // ===========================================================================
  
  /**
   * Start the council
   */
  async start(): Promise<void> {
    await this.orchestrator.start();
    this.running = true;
    
    // Create initial checkpoint
    await this.recovery.checkpoint({
      name: 'Startup checkpoint',
      created_by: 'system',
      tags: ['startup'],
    });
    
    console.log('[Witan] Council started');
  }
  
  /**
   * Stop the council
   */
  async stop(): Promise<void> {
    // Create final checkpoint
    await this.recovery.checkpoint({
      name: 'Shutdown checkpoint',
      created_by: 'system',
      tags: ['shutdown'],
    });
    
    await this.orchestrator.stop();
    this.running = false;
    
    console.log('[Witan] Council stopped');
  }
  
  // ===========================================================================
  // Agent Management (Enhanced)
  // ===========================================================================
  
  /**
   * Register an agent with the council
   */
  async registerAgent(params: {
    id?: string;
    name?: string;
    capabilities: string[];
    max_concurrent_tasks?: number;
    voting_weight?: number;
  }): Promise<string> {
    // Register with orchestrator
    const agent = await this.orchestrator.registerAgent({
      id: params.id,
      name: params.name,
      capabilities: params.capabilities,
      max_concurrent_tasks: params.max_concurrent_tasks,
    });
    
    // Register with communication bus
    await this.bus.registerAgent(agent.id);
    
    // Store voting weight in state if provided
    if (params.voting_weight) {
      await this.state.set(`voting_weight:${agent.id}`, params.voting_weight, {
        agent_id: 'system',
      });
    }
    
    return agent.id;
  }
  
  /**
   * Unregister an agent
   */
  async unregisterAgent(agentId: string): Promise<void> {
    await this.bus.unregisterAgent(agentId);
    await this.registry.deregister(agentId, true);
    await this.state.releaseAllLocks(agentId);
  }
  
  // ===========================================================================
  // Consensus Operations
  // ===========================================================================
  
  /**
   * Propose an action for council vote
   */
  async propose(params: {
    title: string;
    description: string;
    type: Proposal['proposal_type'];
    payload?: any;
    proposer_id: string;
    voters?: string[];  // If not provided, all registered agents
    voting_config?: {
      quorum?: number;
      threshold?: number;
      duration_ms?: number;
      require_unanimous?: boolean;
    };
  }): Promise<Proposal> {
    // Get voters
    let voters = params.voters;
    if (!voters) {
      const agents = this.registry.getAllAgents();
      voters = agents.map(a => a.id);
    }
    
    // Get voting weights
    const weights = new Map<string, number>();
    for (const voterId of voters) {
      const weight = await this.state.get(`voting_weight:${voterId}`);
      weights.set(voterId, weight || 1);
    }
    
    // Create proposal
    const proposal = await this.consensus.createProposal({
      title: params.title,
      description: params.description,
      proposal_type: params.type,
      payload: params.payload,
      proposer_id: params.proposer_id,
      eligible_voters: voters,
      voting_config: {
        ...params.voting_config,
        weighted_voting: true,
        weights,
      },
    });
    
    // Broadcast proposal to all voters
    await this.bus.broadcast({
      from: 'council',
      type: 'proposal_created',
      payload: {
        proposal_id: proposal.id,
        title: proposal.title,
        description: proposal.description,
        voting_ends_at: proposal.voting_ends_at,
      },
      priority: 'high',
    });
    
    return proposal;
  }
  
  /**
   * Vote on a proposal
   */
  async vote(proposalId: string, voterId: string, choice: 'approve' | 'reject' | 'abstain', reason?: string): Promise<void> {
    // Check policy
    const decision = await this.policy.enforce({
      agent_id: voterId,
      action: 'vote',
      resource: proposalId,
      timestamp: new Date(),
    });
    
    if (!decision.allowed) {
      throw new Error(`Vote denied: ${decision.message}`);
    }
    
    await this.consensus.vote(proposalId, voterId, choice, reason);
  }
  
  // ===========================================================================
  // Communication Operations
  // ===========================================================================
  
  /**
   * Send a message to another agent
   */
  async sendMessage(params: {
    from: string;
    to: string | string[];
    type: string;
    payload: any;
    priority?: Message['priority'];
    require_ack?: boolean;
  }): Promise<Message> {
    // Check policy
    const decision = await this.policy.enforce({
      agent_id: params.from,
      action: 'send_message',
      properties: { to: params.to, type: params.type },
      timestamp: new Date(),
    });
    
    if (!decision.allowed) {
      throw new Error(`Message denied: ${decision.message}`);
    }
    
    return this.bus.send(params);
  }
  
  /**
   * Broadcast to all agents
   */
  async broadcast(params: {
    from: string;
    type: string;
    payload: any;
    priority?: Message['priority'];
  }): Promise<Message> {
    return this.bus.broadcast(params);
  }
  
  /**
   * Create a communication channel
   */
  async createChannel(params: {
    name: string;
    owner: string;
    type?: Channel['type'];
    members?: string[];
  }): Promise<Channel> {
    return this.bus.createChannel({
      name: params.name,
      owner: params.owner,
      type: params.type || 'topic',
      initial_members: params.members,
    });
  }
  
  // ===========================================================================
  // Policy Operations
  // ===========================================================================
  
  /**
   * Create a rate limit for an agent or action
   */
  async setRateLimit(params: {
    name: string;
    agent_ids?: string[];
    action?: string;
    max_requests: number;
    window_ms: number;
  }): Promise<Policy> {
    const targets = params.agent_ids 
      ? [{ type: 'agent' as const, ids: params.agent_ids }]
      : [{ type: 'all' as const }];
    
    return this.policy.createRateLimit({
      name: params.name,
      targets,
      max_requests: params.max_requests,
      window_ms: params.window_ms,
    });
  }
  
  /**
   * Set a resource quota
   */
  async setQuota(params: {
    name: string;
    agent_ids?: string[];
    resource: string;
    max_value: number;
  }): Promise<Policy> {
    const targets = params.agent_ids 
      ? [{ type: 'agent' as const, ids: params.agent_ids }]
      : [{ type: 'all' as const }];
    
    return this.policy.createQuota({
      name: params.name,
      targets,
      resource: params.resource,
      max_value: params.max_value,
    });
  }
  
  /**
   * Check if an action is allowed
   */
  async checkPolicy(context: EvaluationContext): Promise<EnforcementDecision> {
    return this.policy.enforce(context);
  }
  
  // ===========================================================================
  // Recovery Operations
  // ===========================================================================
  
  /**
   * Create a checkpoint
   */
  async checkpoint(name?: string, createdBy?: string): Promise<Checkpoint> {
    return this.recovery.checkpoint({
      name: name || 'Manual checkpoint',
      created_by: createdBy || 'system',
      include_agents: true,
      include_tasks: true,
    });
  }
  
  /**
   * Restore from checkpoint
   */
  async restore(checkpointId: string): Promise<void> {
    await this.recovery.restore(checkpointId, 'manual');
  }
  
  /**
   * Begin a transaction
   */
  async beginTransaction(initiator: string, description?: string): Promise<Transaction> {
    return this.recovery.beginTransaction({
      initiator,
      description,
      auto_checkpoint: true,
    });
  }
  
  /**
   * Commit a transaction
   */
  async commitTransaction(transactionId: string): Promise<void> {
    await this.recovery.commitTransaction(transactionId);
  }
  
  /**
   * Rollback a transaction
   */
  async rollbackTransaction(transactionId: string): Promise<void> {
    await this.recovery.rollbackTransaction(transactionId);
  }
  
  // ===========================================================================
  // Task Operations (Delegated to Orchestrator)
  // ===========================================================================
  
  /**
   * Submit a task
   */
  async submitTask(params: Parameters<Orchestrator['submitTask']>[0]) {
    // Check policy
    const decision = await this.policy.enforce({
      agent_id: 'orchestrator',
      action: 'submit_task',
      properties: { intent: params.intent, priority: params.priority },
      timestamp: new Date(),
    });
    
    if (!decision.allowed) {
      throw new Error(`Task submission denied: ${decision.message}`);
    }
    
    return this.orchestrator.submitTask(params);
  }
  
  /**
   * Agent heartbeat
   */
  async heartbeat(agentId: string, currentTasks: string[]) {
    // Receive any pending messages
    const messages = await this.bus.receive(agentId, { mark_delivered: true });
    
    // Get orchestrator response
    const orchResponse = await this.orchestrator.heartbeat(agentId, currentTasks);
    
    return {
      ...orchResponse,
      messages,
    };
  }
  
  // ===========================================================================
  // Statistics
  // ===========================================================================
  
  /**
   * Get council statistics
   */
  getStats(): WitanStats {
    const orchStats = this.orchestrator.getStats();
    const consensusStats = this.consensus.getStats();
    const busStats = this.bus.getStats();
    const policyStats = this.policy.getStats();
    const recoveryStats = this.recovery.getStats();
    
    return {
      orchestration: {
        agents: orchStats.agents.total,
        agents_ready: orchStats.agents.ready,
        tasks_queued: orchStats.tasks.queued,
        tasks_running: orchStats.tasks.running,
      },
      consensus: {
        proposals_open: consensusStats.by_status.open,
        proposals_total: consensusStats.total_proposals,
        avg_participation: consensusStats.avg_participation,
      },
      communication: {
        messages_pending: busStats.pending_messages,
        channels: busStats.channels,
        agents_connected: busStats.registered_agents,
      },
      policy: {
        policies_active: policyStats.active_policies,
        violations_last_hour: policyStats.violations_last_hour,
      },
      recovery: {
        checkpoints: recoveryStats.checkpoints,
        active_transactions: recoveryStats.active_transactions,
      },
    };
  }
  
  /**
   * Subscribe to all council events
   */
  onEvent(callback: (event: WitanEvent) => void): () => void {
    this.eventCallbacks.push(callback);
    return () => {
      const index = this.eventCallbacks.indexOf(callback);
      if (index !== -1) this.eventCallbacks.splice(index, 1);
    };
  }
  
  // ===========================================================================
  // Private Methods
  // ===========================================================================
  
  private setupEventHandlers(): void {
    // Forward consensus events
    this.consensus.onEvent((event) => {
      this.emitEvent({ source: 'consensus', event, timestamp: new Date() });
      
      // Auto-broadcast proposal results
      if (event.type === 'passed' || event.type === 'rejected') {
        this.bus.broadcast({
          from: 'council',
          type: 'proposal_decided',
          payload: event,
        }).catch(() => {});
      }
    });
    
    // Forward bus events
    this.bus.onEvent((event) => {
      this.emitEvent({ source: 'bus', event, timestamp: new Date() });
    });
    
    // Forward recovery events
    this.recovery.onEvent((event) => {
      this.emitEvent({ source: 'recovery', event, timestamp: new Date() });
    });
    
    // Handle policy violations
    this.policy.onViolation((violation) => {
      this.emitEvent({
        source: 'policy',
        event: { type: 'violation', violation },
        timestamp: new Date(),
      });
    });
    
    // Handle agent failures
    this.registry.onAgentDown(async (agent, tasks) => {
      await this.recovery.reportFailure({
        type: 'agent',
        id: agent.id,
        error: 'Agent went offline',
        context: { tasks },
      });
    });
  }
  
  private setupRecoveryAccessors(): void {
    this.recovery.setStateAccessors({
      stateGetter: async () => this.state.exportState(),
      stateSetter: async (state) => {
        await this.state.importState(state, { merge: false });
      },
      agentStateGetter: async () => {
        const agents = this.registry.getAllAgents();
        return new Map(agents.map(a => [a.id, a]));
      },
      taskStateGetter: async () => {
        const tasks = this.scheduler.getAllTasks();
        return new Map(tasks.map(t => [t.id, t]));
      },
    });
  }
  
  private emitEvent(event: WitanEvent): void {
    for (const cb of this.eventCallbacks) {
      try {
        cb(event);
      } catch (e) {
        // Ignore
      }
    }
  }
}

export default WitanCouncil;
