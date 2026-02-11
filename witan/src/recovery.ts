/**
 * Witan - Recovery Manager
 * 
 * Checkpoints, rollback, transaction logging, and disaster recovery
 * for multi-agent AI orchestration systems.
 */

import * as crypto from 'crypto';

// =============================================================================
// Types
// =============================================================================

export type CheckpointStatus = 'creating' | 'active' | 'restoring' | 'restored' | 'deleted';
export type TransactionStatus = 'pending' | 'committed' | 'rolled_back' | 'failed';

export interface Checkpoint {
  id: string;
  name?: string;
  
  // Scope
  thread_id?: string;
  task_id?: string;
  scope: 'full' | 'thread' | 'task' | 'agent' | 'custom';
  
  // Content
  state_snapshot: any;
  agent_states?: Map<string, any>;
  task_states?: Map<string, any>;
  
  // Verification
  hash: string;
  signature: string;
  
  // Status
  status: CheckpointStatus;
  created_at: Date;
  created_by: string;
  restored_at?: Date;
  restored_by?: string;
  
  // Metadata
  tags: string[];
  metadata: Record<string, any>;
}

export interface Transaction {
  id: string;
  thread_id?: string;
  
  // Content
  operations: Operation[];
  
  // Status
  status: TransactionStatus;
  started_at: Date;
  completed_at?: Date;
  
  // Rollback info
  rollback_operations: Operation[];
  checkpoint_id?: string;
  
  // Metadata
  initiator: string;
  description?: string;
}

export interface Operation {
  id: string;
  type: 'state_change' | 'task_action' | 'agent_action' | 'message' | 'external';
  
  // Target
  target_type: 'state' | 'task' | 'agent' | 'message' | 'resource';
  target_id: string;
  
  // Change
  action: string;
  before?: any;
  after?: any;
  
  // Timing
  timestamp: Date;
  duration_ms?: number;
  
  // Status
  success: boolean;
  error?: string;
  
  // Rollback
  reversible: boolean;
  rollback_action?: string;
}

export interface RecoveryPlan {
  id: string;
  name: string;
  
  // Trigger
  trigger: RecoveryTrigger;
  
  // Actions
  actions: RecoveryAction[];
  
  // Config
  auto_execute: boolean;
  notify_on_trigger: boolean;
  
  enabled: boolean;
  created_at: Date;
}

export interface RecoveryTrigger {
  type: 'agent_failure' | 'task_failure' | 'state_corruption' | 'consensus_failure' | 'manual' | 'threshold';
  
  // Threshold triggers
  failure_count?: number;
  failure_window_ms?: number;
  
  // Pattern matching
  agent_pattern?: string;
  task_pattern?: string;
}

export interface RecoveryAction {
  type: 'restore_checkpoint' | 'reassign_tasks' | 'restart_agent' | 'rollback_transaction' | 'notify' | 'custom';
  
  // Config
  checkpoint_id?: string;
  checkpoint_age_ms?: number;  // Use most recent within this age
  notify_targets?: string[];
  custom_handler?: (context: any) => Promise<void>;
  
  // Sequencing
  order: number;
  continue_on_failure: boolean;
}

export interface RecoveryEvent {
  type: 'checkpoint_created' | 'checkpoint_restored' | 'transaction_started' | 'transaction_committed' | 'transaction_rolled_back' | 'recovery_triggered' | 'recovery_completed';
  timestamp: Date;
  details: Record<string, any>;
}

export interface RecoveryConfig {
  max_checkpoints: number;
  auto_checkpoint_interval_ms?: number;
  transaction_timeout_ms: number;
  max_transaction_log_size: number;
  enable_auto_recovery: boolean;
}

// =============================================================================
// Recovery Manager
// =============================================================================

export class RecoveryManager {
  private checkpoints: Map<string, Checkpoint> = new Map();
  private transactions: Map<string, Transaction> = new Map();
  private transactionLog: Operation[] = [];
  private recoveryPlans: Map<string, RecoveryPlan> = new Map();
  private failureCounts: Map<string, { count: number; window_start: Date }> = new Map();
  private signingKey: Buffer;
  private config: RecoveryConfig;
  private eventCallbacks: ((event: RecoveryEvent) => void)[] = [];
  private autoCheckpointTimer?: NodeJS.Timeout;
  
  // External state accessors (set by Witan main class)
  private stateGetter?: () => Promise<any>;
  private stateSetter?: (state: any) => Promise<void>;
  private agentStateGetter?: () => Promise<Map<string, any>>;
  private taskStateGetter?: () => Promise<Map<string, any>>;
  
  constructor(signingKey: string, config?: Partial<RecoveryConfig>) {
    this.signingKey = crypto.scryptSync(signingKey, 'witan-recovery', 32);
    this.config = {
      max_checkpoints: 100,
      transaction_timeout_ms: 300000,  // 5 minutes
      max_transaction_log_size: 10000,
      enable_auto_recovery: true,
      ...config,
    };
    
    // Start auto-checkpoint if configured
    if (this.config.auto_checkpoint_interval_ms) {
      this.startAutoCheckpoint();
    }
    
    // Start transaction timeout checker
    setInterval(() => this.checkTransactionTimeouts(), 30000);
  }
  
  /**
   * Set state accessors for checkpoint/restore
   */
  setStateAccessors(accessors: {
    stateGetter?: () => Promise<any>;
    stateSetter?: (state: any) => Promise<void>;
    agentStateGetter?: () => Promise<Map<string, any>>;
    taskStateGetter?: () => Promise<Map<string, any>>;
  }): void {
    this.stateGetter = accessors.stateGetter;
    this.stateSetter = accessors.stateSetter;
    this.agentStateGetter = accessors.agentStateGetter;
    this.taskStateGetter = accessors.taskStateGetter;
  }
  
  // ===========================================================================
  // Checkpoints
  // ===========================================================================
  
  /**
   * Create a checkpoint
   */
  async checkpoint(params: {
    name?: string;
    scope?: Checkpoint['scope'];
    thread_id?: string;
    task_id?: string;
    created_by: string;
    state_snapshot?: any;
    include_agents?: boolean;
    include_tasks?: boolean;
    tags?: string[];
    metadata?: Record<string, any>;
  }): Promise<Checkpoint> {
    // Check checkpoint limit
    if (this.checkpoints.size >= this.config.max_checkpoints) {
      // Remove oldest checkpoint
      const oldest = Array.from(this.checkpoints.values())
        .sort((a, b) => a.created_at.getTime() - b.created_at.getTime())[0];
      if (oldest) {
        this.checkpoints.delete(oldest.id);
      }
    }
    
    const id = `ckpt_${crypto.randomUUID()}`;
    const now = new Date();
    
    // Get state
    let stateSnapshot = params.state_snapshot;
    if (!stateSnapshot && this.stateGetter) {
      stateSnapshot = await this.stateGetter();
    }
    
    // Get agent states
    let agentStates: Map<string, any> | undefined;
    if (params.include_agents !== false && this.agentStateGetter) {
      agentStates = await this.agentStateGetter();
    }
    
    // Get task states
    let taskStates: Map<string, any> | undefined;
    if (params.include_tasks !== false && this.taskStateGetter) {
      taskStates = await this.taskStateGetter();
    }
    
    // Compute hash
    const hashData = JSON.stringify({
      state: stateSnapshot,
      agents: agentStates ? Object.fromEntries(agentStates) : null,
      tasks: taskStates ? Object.fromEntries(taskStates) : null,
    });
    const hash = crypto.createHash('sha256').update(hashData).digest('hex');
    
    const checkpoint: Checkpoint = {
      id,
      name: params.name,
      
      thread_id: params.thread_id,
      task_id: params.task_id,
      scope: params.scope || 'full',
      
      state_snapshot: stateSnapshot,
      agent_states: agentStates,
      task_states: taskStates,
      
      hash,
      signature: this.sign(hash),
      
      status: 'active',
      created_at: now,
      created_by: params.created_by,
      
      tags: params.tags || [],
      metadata: params.metadata || {},
    };
    
    this.checkpoints.set(id, checkpoint);
    
    this.emitEvent({
      type: 'checkpoint_created',
      timestamp: now,
      details: { checkpoint_id: id, scope: checkpoint.scope }
    });
    
    return checkpoint;
  }
  
  /**
   * Restore from a checkpoint
   */
  async restore(checkpointId: string, restoredBy: string): Promise<void> {
    const checkpoint = this.checkpoints.get(checkpointId);
    if (!checkpoint) throw new Error(`Checkpoint ${checkpointId} not found`);
    
    // Verify integrity
    const hashData = JSON.stringify({
      state: checkpoint.state_snapshot,
      agents: checkpoint.agent_states ? Object.fromEntries(checkpoint.agent_states) : null,
      tasks: checkpoint.task_states ? Object.fromEntries(checkpoint.task_states) : null,
    });
    const computedHash = crypto.createHash('sha256').update(hashData).digest('hex');
    
    if (computedHash !== checkpoint.hash) {
      throw new Error('Checkpoint integrity check failed');
    }
    
    checkpoint.status = 'restoring';
    
    try {
      // Restore state
      if (this.stateSetter && checkpoint.state_snapshot) {
        await this.stateSetter(checkpoint.state_snapshot);
      }
      
      checkpoint.status = 'restored';
      checkpoint.restored_at = new Date();
      checkpoint.restored_by = restoredBy;
      
      this.emitEvent({
        type: 'checkpoint_restored',
        timestamp: new Date(),
        details: { checkpoint_id: checkpointId, restored_by: restoredBy }
      });
    } catch (error) {
      checkpoint.status = 'active';  // Revert status
      throw error;
    }
  }
  
  /**
   * Get checkpoint by ID
   */
  getCheckpoint(checkpointId: string): Checkpoint | undefined {
    return this.checkpoints.get(checkpointId);
  }
  
  /**
   * List checkpoints
   */
  listCheckpoints(filter?: {
    scope?: Checkpoint['scope'];
    thread_id?: string;
    tags?: string[];
    since?: Date;
  }): Checkpoint[] {
    let checkpoints = Array.from(this.checkpoints.values());
    
    if (filter?.scope) {
      checkpoints = checkpoints.filter(c => c.scope === filter.scope);
    }
    if (filter?.thread_id) {
      checkpoints = checkpoints.filter(c => c.thread_id === filter.thread_id);
    }
    if (filter?.tags?.length) {
      checkpoints = checkpoints.filter(c => 
        filter.tags!.some(tag => c.tags.includes(tag))
      );
    }
    if (filter?.since) {
      checkpoints = checkpoints.filter(c => c.created_at >= filter.since!);
    }
    
    // Sort by created_at descending
    checkpoints.sort((a, b) => b.created_at.getTime() - a.created_at.getTime());
    
    return checkpoints;
  }
  
  /**
   * Get most recent checkpoint
   */
  getLatestCheckpoint(scope?: Checkpoint['scope']): Checkpoint | undefined {
    const checkpoints = this.listCheckpoints({ scope });
    return checkpoints[0];
  }
  
  /**
   * Delete a checkpoint
   */
  deleteCheckpoint(checkpointId: string): boolean {
    const checkpoint = this.checkpoints.get(checkpointId);
    if (checkpoint) {
      checkpoint.status = 'deleted';
    }
    return this.checkpoints.delete(checkpointId);
  }
  
  // ===========================================================================
  // Transactions
  // ===========================================================================
  
  /**
   * Begin a transaction
   */
  async beginTransaction(params: {
    initiator: string;
    description?: string;
    thread_id?: string;
    auto_checkpoint?: boolean;
  }): Promise<Transaction> {
    const id = `txn_${crypto.randomUUID()}`;
    
    // Create checkpoint if requested
    let checkpointId: string | undefined;
    if (params.auto_checkpoint) {
      const checkpoint = await this.checkpoint({
        name: `Pre-transaction ${id}`,
        created_by: params.initiator,
        tags: ['transaction', 'auto'],
      });
      checkpointId = checkpoint.id;
    }
    
    const transaction: Transaction = {
      id,
      thread_id: params.thread_id,
      
      operations: [],
      
      status: 'pending',
      started_at: new Date(),
      
      rollback_operations: [],
      checkpoint_id: checkpointId,
      
      initiator: params.initiator,
      description: params.description,
    };
    
    this.transactions.set(id, transaction);
    
    this.emitEvent({
      type: 'transaction_started',
      timestamp: new Date(),
      details: { transaction_id: id, initiator: params.initiator }
    });
    
    return transaction;
  }
  
  /**
   * Record an operation in a transaction
   */
  async recordOperation(transactionId: string, operation: Omit<Operation, 'id' | 'timestamp'>): Promise<Operation> {
    const transaction = this.transactions.get(transactionId);
    if (!transaction) throw new Error(`Transaction ${transactionId} not found`);
    if (transaction.status !== 'pending') {
      throw new Error(`Transaction ${transactionId} is ${transaction.status}`);
    }
    
    const op: Operation = {
      ...operation,
      id: `op_${crypto.randomUUID()}`,
      timestamp: new Date(),
    };
    
    transaction.operations.push(op);
    
    // Add to global log
    this.transactionLog.push(op);
    if (this.transactionLog.length > this.config.max_transaction_log_size) {
      this.transactionLog.shift();
    }
    
    // Create rollback operation if reversible
    if (operation.reversible && operation.rollback_action) {
      const rollbackOp: Operation = {
        id: `rollback_${op.id}`,
        type: op.type,
        target_type: op.target_type,
        target_id: op.target_id,
        action: operation.rollback_action,
        before: op.after,
        after: op.before,
        timestamp: new Date(),
        success: false,
        reversible: false,
      };
      transaction.rollback_operations.unshift(rollbackOp);  // Add to front for reverse order
    }
    
    return op;
  }
  
  /**
   * Commit a transaction
   */
  async commitTransaction(transactionId: string): Promise<void> {
    const transaction = this.transactions.get(transactionId);
    if (!transaction) throw new Error(`Transaction ${transactionId} not found`);
    if (transaction.status !== 'pending') {
      throw new Error(`Transaction ${transactionId} is ${transaction.status}`);
    }
    
    transaction.status = 'committed';
    transaction.completed_at = new Date();
    
    this.emitEvent({
      type: 'transaction_committed',
      timestamp: new Date(),
      details: { 
        transaction_id: transactionId, 
        operation_count: transaction.operations.length 
      }
    });
  }
  
  /**
   * Rollback a transaction
   */
  async rollbackTransaction(transactionId: string, reason?: string): Promise<void> {
    const transaction = this.transactions.get(transactionId);
    if (!transaction) throw new Error(`Transaction ${transactionId} not found`);
    
    // If checkpoint exists, restore it
    if (transaction.checkpoint_id) {
      await this.restore(transaction.checkpoint_id, 'system');
    }
    
    transaction.status = 'rolled_back';
    transaction.completed_at = new Date();
    
    this.emitEvent({
      type: 'transaction_rolled_back',
      timestamp: new Date(),
      details: { 
        transaction_id: transactionId, 
        reason,
        operations_rolled_back: transaction.operations.length
      }
    });
  }
  
  /**
   * Get transaction
   */
  getTransaction(transactionId: string): Transaction | undefined {
    return this.transactions.get(transactionId);
  }
  
  /**
   * Get transaction log
   */
  getTransactionLog(filter?: {
    type?: Operation['type'];
    target_id?: string;
    since?: Date;
    limit?: number;
  }): Operation[] {
    let log = [...this.transactionLog];
    
    if (filter?.type) {
      log = log.filter(op => op.type === filter.type);
    }
    if (filter?.target_id) {
      log = log.filter(op => op.target_id === filter.target_id);
    }
    if (filter?.since) {
      log = log.filter(op => op.timestamp >= filter.since!);
    }
    
    // Sort by timestamp descending
    log.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
    
    if (filter?.limit) {
      log = log.slice(0, filter.limit);
    }
    
    return log;
  }
  
  // ===========================================================================
  // Recovery Plans
  // ===========================================================================
  
  /**
   * Create a recovery plan
   */
  async createRecoveryPlan(params: {
    name: string;
    trigger: RecoveryTrigger;
    actions: RecoveryAction[];
    auto_execute?: boolean;
    notify_on_trigger?: boolean;
  }): Promise<RecoveryPlan> {
    const id = `plan_${crypto.randomUUID()}`;
    
    const plan: RecoveryPlan = {
      id,
      name: params.name,
      trigger: params.trigger,
      actions: params.actions.sort((a, b) => a.order - b.order),
      auto_execute: params.auto_execute || false,
      notify_on_trigger: params.notify_on_trigger || true,
      enabled: true,
      created_at: new Date(),
    };
    
    this.recoveryPlans.set(id, plan);
    
    return plan;
  }
  
  /**
   * Report a failure (may trigger recovery)
   */
  async reportFailure(params: {
    type: 'agent' | 'task' | 'state' | 'consensus';
    id: string;
    error?: string;
    context?: any;
  }): Promise<{ recovered: boolean; plan_id?: string }> {
    // Track failure count
    const key = `${params.type}:${params.id}`;
    let failureInfo = this.failureCounts.get(key);
    
    if (!failureInfo || (Date.now() - failureInfo.window_start.getTime()) > 60000) {
      failureInfo = { count: 0, window_start: new Date() };
    }
    failureInfo.count++;
    this.failureCounts.set(key, failureInfo);
    
    // Find matching recovery plan
    const triggerType = {
      agent: 'agent_failure',
      task: 'task_failure',
      state: 'state_corruption',
      consensus: 'consensus_failure',
    }[params.type] as RecoveryTrigger['type'];
    
    for (const plan of this.recoveryPlans.values()) {
      if (!plan.enabled) continue;
      
      const trigger = plan.trigger;
      if (trigger.type !== triggerType) continue;
      
      // Check threshold
      if (trigger.failure_count && trigger.failure_window_ms) {
        if (failureInfo.count < trigger.failure_count) continue;
      }
      
      // Check pattern
      if (trigger.agent_pattern && params.type === 'agent') {
        if (!new RegExp(trigger.agent_pattern).test(params.id)) continue;
      }
      if (trigger.task_pattern && params.type === 'task') {
        if (!new RegExp(trigger.task_pattern).test(params.id)) continue;
      }
      
      // Trigger matched
      this.emitEvent({
        type: 'recovery_triggered',
        timestamp: new Date(),
        details: { plan_id: plan.id, failure_type: params.type, failure_id: params.id }
      });
      
      if (plan.auto_execute && this.config.enable_auto_recovery) {
        await this.executeRecoveryPlan(plan.id, params.context);
        return { recovered: true, plan_id: plan.id };
      }
      
      return { recovered: false, plan_id: plan.id };
    }
    
    return { recovered: false };
  }
  
  /**
   * Execute a recovery plan
   */
  async executeRecoveryPlan(planId: string, context?: any): Promise<void> {
    const plan = this.recoveryPlans.get(planId);
    if (!plan) throw new Error(`Recovery plan ${planId} not found`);
    
    for (const action of plan.actions) {
      try {
        await this.executeRecoveryAction(action, context);
      } catch (error) {
        if (!action.continue_on_failure) {
          throw error;
        }
      }
    }
    
    this.emitEvent({
      type: 'recovery_completed',
      timestamp: new Date(),
      details: { plan_id: planId, actions_executed: plan.actions.length }
    });
  }
  
  private async executeRecoveryAction(action: RecoveryAction, context?: any): Promise<void> {
    switch (action.type) {
      case 'restore_checkpoint':
        if (action.checkpoint_id) {
          await this.restore(action.checkpoint_id, 'recovery');
        } else if (action.checkpoint_age_ms) {
          const since = new Date(Date.now() - action.checkpoint_age_ms);
          const checkpoints = this.listCheckpoints({ since });
          if (checkpoints.length > 0) {
            await this.restore(checkpoints[0].id, 'recovery');
          }
        }
        break;
      
      case 'custom':
        if (action.custom_handler) {
          await action.custom_handler(context);
        }
        break;
      
      // Other actions would integrate with scheduler/registry
      default:
        break;
    }
  }
  
  // ===========================================================================
  // Utilities
  // ===========================================================================
  
  private startAutoCheckpoint(): void {
    if (this.autoCheckpointTimer) {
      clearInterval(this.autoCheckpointTimer);
    }
    
    this.autoCheckpointTimer = setInterval(async () => {
      try {
        await this.checkpoint({
          name: 'Auto checkpoint',
          created_by: 'system',
          tags: ['auto'],
        });
      } catch (e) {
        // Ignore auto-checkpoint errors
      }
    }, this.config.auto_checkpoint_interval_ms!);
  }
  
  private checkTransactionTimeouts(): void {
    const now = Date.now();
    
    for (const transaction of this.transactions.values()) {
      if (transaction.status !== 'pending') continue;
      
      const age = now - transaction.started_at.getTime();
      if (age > this.config.transaction_timeout_ms) {
        transaction.status = 'failed';
        transaction.completed_at = new Date();
      }
    }
  }
  
  private sign(data: string): string {
    const hmac = crypto.createHmac('sha256', this.signingKey);
    hmac.update(data);
    return hmac.digest('hex');
  }
  
  private emitEvent(event: RecoveryEvent): void {
    for (const cb of this.eventCallbacks) {
      try {
        cb(event);
      } catch (e) {
        // Ignore
      }
    }
  }
  
  /**
   * Subscribe to recovery events
   */
  onEvent(callback: (event: RecoveryEvent) => void): () => void {
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
    checkpoints: number;
    active_transactions: number;
    transaction_log_size: number;
    recovery_plans: number;
  } {
    return {
      checkpoints: this.checkpoints.size,
      active_transactions: Array.from(this.transactions.values())
        .filter(t => t.status === 'pending').length,
      transaction_log_size: this.transactionLog.length,
      recovery_plans: this.recoveryPlans.size,
    };
  }
}

export default RecoveryManager;
