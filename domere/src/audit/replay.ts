/**
 * Dōmere - Execution Replay & Audit Trail
 * 
 * Cryptographically verifiable audit trail for AI agent actions.
 * Enables complete replay and forensic analysis of agent behavior.
 */

import * as crypto from 'crypto';

// =============================================================================
// Types
// =============================================================================

export interface ActionRecord {
  id: string;
  thread_id: string;
  sequence: number;
  timestamp: Date;
  
  // Actor
  agent_id: string;
  agent_type: 'llm' | 'tool' | 'human' | 'system';
  
  // Action details
  action_type: 'inference' | 'tool_call' | 'api_request' | 'file_access' | 'data_read' | 'data_write' | 'delegation' | 'decision';
  action_name: string;
  
  // I/O hashes (not raw data for privacy)
  input_hash: string;
  output_hash: string;
  input_size_bytes?: number;
  output_size_bytes?: number;
  
  // Optional raw data (encrypted)
  input_encrypted?: string;
  output_encrypted?: string;
  
  // Metadata
  latency_ms: number;
  cost_usd?: number;
  tokens_in?: number;
  tokens_out?: number;
  model?: string;
  provider?: string;
  
  // Verification
  previous_hash: string;
  action_hash: string;
  signature?: string;
}

export interface ExecutionTrail {
  thread_id: string;
  created_at: Date;
  updated_at: Date;
  action_count: number;
  total_cost_usd: number;
  total_latency_ms: number;
  agents_involved: string[];
  merkle_root: string;
  actions: ActionRecord[];
  integrity_valid: boolean;
}

export interface ReplayOptions {
  from_sequence?: number;
  to_sequence?: number;
  agent_filter?: string[];
  action_type_filter?: ActionRecord['action_type'][];
  include_encrypted?: boolean;
}

export interface AuditQuery {
  thread_id?: string;
  agent_id?: string;
  action_type?: ActionRecord['action_type'];
  start_time?: Date;
  end_time?: Date;
  min_cost_usd?: number;
  min_latency_ms?: number;
  limit?: number;
}

export interface AuditReport {
  query: AuditQuery;
  generated_at: Date;
  total_actions: number;
  total_cost_usd: number;
  total_latency_ms: number;
  actions_by_type: Record<string, number>;
  actions_by_agent: Record<string, number>;
  cost_by_agent: Record<string, number>;
  anomalies: AuditAnomaly[];
}

export interface AuditAnomaly {
  type: 'high_latency' | 'high_cost' | 'repeated_failure' | 'unusual_pattern' | 'integrity_violation';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  action_ids: string[];
  detected_at: Date;
}

// =============================================================================
// Execution Replay Manager
// =============================================================================

export class ExecutionReplayManager {
  private trails: Map<string, ActionRecord[]> = new Map();
  private encryptionKey?: Buffer;
  
  constructor(encryptionKey?: string) {
    if (encryptionKey) {
      this.encryptionKey = crypto.scryptSync(encryptionKey, 'domere-audit', 32);
    }
  }
  
  /**
   * Record an action in the audit trail
   */
  async recordAction(params: {
    thread_id: string;
    agent_id: string;
    agent_type: ActionRecord['agent_type'];
    action_type: ActionRecord['action_type'];
    action_name: string;
    input: any;
    output: any;
    latency_ms: number;
    cost_usd?: number;
    tokens_in?: number;
    tokens_out?: number;
    model?: string;
    provider?: string;
    store_raw?: boolean;
  }): Promise<ActionRecord> {
    const trail = this.trails.get(params.thread_id) || [];
    const sequence = trail.length;
    const previousHash = sequence > 0 ? trail[sequence - 1].action_hash : '0'.repeat(64);
    
    // Hash inputs/outputs
    const inputStr = JSON.stringify(params.input);
    const outputStr = JSON.stringify(params.output);
    const inputHash = crypto.createHash('sha256').update(inputStr).digest('hex');
    const outputHash = crypto.createHash('sha256').update(outputStr).digest('hex');
    
    // Create action record
    const record: ActionRecord = {
      id: `act_${crypto.randomUUID()}`,
      thread_id: params.thread_id,
      sequence,
      timestamp: new Date(),
      
      agent_id: params.agent_id,
      agent_type: params.agent_type,
      
      action_type: params.action_type,
      action_name: params.action_name,
      
      input_hash: inputHash,
      output_hash: outputHash,
      input_size_bytes: Buffer.byteLength(inputStr),
      output_size_bytes: Buffer.byteLength(outputStr),
      
      latency_ms: params.latency_ms,
      cost_usd: params.cost_usd,
      tokens_in: params.tokens_in,
      tokens_out: params.tokens_out,
      model: params.model,
      provider: params.provider,
      
      previous_hash: previousHash,
      action_hash: '', // Computed below
    };
    
    // Optionally encrypt and store raw data
    if (params.store_raw && this.encryptionKey) {
      record.input_encrypted = this.encrypt(inputStr);
      record.output_encrypted = this.encrypt(outputStr);
    }
    
    // Compute action hash (chain integrity)
    record.action_hash = this.computeActionHash(record);
    
    // Store
    trail.push(record);
    this.trails.set(params.thread_id, trail);
    
    return record;
  }
  
  /**
   * Get complete execution trail for a thread
   */
  async getExecutionTrail(threadId: string, options?: ReplayOptions): Promise<ExecutionTrail | null> {
    const actions = this.trails.get(threadId);
    if (!actions || actions.length === 0) return null;
    
    let filtered = [...actions];
    
    // Apply filters
    if (options?.from_sequence !== undefined) {
      filtered = filtered.filter(a => a.sequence >= options.from_sequence!);
    }
    if (options?.to_sequence !== undefined) {
      filtered = filtered.filter(a => a.sequence <= options.to_sequence!);
    }
    if (options?.agent_filter?.length) {
      filtered = filtered.filter(a => options.agent_filter!.includes(a.agent_id));
    }
    if (options?.action_type_filter?.length) {
      filtered = filtered.filter(a => options.action_type_filter!.includes(a.action_type));
    }
    
    // Remove encrypted data if not requested
    if (!options?.include_encrypted) {
      filtered = filtered.map(a => {
        const { input_encrypted, output_encrypted, ...rest } = a;
        return rest as ActionRecord;
      });
    }
    
    // Compute stats
    const totalCost = filtered.reduce((sum, a) => sum + (a.cost_usd || 0), 0);
    const totalLatency = filtered.reduce((sum, a) => sum + a.latency_ms, 0);
    const agents = [...new Set(filtered.map(a => a.agent_id))];
    
    // Verify integrity
    const integrityValid = this.verifyTrailIntegrity(actions);
    
    return {
      thread_id: threadId,
      created_at: actions[0].timestamp,
      updated_at: actions[actions.length - 1].timestamp,
      action_count: filtered.length,
      total_cost_usd: totalCost,
      total_latency_ms: totalLatency,
      agents_involved: agents,
      merkle_root: this.computeMerkleRoot(actions),
      actions: filtered,
      integrity_valid: integrityValid,
    };
  }
  
  /**
   * Replay actions for debugging/analysis
   */
  async replayActions(threadId: string, options?: ReplayOptions): Promise<{
    actions: ActionRecord[];
    timeline: { timestamp: Date; description: string }[];
    summary: {
      total_actions: number;
      duration_ms: number;
      cost_usd: number;
      agents: string[];
    };
  }> {
    const trail = await this.getExecutionTrail(threadId, options);
    if (!trail) {
      throw new Error(`No trail found for thread ${threadId}`);
    }
    
    const timeline = trail.actions.map(action => ({
      timestamp: action.timestamp,
      description: `[${action.agent_id}] ${action.action_type}: ${action.action_name} (${action.latency_ms}ms)`,
    }));
    
    const duration = trail.actions.length > 1 
      ? trail.actions[trail.actions.length - 1].timestamp.getTime() - trail.actions[0].timestamp.getTime()
      : 0;
    
    return {
      actions: trail.actions,
      timeline,
      summary: {
        total_actions: trail.action_count,
        duration_ms: duration,
        cost_usd: trail.total_cost_usd,
        agents: trail.agents_involved,
      },
    };
  }
  
  /**
   * Query actions across threads
   */
  async queryActions(query: AuditQuery): Promise<ActionRecord[]> {
    let results: ActionRecord[] = [];
    
    for (const [threadId, actions] of this.trails) {
      if (query.thread_id && threadId !== query.thread_id) continue;
      
      for (const action of actions) {
        if (query.agent_id && action.agent_id !== query.agent_id) continue;
        if (query.action_type && action.action_type !== query.action_type) continue;
        if (query.start_time && action.timestamp < query.start_time) continue;
        if (query.end_time && action.timestamp > query.end_time) continue;
        if (query.min_cost_usd && (action.cost_usd || 0) < query.min_cost_usd) continue;
        if (query.min_latency_ms && action.latency_ms < query.min_latency_ms) continue;
        
        results.push(action);
      }
    }
    
    // Sort by timestamp
    results.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
    
    // Apply limit
    if (query.limit) {
      results = results.slice(0, query.limit);
    }
    
    return results;
  }
  
  /**
   * Generate audit report
   */
  async generateAuditReport(query: AuditQuery): Promise<AuditReport> {
    const actions = await this.queryActions(query);
    
    const actionsByType: Record<string, number> = {};
    const actionsByAgent: Record<string, number> = {};
    const costByAgent: Record<string, number> = {};
    let totalCost = 0;
    let totalLatency = 0;
    
    for (const action of actions) {
      actionsByType[action.action_type] = (actionsByType[action.action_type] || 0) + 1;
      actionsByAgent[action.agent_id] = (actionsByAgent[action.agent_id] || 0) + 1;
      costByAgent[action.agent_id] = (costByAgent[action.agent_id] || 0) + (action.cost_usd || 0);
      totalCost += action.cost_usd || 0;
      totalLatency += action.latency_ms;
    }
    
    // Detect anomalies
    const anomalies = this.detectAnomalies(actions);
    
    return {
      query,
      generated_at: new Date(),
      total_actions: actions.length,
      total_cost_usd: totalCost,
      total_latency_ms: totalLatency,
      actions_by_type: actionsByType,
      actions_by_agent: actionsByAgent,
      cost_by_agent: costByAgent,
      anomalies,
    };
  }
  
  /**
   * Verify trail integrity
   */
  verifyTrailIntegrity(actions: ActionRecord[]): boolean {
    if (actions.length === 0) return true;
    
    for (let i = 0; i < actions.length; i++) {
      const action = actions[i];
      const expectedPrevHash = i === 0 ? '0'.repeat(64) : actions[i - 1].action_hash;
      
      if (action.previous_hash !== expectedPrevHash) {
        return false;
      }
      
      const computedHash = this.computeActionHash(action);
      if (action.action_hash !== computedHash) {
        return false;
      }
    }
    
    return true;
  }
  
  /**
   * Export trail for external storage/verification
   */
  async exportTrail(threadId: string): Promise<string> {
    const trail = await this.getExecutionTrail(threadId, { include_encrypted: true });
    if (!trail) throw new Error(`No trail found for thread ${threadId}`);
    
    return JSON.stringify(trail, null, 2);
  }
  
  /**
   * Import trail from external source
   */
  async importTrail(data: string): Promise<{ thread_id: string; actions_imported: number; valid: boolean }> {
    const trail: ExecutionTrail = JSON.parse(data);
    
    // Verify integrity
    const valid = this.verifyTrailIntegrity(trail.actions);
    
    // Store
    this.trails.set(trail.thread_id, trail.actions);
    
    return {
      thread_id: trail.thread_id,
      actions_imported: trail.actions.length,
      valid,
    };
  }
  
  // ===========================================================================
  // Private Methods
  // ===========================================================================
  
  private computeActionHash(action: ActionRecord): string {
    const data = [
      action.thread_id,
      action.sequence.toString(),
      action.agent_id,
      action.action_type,
      action.action_name,
      action.input_hash,
      action.output_hash,
      action.timestamp.toISOString(),
      action.previous_hash,
    ].join('|');
    
    return crypto.createHash('sha256').update(data).digest('hex');
  }
  
  private computeMerkleRoot(actions: ActionRecord[]): string {
    if (actions.length === 0) return '0'.repeat(64);
    
    let hashes = actions.map(a => a.action_hash);
    
    while (hashes.length > 1) {
      const newHashes: string[] = [];
      for (let i = 0; i < hashes.length; i += 2) {
        const left = hashes[i];
        const right = hashes[i + 1] || left;
        const combined = crypto.createHash('sha256').update(left + right).digest('hex');
        newHashes.push(combined);
      }
      hashes = newHashes;
    }
    
    return hashes[0];
  }
  
  private encrypt(data: string): string {
    if (!this.encryptionKey) throw new Error('Encryption key not set');
    
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.encryptionKey, iv);
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
  }
  
  private decrypt(encrypted: string): string {
    if (!this.encryptionKey) throw new Error('Encryption key not set');
    
    const [ivHex, authTagHex, data] = encrypted.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.encryptionKey, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(data, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }
  
  private detectAnomalies(actions: ActionRecord[]): AuditAnomaly[] {
    const anomalies: AuditAnomaly[] = [];
    
    // High latency detection (>10s)
    const highLatency = actions.filter(a => a.latency_ms > 10000);
    if (highLatency.length > 0) {
      anomalies.push({
        type: 'high_latency',
        severity: 'medium',
        description: `${highLatency.length} actions exceeded 10s latency`,
        action_ids: highLatency.map(a => a.id),
        detected_at: new Date(),
      });
    }
    
    // High cost detection (>$1 per action)
    const highCost = actions.filter(a => (a.cost_usd || 0) > 1);
    if (highCost.length > 0) {
      anomalies.push({
        type: 'high_cost',
        severity: 'high',
        description: `${highCost.length} actions exceeded $1 cost`,
        action_ids: highCost.map(a => a.id),
        detected_at: new Date(),
      });
    }
    
    return anomalies;
  }
}

export default ExecutionReplayManager;
