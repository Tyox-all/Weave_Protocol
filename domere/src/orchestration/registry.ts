/**
 * Dōmere - Agent Registry
 * 
 * Agent lifecycle management, health monitoring, and capability tracking
 * for multi-agent AI orchestration systems.
 */

import * as crypto from 'crypto';

// =============================================================================
// Types
// =============================================================================

export type AgentStatus = 'initializing' | 'ready' | 'busy' | 'overloaded' | 'draining' | 'offline' | 'failed';

export interface Agent {
  id: string;
  name?: string;
  
  // Status
  status: AgentStatus;
  registered_at: Date;
  last_heartbeat: Date;
  
  // Capabilities
  capabilities: string[];
  max_concurrent_tasks: number;
  current_tasks: string[];  // Task IDs
  
  // Performance
  metrics: AgentMetrics;
  
  // Configuration
  config: AgentConfig;
  
  // Metadata
  metadata: Record<string, any>;
}

export interface AgentConfig {
  heartbeat_interval_ms: number;
  heartbeat_timeout_ms: number;
  drain_timeout_ms: number;
  auto_recover: boolean;
}

export interface AgentMetrics {
  tasks_completed: number;
  tasks_failed: number;
  total_duration_ms: number;
  avg_duration_ms: number;
  success_rate: number;
  current_load: number;  // 0-1
  uptime_ms: number;
  last_task_completed_at?: Date;
}

export interface AgentRegistration {
  agent_id?: string;  // Optional, will generate if not provided
  name?: string;
  capabilities: string[];
  max_concurrent_tasks?: number;
  heartbeat_interval_ms?: number;
  metadata?: Record<string, any>;
}

export interface HeartbeatPayload {
  agent_id: string;
  status?: AgentStatus;
  current_tasks?: string[];
  metrics_update?: Partial<AgentMetrics>;
  metadata_update?: Record<string, any>;
}

export interface AgentQuery {
  capabilities?: string[];
  status?: AgentStatus[];
  min_available_slots?: number;
  max_load?: number;
  exclude?: string[];
}

export interface AgentEvent {
  type: 'registered' | 'ready' | 'busy' | 'overloaded' | 'draining' | 'offline' | 'failed' | 'recovered' | 'deregistered';
  agent_id: string;
  timestamp: Date;
  details?: Record<string, any>;
}

// =============================================================================
// Agent Registry
// =============================================================================

export class AgentRegistry {
  private agents: Map<string, Agent> = new Map();
  private heartbeatTimers: Map<string, NodeJS.Timeout> = new Map();
  private eventCallbacks: Map<string, ((event: AgentEvent) => void)[]> = new Map();
  private globalEventCallbacks: ((event: AgentEvent) => void)[] = [];
  
  private defaultConfig: AgentConfig = {
    heartbeat_interval_ms: 5000,
    heartbeat_timeout_ms: 15000,
    drain_timeout_ms: 60000,
    auto_recover: true,
  };
  
  constructor(defaultConfig?: Partial<AgentConfig>) {
    if (defaultConfig) {
      this.defaultConfig = { ...this.defaultConfig, ...defaultConfig };
    }
  }
  
  /**
   * Register a new agent
   */
  async register(params: AgentRegistration): Promise<Agent> {
    const id = params.agent_id || `agent_${crypto.randomUUID().split('-')[0]}`;
    
    if (this.agents.has(id)) {
      throw new Error(`Agent ${id} already registered`);
    }
    
    const now = new Date();
    
    const agent: Agent = {
      id,
      name: params.name,
      
      status: 'initializing',
      registered_at: now,
      last_heartbeat: now,
      
      capabilities: params.capabilities,
      max_concurrent_tasks: params.max_concurrent_tasks || 5,
      current_tasks: [],
      
      metrics: {
        tasks_completed: 0,
        tasks_failed: 0,
        total_duration_ms: 0,
        avg_duration_ms: 0,
        success_rate: 1,
        current_load: 0,
        uptime_ms: 0,
      },
      
      config: {
        ...this.defaultConfig,
        heartbeat_interval_ms: params.heartbeat_interval_ms || this.defaultConfig.heartbeat_interval_ms,
      },
      
      metadata: params.metadata || {},
    };
    
    this.agents.set(id, agent);
    this.startHeartbeatMonitor(id);
    this.emitEvent({ type: 'registered', agent_id: id, timestamp: now });
    
    return agent;
  }
  
  /**
   * Mark agent as ready
   */
  async setReady(agentId: string): Promise<void> {
    const agent = this.agents.get(agentId);
    if (!agent) throw new Error(`Agent ${agentId} not found`);
    
    agent.status = 'ready';
    this.emitEvent({ type: 'ready', agent_id: agentId, timestamp: new Date() });
  }
  
  /**
   * Process heartbeat from agent
   */
  async heartbeat(payload: HeartbeatPayload): Promise<{ acknowledged: boolean; instructions?: string[] }> {
    const agent = this.agents.get(payload.agent_id);
    if (!agent) {
      return { acknowledged: false, instructions: ['re-register'] };
    }
    
    const now = new Date();
    const wasOffline = agent.status === 'offline' || agent.status === 'failed';
    
    agent.last_heartbeat = now;
    
    // Update status
    if (payload.status) {
      agent.status = payload.status;
    }
    
    // Update current tasks
    if (payload.current_tasks !== undefined) {
      agent.current_tasks = payload.current_tasks;
      agent.metrics.current_load = agent.current_tasks.length / agent.max_concurrent_tasks;
      
      // Auto-update status based on load
      if (agent.status !== 'draining') {
        if (agent.metrics.current_load >= 1) {
          agent.status = 'overloaded';
        } else if (agent.metrics.current_load > 0) {
          agent.status = 'busy';
        } else {
          agent.status = 'ready';
        }
      }
    }
    
    // Update metrics
    if (payload.metrics_update) {
      agent.metrics = { ...agent.metrics, ...payload.metrics_update };
    }
    
    // Update metadata
    if (payload.metadata_update) {
      agent.metadata = { ...agent.metadata, ...payload.metadata_update };
    }
    
    // Calculate uptime
    agent.metrics.uptime_ms = now.getTime() - agent.registered_at.getTime();
    
    // Recovery event
    if (wasOffline && agent.config.auto_recover) {
      this.emitEvent({ type: 'recovered', agent_id: payload.agent_id, timestamp: now });
    }
    
    // Reset heartbeat timer
    this.resetHeartbeatTimer(payload.agent_id);
    
    const instructions: string[] = [];
    if (agent.status === 'draining') {
      instructions.push('drain-tasks');
    }
    
    return { acknowledged: true, instructions: instructions.length > 0 ? instructions : undefined };
  }
  
  /**
   * Get agent by ID
   */
  getAgent(agentId: string): Agent | undefined {
    return this.agents.get(agentId);
  }
  
  /**
   * Get all agents
   */
  getAllAgents(): Agent[] {
    return Array.from(this.agents.values());
  }
  
  /**
   * Find agents matching criteria
   */
  findAgents(query: AgentQuery): Agent[] {
    let results = Array.from(this.agents.values());
    
    // Filter by status
    if (query.status?.length) {
      results = results.filter(a => query.status!.includes(a.status));
    } else {
      // Default: only ready/busy agents
      results = results.filter(a => a.status === 'ready' || a.status === 'busy');
    }
    
    // Filter by capabilities
    if (query.capabilities?.length) {
      results = results.filter(a => 
        query.capabilities!.every(c => a.capabilities.includes(c))
      );
    }
    
    // Filter by available slots
    if (query.min_available_slots !== undefined) {
      results = results.filter(a => 
        (a.max_concurrent_tasks - a.current_tasks.length) >= query.min_available_slots!
      );
    }
    
    // Filter by load
    if (query.max_load !== undefined) {
      results = results.filter(a => a.metrics.current_load <= query.max_load!);
    }
    
    // Exclude specific agents
    if (query.exclude?.length) {
      results = results.filter(a => !query.exclude!.includes(a.id));
    }
    
    return results;
  }
  
  /**
   * Get best agent for a task
   */
  getBestAgent(query: AgentQuery & { prefer_lowest_load?: boolean; prefer_highest_success?: boolean }): Agent | null {
    let candidates = this.findAgents(query);
    
    if (candidates.length === 0) return null;
    
    // Sort by preference
    if (query.prefer_lowest_load) {
      candidates.sort((a, b) => a.metrics.current_load - b.metrics.current_load);
    } else if (query.prefer_highest_success) {
      candidates.sort((a, b) => b.metrics.success_rate - a.metrics.success_rate);
    }
    
    return candidates[0];
  }
  
  /**
   * Assign task to agent
   */
  async assignTask(agentId: string, taskId: string): Promise<boolean> {
    const agent = this.agents.get(agentId);
    if (!agent) return false;
    
    if (agent.current_tasks.length >= agent.max_concurrent_tasks) {
      return false;
    }
    
    if (agent.status === 'offline' || agent.status === 'failed' || agent.status === 'draining') {
      return false;
    }
    
    agent.current_tasks.push(taskId);
    agent.metrics.current_load = agent.current_tasks.length / agent.max_concurrent_tasks;
    
    // Update status
    if (agent.metrics.current_load >= 1) {
      agent.status = 'overloaded';
      this.emitEvent({ type: 'overloaded', agent_id: agentId, timestamp: new Date() });
    } else if (agent.status === 'ready') {
      agent.status = 'busy';
      this.emitEvent({ type: 'busy', agent_id: agentId, timestamp: new Date() });
    }
    
    return true;
  }
  
  /**
   * Complete task for agent
   */
  async completeTask(agentId: string, taskId: string, success: boolean, durationMs: number): Promise<void> {
    const agent = this.agents.get(agentId);
    if (!agent) return;
    
    // Remove from current tasks
    const taskIndex = agent.current_tasks.indexOf(taskId);
    if (taskIndex !== -1) {
      agent.current_tasks.splice(taskIndex, 1);
    }
    
    // Update metrics
    if (success) {
      agent.metrics.tasks_completed++;
    } else {
      agent.metrics.tasks_failed++;
    }
    
    agent.metrics.total_duration_ms += durationMs;
    const totalTasks = agent.metrics.tasks_completed + agent.metrics.tasks_failed;
    agent.metrics.avg_duration_ms = agent.metrics.total_duration_ms / totalTasks;
    agent.metrics.success_rate = agent.metrics.tasks_completed / totalTasks;
    agent.metrics.current_load = agent.current_tasks.length / agent.max_concurrent_tasks;
    agent.metrics.last_task_completed_at = new Date();
    
    // Update status
    if (agent.status !== 'draining') {
      if (agent.current_tasks.length === 0) {
        agent.status = 'ready';
      } else if (agent.metrics.current_load < 1) {
        agent.status = 'busy';
      }
    }
  }
  
  /**
   * Start draining agent (stop accepting new tasks)
   */
  async drain(agentId: string): Promise<{ drained: boolean; remaining_tasks: number }> {
    const agent = this.agents.get(agentId);
    if (!agent) throw new Error(`Agent ${agentId} not found`);
    
    agent.status = 'draining';
    this.emitEvent({ type: 'draining', agent_id: agentId, timestamp: new Date() });
    
    return {
      drained: agent.current_tasks.length === 0,
      remaining_tasks: agent.current_tasks.length,
    };
  }
  
  /**
   * Deregister agent
   */
  async deregister(agentId: string, force: boolean = false): Promise<{ success: boolean; orphaned_tasks: string[] }> {
    const agent = this.agents.get(agentId);
    if (!agent) throw new Error(`Agent ${agentId} not found`);
    
    const orphanedTasks = [...agent.current_tasks];
    
    if (!force && orphanedTasks.length > 0) {
      throw new Error(`Agent ${agentId} has ${orphanedTasks.length} active tasks. Use force=true or drain first.`);
    }
    
    // Clear heartbeat timer
    const timer = this.heartbeatTimers.get(agentId);
    if (timer) {
      clearTimeout(timer);
      this.heartbeatTimers.delete(agentId);
    }
    
    // Remove agent
    this.agents.delete(agentId);
    this.emitEvent({ type: 'deregistered', agent_id: agentId, timestamp: new Date(), details: { orphaned_tasks: orphanedTasks } });
    
    return { success: true, orphaned_tasks: orphanedTasks };
  }
  
  /**
   * Get agent statistics
   */
  getStats(): {
    total_agents: number;
    by_status: Record<AgentStatus, number>;
    total_capacity: number;
    total_load: number;
    avg_success_rate: number;
  } {
    const agents = Array.from(this.agents.values());
    
    const byStatus: Record<AgentStatus, number> = {
      initializing: 0, ready: 0, busy: 0, overloaded: 0, draining: 0, offline: 0, failed: 0
    };
    
    let totalCapacity = 0;
    let totalCurrentTasks = 0;
    let totalSuccessRate = 0;
    let agentsWithTasks = 0;
    
    for (const agent of agents) {
      byStatus[agent.status]++;
      totalCapacity += agent.max_concurrent_tasks;
      totalCurrentTasks += agent.current_tasks.length;
      
      if (agent.metrics.tasks_completed + agent.metrics.tasks_failed > 0) {
        totalSuccessRate += agent.metrics.success_rate;
        agentsWithTasks++;
      }
    }
    
    return {
      total_agents: agents.length,
      by_status: byStatus,
      total_capacity: totalCapacity,
      total_load: totalCapacity > 0 ? totalCurrentTasks / totalCapacity : 0,
      avg_success_rate: agentsWithTasks > 0 ? totalSuccessRate / agentsWithTasks : 1,
    };
  }
  
  /**
   * Subscribe to agent events
   */
  onAgentEvent(agentId: string, callback: (event: AgentEvent) => void): () => void {
    const callbacks = this.eventCallbacks.get(agentId) || [];
    callbacks.push(callback);
    this.eventCallbacks.set(agentId, callbacks);
    
    return () => {
      const cbs = this.eventCallbacks.get(agentId) || [];
      const index = cbs.indexOf(callback);
      if (index !== -1) cbs.splice(index, 1);
    };
  }
  
  /**
   * Subscribe to all agent events
   */
  onAnyAgentEvent(callback: (event: AgentEvent) => void): () => void {
    this.globalEventCallbacks.push(callback);
    
    return () => {
      const index = this.globalEventCallbacks.indexOf(callback);
      if (index !== -1) this.globalEventCallbacks.splice(index, 1);
    };
  }
  
  /**
   * Subscribe to agent going offline/failed
   */
  onAgentDown(callback: (agent: Agent, activeTasks: string[]) => void): () => void {
    return this.onAnyAgentEvent((event) => {
      if (event.type === 'offline' || event.type === 'failed') {
        const agent = this.agents.get(event.agent_id);
        if (agent) {
          callback(agent, [...agent.current_tasks]);
        }
      }
    });
  }
  
  // ===========================================================================
  // Private Methods
  // ===========================================================================
  
  private startHeartbeatMonitor(agentId: string): void {
    const agent = this.agents.get(agentId);
    if (!agent) return;
    
    const timer = setTimeout(() => {
      this.handleHeartbeatTimeout(agentId);
    }, agent.config.heartbeat_timeout_ms);
    
    this.heartbeatTimers.set(agentId, timer);
  }
  
  private resetHeartbeatTimer(agentId: string): void {
    const existing = this.heartbeatTimers.get(agentId);
    if (existing) {
      clearTimeout(existing);
    }
    this.startHeartbeatMonitor(agentId);
  }
  
  private handleHeartbeatTimeout(agentId: string): void {
    const agent = this.agents.get(agentId);
    if (!agent) return;
    
    const wasOnline = agent.status !== 'offline' && agent.status !== 'failed';
    
    if (wasOnline) {
      agent.status = 'offline';
      this.emitEvent({ 
        type: 'offline', 
        agent_id: agentId, 
        timestamp: new Date(),
        details: { last_heartbeat: agent.last_heartbeat }
      });
    }
    
    // Continue monitoring in case agent recovers
    this.startHeartbeatMonitor(agentId);
  }
  
  private emitEvent(event: AgentEvent): void {
    // Agent-specific callbacks
    const callbacks = this.eventCallbacks.get(event.agent_id) || [];
    for (const cb of callbacks) {
      try {
        cb(event);
      } catch (e) {
        // Ignore
      }
    }
    
    // Global callbacks
    for (const cb of this.globalEventCallbacks) {
      try {
        cb(event);
      } catch (e) {
        // Ignore
      }
    }
  }
}

export default AgentRegistry;
