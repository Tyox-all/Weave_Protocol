/**
 * Dōmere - Orchestration Module
 * 
 * Multi-agent coordination infrastructure for AI systems.
 * Provides task scheduling, agent registry, and shared state management.
 */

export * from './scheduler.js';
export * from './registry.js';
export * from './state.js';

import { TaskScheduler, Task, TaskAssignment, TaskResult } from './scheduler.js';
import { AgentRegistry, Agent, AgentEvent } from './registry.js';
import { StateManager, StateChange } from './state.js';

// =============================================================================
// Orchestrator - Unified Interface
// =============================================================================

export interface OrchestratorConfig {
  max_agents?: number;
  default_task_timeout_ms?: number;
  heartbeat_interval_ms?: number;
  state_conflict_resolution?: 'last-write-wins' | 'first-write-wins' | 'merge' | 'manual';
  auto_reassign_on_failure?: boolean;
}

export interface OrchestratorStats {
  agents: {
    total: number;
    ready: number;
    busy: number;
    offline: number;
  };
  tasks: {
    total: number;
    queued: number;
    running: number;
    completed: number;
    failed: number;
  };
  state: {
    keys: number;
    branches: number;
    locks: number;
  };
}

/**
 * Unified orchestrator combining scheduler, registry, and state
 */
export class Orchestrator {
  public readonly scheduler: TaskScheduler;
  public readonly registry: AgentRegistry;
  public readonly state: StateManager;
  
  private config: OrchestratorConfig;
  private running: boolean = false;
  
  constructor(config?: OrchestratorConfig) {
    this.config = {
      max_agents: 16,
      default_task_timeout_ms: 300000,
      heartbeat_interval_ms: 5000,
      state_conflict_resolution: 'last-write-wins',
      auto_reassign_on_failure: true,
      ...config,
    };
    
    // Initialize components
    this.registry = new AgentRegistry({
      heartbeat_interval_ms: this.config.heartbeat_interval_ms,
      heartbeat_timeout_ms: this.config.heartbeat_interval_ms! * 3,
    });
    
    this.scheduler = new TaskScheduler({
      agentGetter: async () => {
        const agents = this.registry.getAllAgents();
        return agents.map(a => ({
          id: a.id,
          available: a.status === 'ready' || a.status === 'busy',
          capabilities: a.capabilities,
          current_load: a.metrics.current_load,
        }));
      },
    });
    
    this.state = new StateManager({
      conflict_resolution: this.config.state_conflict_resolution,
    });
    
    // Wire up event handlers
    this.setupEventHandlers();
  }
  
  /**
   * Start the orchestrator
   */
  async start(): Promise<void> {
    this.running = true;
    console.log('[Orchestrator] Started');
  }
  
  /**
   * Stop the orchestrator
   */
  async stop(): Promise<void> {
    this.running = false;
    
    // Drain all agents
    const agents = this.registry.getAllAgents();
    for (const agent of agents) {
      await this.registry.drain(agent.id);
    }
    
    console.log('[Orchestrator] Stopped');
  }
  
  /**
   * Register an agent
   */
  async registerAgent(params: {
    id?: string;
    name?: string;
    capabilities: string[];
    max_concurrent_tasks?: number;
  }): Promise<Agent> {
    const agents = this.registry.getAllAgents();
    if (agents.length >= this.config.max_agents!) {
      throw new Error(`Maximum agents (${this.config.max_agents}) reached`);
    }
    
    const agent = await this.registry.register({
      agent_id: params.id,
      name: params.name,
      capabilities: params.capabilities,
      max_concurrent_tasks: params.max_concurrent_tasks,
      heartbeat_interval_ms: this.config.heartbeat_interval_ms,
    });
    
    return agent;
  }
  
  /**
   * Submit a task
   */
  async submitTask(params: {
    intent: string;
    priority?: 'critical' | 'high' | 'normal' | 'low' | 'background';
    dependencies?: string[];
    required_capabilities?: string[];
    timeout_ms?: number;
  }): Promise<Task> {
    const task = await this.scheduler.createTask({
      intent: params.intent,
      priority: params.priority,
      dependencies: params.dependencies,
      constraints: {
        required_capabilities: params.required_capabilities,
        max_duration_ms: params.timeout_ms || this.config.default_task_timeout_ms,
      },
    });
    
    // Try to assign immediately if agents available
    try {
      const queued = this.scheduler.getTasksByStatus('queued');
      if (queued.find(t => t.id === task.id)) {
        await this.scheduler.assignTask(task.id);
      }
    } catch (e) {
      // No available agent, will be assigned later
    }
    
    return task;
  }
  
  /**
   * Get orchestrator statistics
   */
  getStats(): OrchestratorStats {
    const agentStats = this.registry.getStats();
    const taskStats = this.scheduler.getStats();
    const stateStats = this.state.getStats();
    
    return {
      agents: {
        total: agentStats.total_agents,
        ready: agentStats.by_status.ready,
        busy: agentStats.by_status.busy,
        offline: agentStats.by_status.offline + agentStats.by_status.failed,
      },
      tasks: {
        total: taskStats.total_tasks,
        queued: taskStats.by_status.queued,
        running: taskStats.by_status.running,
        completed: taskStats.by_status.completed,
        failed: taskStats.by_status.failed,
      },
      state: {
        keys: stateStats.total_keys,
        branches: stateStats.branches,
        locks: stateStats.active_locks,
      },
    };
  }
  
  /**
   * Agent heartbeat (call from agent)
   */
  async heartbeat(agentId: string, currentTasks: string[]): Promise<{ ok: boolean; tasks_to_run?: Task[] }> {
    const result = await this.registry.heartbeat({
      agent_id: agentId,
      current_tasks: currentTasks,
    });
    
    if (!result.acknowledged) {
      return { ok: false };
    }
    
    // Check for new tasks to assign
    const agent = this.registry.getAgent(agentId);
    if (!agent) return { ok: false };
    
    const availableSlots = agent.max_concurrent_tasks - agent.current_tasks.length;
    const tasksToRun: Task[] = [];
    
    for (let i = 0; i < availableSlots; i++) {
      const task = await this.scheduler.getNextTask(agentId, agent.capabilities);
      if (task) {
        await this.scheduler.assignTask(task.id, agentId);
        await this.registry.assignTask(agentId, task.id);
        tasksToRun.push(task);
      } else {
        break;
      }
    }
    
    return { ok: true, tasks_to_run: tasksToRun.length > 0 ? tasksToRun : undefined };
  }
  
  /**
   * Report task started (call from agent)
   */
  async taskStarted(agentId: string, taskId: string): Promise<void> {
    await this.scheduler.startTask(taskId, agentId);
  }
  
  /**
   * Report task progress (call from agent)
   */
  async taskProgress(agentId: string, taskId: string, percent: number, message?: string): Promise<void> {
    await this.scheduler.reportProgress(taskId, agentId, percent, undefined, message);
  }
  
  /**
   * Report task completed (call from agent)
   */
  async taskCompleted(agentId: string, taskId: string, result?: any): Promise<void> {
    const taskResult = await this.scheduler.completeTask(taskId, agentId, result);
    await this.registry.completeTask(agentId, taskId, true, taskResult.duration_ms);
  }
  
  /**
   * Report task failed (call from agent)
   */
  async taskFailed(agentId: string, taskId: string, error: string): Promise<void> {
    const taskResult = await this.scheduler.failTask(taskId, agentId, error);
    await this.registry.completeTask(agentId, taskId, false, taskResult.duration_ms);
  }
  
  // ===========================================================================
  // Event Handlers
  // ===========================================================================
  
  private setupEventHandlers(): void {
    // Handle agent going offline
    this.registry.onAgentDown(async (agent, activeTasks) => {
      console.log(`[Orchestrator] Agent ${agent.id} went down with ${activeTasks.length} active tasks`);
      
      if (this.config.auto_reassign_on_failure) {
        // Release all locks held by agent
        await this.state.releaseAllLocks(agent.id);
        
        // Reassign tasks
        const reassignments = await this.scheduler.reassignFromAgent(agent.id);
        console.log(`[Orchestrator] Reassigned ${reassignments.length} tasks from failed agent`);
      }
    });
    
    // Log task completions
    this.scheduler.onAnyTaskComplete((result) => {
      console.log(`[Orchestrator] Task ${result.task_id} ${result.status} in ${result.duration_ms}ms`);
    });
  }
  
  // ===========================================================================
  // Convenience Methods for State
  // ===========================================================================
  
  /**
   * Get shared state value
   */
  async getState(key: string): Promise<any> {
    return this.state.get(key);
  }
  
  /**
   * Set shared state value (with optional lock)
   */
  async setState(key: string, value: any, agentId: string, options?: { lock?: boolean }): Promise<void> {
    if (options?.lock) {
      const lockResult = await this.state.acquireLock({ key, holder: agentId });
      if (!lockResult.acquired) {
        throw new Error(`Could not acquire lock on ${key}: ${lockResult.reason}`);
      }
    }
    
    await this.state.set(key, value, { agent_id: agentId });
  }
  
  /**
   * Lock state key
   */
  async lockState(key: string, agentId: string, durationMs?: number): Promise<boolean> {
    const result = await this.state.acquireLock({
      key,
      holder: agentId,
      duration_ms: durationMs,
    });
    return result.acquired;
  }
  
  /**
   * Unlock state key
   */
  async unlockState(key: string, agentId: string): Promise<boolean> {
    return this.state.releaseLock(key, agentId);
  }
}

export default Orchestrator;
