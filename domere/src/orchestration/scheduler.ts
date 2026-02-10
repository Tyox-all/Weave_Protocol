/**
 * Dōmere - Task Scheduler
 * 
 * Distributed task scheduling for multi-agent AI orchestration.
 * Handles dependencies, priorities, load balancing, and failure recovery.
 */

import * as crypto from 'crypto';

// =============================================================================
// Types
// =============================================================================

export type TaskStatus = 'pending' | 'queued' | 'assigned' | 'running' | 'completed' | 'failed' | 'cancelled' | 'blocked';
export type TaskPriority = 'critical' | 'high' | 'normal' | 'low' | 'background';

export interface Task {
  id: string;
  thread_id?: string;
  
  // Definition
  intent: string;
  intent_hash: string;
  description?: string;
  
  // Scheduling
  priority: TaskPriority;
  status: TaskStatus;
  dependencies: string[];  // Task IDs that must complete first
  dependents: string[];    // Tasks waiting on this one
  
  // Assignment
  assigned_agent?: string;
  assignment_time?: Date;
  
  // Constraints
  constraints: TaskConstraints;
  
  // Retry
  retry_policy: RetryPolicy;
  attempt_count: number;
  last_error?: string;
  
  // Timing
  created_at: Date;
  started_at?: Date;
  completed_at?: Date;
  deadline?: Date;
  
  // Results
  result?: any;
  result_hash?: string;
  
  // Metadata
  metadata: Record<string, any>;
}

export interface TaskConstraints {
  max_duration_ms?: number;
  required_capabilities?: string[];
  preferred_agents?: string[];
  excluded_agents?: string[];
  exclusive_resources?: string[];  // Resources this task needs exclusively
  max_concurrent?: number;         // Max instances of this task type
}

export interface RetryPolicy {
  max_retries: number;
  backoff: 'none' | 'linear' | 'exponential';
  base_delay_ms: number;
  max_delay_ms: number;
}

export interface TaskAssignment {
  task_id: string;
  agent_id: string;
  assigned_at: Date;
  reason: string;
  estimated_duration_ms?: number;
}

export interface TaskProgress {
  task_id: string;
  agent_id: string;
  percent: number;
  stage?: string;
  message?: string;
  updated_at: Date;
}

export interface TaskResult {
  task_id: string;
  status: 'completed' | 'failed';
  result?: any;
  error?: string;
  duration_ms: number;
  agent_id: string;
  completed_at: Date;
}

export interface SchedulerStats {
  total_tasks: number;
  by_status: Record<TaskStatus, number>;
  by_priority: Record<TaskPriority, number>;
  avg_wait_time_ms: number;
  avg_duration_ms: number;
  throughput_per_minute: number;
}

// =============================================================================
// Task Scheduler
// =============================================================================

export class TaskScheduler {
  private tasks: Map<string, Task> = new Map();
  private queue: string[] = [];  // Task IDs in priority order
  private resourceLocks: Map<string, string> = new Map();  // resource -> task_id
  private progressCallbacks: Map<string, ((progress: TaskProgress) => void)[]> = new Map();
  private completionCallbacks: Map<string, ((result: TaskResult) => void)[]> = new Map();
  private globalCompletionCallbacks: ((result: TaskResult) => void)[] = [];
  
  private agentGetter?: () => Promise<AgentInfo[]>;
  
  constructor(options?: {
    agentGetter?: () => Promise<AgentInfo[]>;
  }) {
    this.agentGetter = options?.agentGetter;
  }
  
  /**
   * Create a new task
   */
  async createTask(params: {
    intent: string;
    thread_id?: string;
    description?: string;
    priority?: TaskPriority;
    dependencies?: string[];
    constraints?: Partial<TaskConstraints>;
    retry_policy?: Partial<RetryPolicy>;
    deadline?: Date;
    metadata?: Record<string, any>;
  }): Promise<Task> {
    const id = `task_${crypto.randomUUID()}`;
    const intentHash = crypto.createHash('sha256').update(params.intent).digest('hex');
    
    // Validate dependencies exist
    for (const depId of params.dependencies || []) {
      if (!this.tasks.has(depId)) {
        throw new Error(`Dependency task ${depId} not found`);
      }
    }
    
    const task: Task = {
      id,
      thread_id: params.thread_id,
      
      intent: params.intent,
      intent_hash: intentHash,
      description: params.description,
      
      priority: params.priority || 'normal',
      status: 'pending',
      dependencies: params.dependencies || [],
      dependents: [],
      
      constraints: {
        max_duration_ms: 300000,  // 5 min default
        required_capabilities: [],
        preferred_agents: [],
        excluded_agents: [],
        exclusive_resources: [],
        max_concurrent: 0,  // No limit
        ...params.constraints,
      },
      
      retry_policy: {
        max_retries: 3,
        backoff: 'exponential',
        base_delay_ms: 1000,
        max_delay_ms: 30000,
        ...params.retry_policy,
      },
      
      attempt_count: 0,
      created_at: new Date(),
      deadline: params.deadline,
      metadata: params.metadata || {},
    };
    
    // Register as dependent on dependencies
    for (const depId of task.dependencies) {
      const dep = this.tasks.get(depId)!;
      dep.dependents.push(id);
    }
    
    this.tasks.set(id, task);
    
    // Check if ready to queue
    await this.evaluateTask(id);
    
    return task;
  }
  
  /**
   * Get a task by ID
   */
  getTask(taskId: string): Task | undefined {
    return this.tasks.get(taskId);
  }
  
  /**
   * Get all tasks
   */
  getAllTasks(): Task[] {
    return Array.from(this.tasks.values());
  }
  
  /**
   * Get tasks by status
   */
  getTasksByStatus(status: TaskStatus): Task[] {
    return Array.from(this.tasks.values()).filter(t => t.status === status);
  }
  
  /**
   * Evaluate if task can be queued (dependencies met)
   */
  private async evaluateTask(taskId: string): Promise<void> {
    const task = this.tasks.get(taskId);
    if (!task || task.status !== 'pending') return;
    
    // Check all dependencies are completed
    const depsComplete = task.dependencies.every(depId => {
      const dep = this.tasks.get(depId);
      return dep && dep.status === 'completed';
    });
    
    if (depsComplete) {
      task.status = 'queued';
      this.insertIntoQueue(taskId);
    } else {
      task.status = 'blocked';
    }
  }
  
  /**
   * Insert task into priority queue
   */
  private insertIntoQueue(taskId: string): void {
    const task = this.tasks.get(taskId)!;
    const priorityOrder: TaskPriority[] = ['critical', 'high', 'normal', 'low', 'background'];
    const taskPriorityIndex = priorityOrder.indexOf(task.priority);
    
    // Find insertion point
    let insertIndex = this.queue.length;
    for (let i = 0; i < this.queue.length; i++) {
      const queuedTask = this.tasks.get(this.queue[i])!;
      const queuedPriorityIndex = priorityOrder.indexOf(queuedTask.priority);
      
      if (taskPriorityIndex < queuedPriorityIndex) {
        insertIndex = i;
        break;
      }
      
      // Same priority: earlier deadline wins
      if (taskPriorityIndex === queuedPriorityIndex && task.deadline && queuedTask.deadline) {
        if (task.deadline < queuedTask.deadline) {
          insertIndex = i;
          break;
        }
      }
    }
    
    this.queue.splice(insertIndex, 0, taskId);
  }
  
  /**
   * Get next task for an agent
   */
  async getNextTask(agentId: string, capabilities: string[] = []): Promise<Task | null> {
    for (let i = 0; i < this.queue.length; i++) {
      const taskId = this.queue[i];
      const task = this.tasks.get(taskId)!;
      
      // Check excluded agents
      if (task.constraints.excluded_agents?.includes(agentId)) continue;
      
      // Check required capabilities
      if (task.constraints.required_capabilities?.length) {
        const hasAll = task.constraints.required_capabilities.every(c => capabilities.includes(c));
        if (!hasAll) continue;
      }
      
      // Check resource availability
      if (task.constraints.exclusive_resources?.length) {
        const resourcesAvailable = task.constraints.exclusive_resources.every(r => !this.resourceLocks.has(r));
        if (!resourcesAvailable) continue;
      }
      
      // Check max concurrent
      if (task.constraints.max_concurrent && task.constraints.max_concurrent > 0) {
        const running = Array.from(this.tasks.values()).filter(
          t => t.intent_hash === task.intent_hash && t.status === 'running'
        ).length;
        if (running >= task.constraints.max_concurrent) continue;
      }
      
      // Found suitable task
      return task;
    }
    
    return null;
  }
  
  /**
   * Assign a task to an agent
   */
  async assignTask(taskId: string, agentId?: string): Promise<TaskAssignment> {
    const task = this.tasks.get(taskId);
    if (!task) throw new Error(`Task ${taskId} not found`);
    if (task.status !== 'queued') throw new Error(`Task ${taskId} is ${task.status}, not queued`);
    
    // Auto-select agent if not specified
    let selectedAgent = agentId;
    let reason = 'Manual assignment';
    
    if (!selectedAgent && this.agentGetter) {
      const agents = await this.agentGetter();
      const suitable = agents.filter(a => {
        if (!a.available) return false;
        if (task.constraints.excluded_agents?.includes(a.id)) return false;
        if (task.constraints.required_capabilities?.length) {
          return task.constraints.required_capabilities.every(c => a.capabilities.includes(c));
        }
        return true;
      });
      
      if (suitable.length === 0) {
        throw new Error('No suitable agents available');
      }
      
      // Prefer agents with lower load
      suitable.sort((a, b) => a.current_load - b.current_load);
      
      // Check preferred agents
      if (task.constraints.preferred_agents?.length) {
        const preferred = suitable.find(a => task.constraints.preferred_agents!.includes(a.id));
        if (preferred) {
          selectedAgent = preferred.id;
          reason = 'Preferred agent available';
        }
      }
      
      if (!selectedAgent) {
        selectedAgent = suitable[0].id;
        reason = 'Lowest load agent';
      }
    }
    
    if (!selectedAgent) {
      throw new Error('No agent specified and no agent getter configured');
    }
    
    // Lock resources
    for (const resource of task.constraints.exclusive_resources || []) {
      this.resourceLocks.set(resource, taskId);
    }
    
    // Update task
    task.status = 'assigned';
    task.assigned_agent = selectedAgent;
    task.assignment_time = new Date();
    
    // Remove from queue
    const queueIndex = this.queue.indexOf(taskId);
    if (queueIndex !== -1) {
      this.queue.splice(queueIndex, 1);
    }
    
    return {
      task_id: taskId,
      agent_id: selectedAgent,
      assigned_at: task.assignment_time,
      reason,
    };
  }
  
  /**
   * Mark task as started
   */
  async startTask(taskId: string, agentId: string): Promise<void> {
    const task = this.tasks.get(taskId);
    if (!task) throw new Error(`Task ${taskId} not found`);
    
    if (task.assigned_agent !== agentId) {
      throw new Error(`Task ${taskId} is assigned to ${task.assigned_agent}, not ${agentId}`);
    }
    
    task.status = 'running';
    task.started_at = new Date();
    task.attempt_count++;
  }
  
  /**
   * Report task progress
   */
  async reportProgress(taskId: string, agentId: string, percent: number, stage?: string, message?: string): Promise<void> {
    const task = this.tasks.get(taskId);
    if (!task) throw new Error(`Task ${taskId} not found`);
    
    const progress: TaskProgress = {
      task_id: taskId,
      agent_id: agentId,
      percent: Math.min(100, Math.max(0, percent)),
      stage,
      message,
      updated_at: new Date(),
    };
    
    // Notify callbacks
    const callbacks = this.progressCallbacks.get(taskId) || [];
    for (const cb of callbacks) {
      try {
        cb(progress);
      } catch (e) {
        // Ignore callback errors
      }
    }
  }
  
  /**
   * Complete a task
   */
  async completeTask(taskId: string, agentId: string, result?: any): Promise<TaskResult> {
    const task = this.tasks.get(taskId);
    if (!task) throw new Error(`Task ${taskId} not found`);
    
    const now = new Date();
    const duration = task.started_at ? now.getTime() - task.started_at.getTime() : 0;
    
    task.status = 'completed';
    task.completed_at = now;
    task.result = result;
    task.result_hash = result ? crypto.createHash('sha256').update(JSON.stringify(result)).digest('hex') : undefined;
    
    // Release resources
    for (const resource of task.constraints.exclusive_resources || []) {
      this.resourceLocks.delete(resource);
    }
    
    // Evaluate dependents
    for (const depId of task.dependents) {
      await this.evaluateTask(depId);
    }
    
    const taskResult: TaskResult = {
      task_id: taskId,
      status: 'completed',
      result,
      duration_ms: duration,
      agent_id: agentId,
      completed_at: now,
    };
    
    // Notify callbacks
    this.notifyCompletion(taskResult);
    
    return taskResult;
  }
  
  /**
   * Fail a task
   */
  async failTask(taskId: string, agentId: string, error: string): Promise<TaskResult> {
    const task = this.tasks.get(taskId);
    if (!task) throw new Error(`Task ${taskId} not found`);
    
    const now = new Date();
    const duration = task.started_at ? now.getTime() - task.started_at.getTime() : 0;
    
    task.last_error = error;
    
    // Release resources
    for (const resource of task.constraints.exclusive_resources || []) {
      this.resourceLocks.delete(resource);
    }
    
    // Check if should retry
    if (task.attempt_count < task.retry_policy.max_retries) {
      // Calculate backoff
      let delay = task.retry_policy.base_delay_ms;
      if (task.retry_policy.backoff === 'linear') {
        delay = task.retry_policy.base_delay_ms * task.attempt_count;
      } else if (task.retry_policy.backoff === 'exponential') {
        delay = task.retry_policy.base_delay_ms * Math.pow(2, task.attempt_count - 1);
      }
      delay = Math.min(delay, task.retry_policy.max_delay_ms);
      
      // Requeue after delay
      task.status = 'pending';
      task.assigned_agent = undefined;
      task.assignment_time = undefined;
      task.started_at = undefined;
      
      setTimeout(() => {
        this.evaluateTask(taskId);
      }, delay);
      
      return {
        task_id: taskId,
        status: 'failed',
        error: `${error} (retry ${task.attempt_count}/${task.retry_policy.max_retries} in ${delay}ms)`,
        duration_ms: duration,
        agent_id: agentId,
        completed_at: now,
      };
    }
    
    // Final failure
    task.status = 'failed';
    task.completed_at = now;
    
    const taskResult: TaskResult = {
      task_id: taskId,
      status: 'failed',
      error,
      duration_ms: duration,
      agent_id: agentId,
      completed_at: now,
    };
    
    // Notify callbacks
    this.notifyCompletion(taskResult);
    
    return taskResult;
  }
  
  /**
   * Cancel a task
   */
  async cancelTask(taskId: string, reason?: string): Promise<void> {
    const task = this.tasks.get(taskId);
    if (!task) throw new Error(`Task ${taskId} not found`);
    
    task.status = 'cancelled';
    task.last_error = reason || 'Cancelled';
    task.completed_at = new Date();
    
    // Release resources
    for (const resource of task.constraints.exclusive_resources || []) {
      this.resourceLocks.delete(resource);
    }
    
    // Remove from queue
    const queueIndex = this.queue.indexOf(taskId);
    if (queueIndex !== -1) {
      this.queue.splice(queueIndex, 1);
    }
  }
  
  /**
   * Reassign tasks from a failed agent
   */
  async reassignFromAgent(agentId: string): Promise<TaskAssignment[]> {
    const assignments: TaskAssignment[] = [];
    
    const agentTasks = Array.from(this.tasks.values()).filter(
      t => t.assigned_agent === agentId && (t.status === 'assigned' || t.status === 'running')
    );
    
    for (const task of agentTasks) {
      // Release resources
      for (const resource of task.constraints.exclusive_resources || []) {
        this.resourceLocks.delete(resource);
      }
      
      // Re-queue
      task.status = 'queued';
      task.assigned_agent = undefined;
      task.assignment_time = undefined;
      task.started_at = undefined;
      task.constraints.excluded_agents = [...(task.constraints.excluded_agents || []), agentId];
      
      this.insertIntoQueue(task.id);
      
      // Try to reassign
      if (this.agentGetter) {
        try {
          const assignment = await this.assignTask(task.id);
          assignments.push(assignment);
        } catch (e) {
          // Will stay in queue
        }
      }
    }
    
    return assignments;
  }
  
  /**
   * Update task priority
   */
  async updatePriority(taskId: string, priority: TaskPriority): Promise<void> {
    const task = this.tasks.get(taskId);
    if (!task) throw new Error(`Task ${taskId} not found`);
    
    const oldPriority = task.priority;
    task.priority = priority;
    
    // Re-sort queue if task is queued
    if (task.status === 'queued') {
      const queueIndex = this.queue.indexOf(taskId);
      if (queueIndex !== -1) {
        this.queue.splice(queueIndex, 1);
        this.insertIntoQueue(taskId);
      }
    }
  }
  
  /**
   * Subscribe to task progress
   */
  onTaskProgress(taskId: string, callback: (progress: TaskProgress) => void): () => void {
    const callbacks = this.progressCallbacks.get(taskId) || [];
    callbacks.push(callback);
    this.progressCallbacks.set(taskId, callbacks);
    
    return () => {
      const cbs = this.progressCallbacks.get(taskId) || [];
      const index = cbs.indexOf(callback);
      if (index !== -1) cbs.splice(index, 1);
    };
  }
  
  /**
   * Subscribe to task completion
   */
  onTaskComplete(taskId: string, callback: (result: TaskResult) => void): () => void {
    const callbacks = this.completionCallbacks.get(taskId) || [];
    callbacks.push(callback);
    this.completionCallbacks.set(taskId, callbacks);
    
    return () => {
      const cbs = this.completionCallbacks.get(taskId) || [];
      const index = cbs.indexOf(callback);
      if (index !== -1) cbs.splice(index, 1);
    };
  }
  
  /**
   * Subscribe to all task completions
   */
  onAnyTaskComplete(callback: (result: TaskResult) => void): () => void {
    this.globalCompletionCallbacks.push(callback);
    
    return () => {
      const index = this.globalCompletionCallbacks.indexOf(callback);
      if (index !== -1) this.globalCompletionCallbacks.splice(index, 1);
    };
  }
  
  private notifyCompletion(result: TaskResult): void {
    // Task-specific callbacks
    const callbacks = this.completionCallbacks.get(result.task_id) || [];
    for (const cb of callbacks) {
      try {
        cb(result);
      } catch (e) {
        // Ignore
      }
    }
    
    // Global callbacks
    for (const cb of this.globalCompletionCallbacks) {
      try {
        cb(result);
      } catch (e) {
        // Ignore
      }
    }
  }
  
  /**
   * Get scheduler statistics
   */
  getStats(): SchedulerStats {
    const tasks = Array.from(this.tasks.values());
    const completed = tasks.filter(t => t.status === 'completed');
    
    const byStatus: Record<TaskStatus, number> = {
      pending: 0, queued: 0, assigned: 0, running: 0,
      completed: 0, failed: 0, cancelled: 0, blocked: 0
    };
    
    const byPriority: Record<TaskPriority, number> = {
      critical: 0, high: 0, normal: 0, low: 0, background: 0
    };
    
    let totalWaitTime = 0;
    let totalDuration = 0;
    
    for (const task of tasks) {
      byStatus[task.status]++;
      byPriority[task.priority]++;
      
      if (task.started_at) {
        totalWaitTime += task.started_at.getTime() - task.created_at.getTime();
      }
      if (task.completed_at && task.started_at) {
        totalDuration += task.completed_at.getTime() - task.started_at.getTime();
      }
    }
    
    // Calculate throughput (completed in last minute)
    const oneMinuteAgo = new Date(Date.now() - 60000);
    const recentCompleted = completed.filter(t => t.completed_at && t.completed_at > oneMinuteAgo).length;
    
    return {
      total_tasks: tasks.length,
      by_status: byStatus,
      by_priority: byPriority,
      avg_wait_time_ms: completed.length > 0 ? totalWaitTime / completed.length : 0,
      avg_duration_ms: completed.length > 0 ? totalDuration / completed.length : 0,
      throughput_per_minute: recentCompleted,
    };
  }
  
  /**
   * Get queue status
   */
  getQueueStatus(): { length: number; tasks: Task[] } {
    return {
      length: this.queue.length,
      tasks: this.queue.map(id => this.tasks.get(id)!),
    };
  }
}

// Helper interface for agent info
interface AgentInfo {
  id: string;
  available: boolean;
  capabilities: string[];
  current_load: number;
}

export default TaskScheduler;
