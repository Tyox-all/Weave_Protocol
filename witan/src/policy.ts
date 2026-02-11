/**
 * Witan - Policy Engine
 * 
 * Governance rules, resource quotas, rate limits, and policy enforcement
 * for multi-agent AI systems.
 */

import * as crypto from 'crypto';

// =============================================================================
// Types
// =============================================================================

export type PolicyType = 'rate_limit' | 'quota' | 'permission' | 'schedule' | 'constraint' | 'custom';
export type PolicyScope = 'global' | 'agent' | 'group' | 'task' | 'resource';
export type PolicyAction = 'allow' | 'deny' | 'throttle' | 'warn' | 'audit';
export type EnforcementResult = 'allowed' | 'denied' | 'throttled' | 'warned';

export interface Policy {
  id: string;
  name: string;
  description?: string;
  
  // Classification
  type: PolicyType;
  scope: PolicyScope;
  
  // Targeting
  targets: PolicyTarget[];
  
  // Rules
  rules: PolicyRule[];
  
  // Actions
  default_action: PolicyAction;
  violation_actions: PolicyAction[];
  
  // Status
  enabled: boolean;
  priority: number;  // Higher = evaluated first
  
  // Timing
  created_at: Date;
  updated_at: Date;
  effective_from?: Date;
  effective_until?: Date;
  
  metadata: Record<string, any>;
}

export interface PolicyTarget {
  type: 'agent' | 'group' | 'task_type' | 'resource' | 'all';
  ids?: string[];
  pattern?: string;  // Regex pattern
}

export interface PolicyRule {
  id: string;
  condition: PolicyCondition;
  action: PolicyAction;
  message?: string;
}

export interface PolicyCondition {
  type: 'rate' | 'quota' | 'time' | 'count' | 'property' | 'custom';
  
  // Rate limit conditions
  max_requests?: number;
  window_ms?: number;
  
  // Quota conditions
  max_value?: number;
  resource?: string;
  
  // Time conditions
  allowed_hours?: { start: number; end: number };
  allowed_days?: number[];  // 0-6, Sunday = 0
  
  // Count conditions
  max_concurrent?: number;
  max_total?: number;
  
  // Property conditions
  property?: string;
  operator?: 'eq' | 'neq' | 'gt' | 'gte' | 'lt' | 'lte' | 'contains' | 'matches';
  value?: any;
  
  // Custom
  evaluator?: (context: EvaluationContext) => boolean;
}

export interface EvaluationContext {
  agent_id: string;
  action: string;
  resource?: string;
  properties?: Record<string, any>;
  timestamp: Date;
}

export interface EnforcementDecision {
  allowed: boolean;
  result: EnforcementResult;
  policy_id?: string;
  rule_id?: string;
  message?: string;
  retry_after_ms?: number;
  audit_log?: boolean;
}

export interface PolicyViolation {
  id: string;
  policy_id: string;
  rule_id: string;
  agent_id: string;
  action: string;
  timestamp: Date;
  context: EvaluationContext;
  decision: EnforcementDecision;
}

export interface RateLimitState {
  key: string;
  count: number;
  window_start: Date;
  window_ms: number;
}

export interface QuotaState {
  key: string;
  used: number;
  limit: number;
  reset_at?: Date;
}

// =============================================================================
// Policy Engine
// =============================================================================

export class PolicyEngine {
  private policies: Map<string, Policy> = new Map();
  private rateLimitStates: Map<string, RateLimitState> = new Map();
  private quotaStates: Map<string, QuotaState> = new Map();
  private concurrentCounts: Map<string, number> = new Map();
  private violations: PolicyViolation[] = [];
  private violationCallbacks: ((violation: PolicyViolation) => void)[] = [];
  
  constructor() {
    // Start cleanup timer
    setInterval(() => this.cleanupExpiredStates(), 60000);
  }
  
  // ===========================================================================
  // Policy Management
  // ===========================================================================
  
  /**
   * Create a policy
   */
  async createPolicy(params: {
    name: string;
    description?: string;
    type: PolicyType;
    scope: PolicyScope;
    targets: PolicyTarget[];
    rules: Omit<PolicyRule, 'id'>[];
    default_action?: PolicyAction;
    violation_actions?: PolicyAction[];
    priority?: number;
    enabled?: boolean;
    effective_from?: Date;
    effective_until?: Date;
    metadata?: Record<string, any>;
  }): Promise<Policy> {
    const id = `pol_${crypto.randomUUID()}`;
    const now = new Date();
    
    const policy: Policy = {
      id,
      name: params.name,
      description: params.description,
      
      type: params.type,
      scope: params.scope,
      
      targets: params.targets,
      
      rules: params.rules.map((r, i) => ({
        ...r,
        id: `rule_${i}`,
      })),
      
      default_action: params.default_action || 'allow',
      violation_actions: params.violation_actions || ['deny'],
      
      enabled: params.enabled !== false,
      priority: params.priority || 0,
      
      created_at: now,
      updated_at: now,
      effective_from: params.effective_from,
      effective_until: params.effective_until,
      
      metadata: params.metadata || {},
    };
    
    this.policies.set(id, policy);
    
    return policy;
  }
  
  /**
   * Update a policy
   */
  async updatePolicy(policyId: string, updates: Partial<Omit<Policy, 'id' | 'created_at'>>): Promise<Policy> {
    const policy = this.policies.get(policyId);
    if (!policy) throw new Error(`Policy ${policyId} not found`);
    
    Object.assign(policy, updates, { updated_at: new Date() });
    
    return policy;
  }
  
  /**
   * Delete a policy
   */
  async deletePolicy(policyId: string): Promise<boolean> {
    return this.policies.delete(policyId);
  }
  
  /**
   * Get policy by ID
   */
  getPolicy(policyId: string): Policy | undefined {
    return this.policies.get(policyId);
  }
  
  /**
   * List all policies
   */
  listPolicies(filter?: { type?: PolicyType; scope?: PolicyScope; enabled?: boolean }): Policy[] {
    let policies = Array.from(this.policies.values());
    
    if (filter?.type) {
      policies = policies.filter(p => p.type === filter.type);
    }
    if (filter?.scope) {
      policies = policies.filter(p => p.scope === filter.scope);
    }
    if (filter?.enabled !== undefined) {
      policies = policies.filter(p => p.enabled === filter.enabled);
    }
    
    // Sort by priority (descending)
    policies.sort((a, b) => b.priority - a.priority);
    
    return policies;
  }
  
  // ===========================================================================
  // Convenience Policy Creators
  // ===========================================================================
  
  /**
   * Create a rate limit policy
   */
  async createRateLimit(params: {
    name: string;
    targets: PolicyTarget[];
    max_requests: number;
    window_ms: number;
    action?: PolicyAction;
  }): Promise<Policy> {
    return this.createPolicy({
      name: params.name,
      type: 'rate_limit',
      scope: 'agent',
      targets: params.targets,
      rules: [{
        condition: {
          type: 'rate',
          max_requests: params.max_requests,
          window_ms: params.window_ms,
        },
        action: params.action || 'throttle',
        message: `Rate limit exceeded: ${params.max_requests} requests per ${params.window_ms / 1000}s`,
      }],
      default_action: 'allow',
    });
  }
  
  /**
   * Create a quota policy
   */
  async createQuota(params: {
    name: string;
    targets: PolicyTarget[];
    resource: string;
    max_value: number;
    reset_interval_ms?: number;
  }): Promise<Policy> {
    return this.createPolicy({
      name: params.name,
      type: 'quota',
      scope: 'resource',
      targets: params.targets,
      rules: [{
        condition: {
          type: 'quota',
          resource: params.resource,
          max_value: params.max_value,
        },
        action: 'deny',
        message: `Quota exceeded for ${params.resource}: max ${params.max_value}`,
      }],
      default_action: 'allow',
    });
  }
  
  /**
   * Create a time-based policy
   */
  async createSchedulePolicy(params: {
    name: string;
    targets: PolicyTarget[];
    allowed_hours?: { start: number; end: number };
    allowed_days?: number[];
    action?: PolicyAction;
  }): Promise<Policy> {
    return this.createPolicy({
      name: params.name,
      type: 'schedule',
      scope: 'global',
      targets: params.targets,
      rules: [{
        condition: {
          type: 'time',
          allowed_hours: params.allowed_hours,
          allowed_days: params.allowed_days,
        },
        action: params.action || 'deny',
        message: 'Action not allowed at this time',
      }],
      default_action: 'allow',
    });
  }
  
  /**
   * Create a concurrency limit policy
   */
  async createConcurrencyLimit(params: {
    name: string;
    targets: PolicyTarget[];
    max_concurrent: number;
    resource?: string;
  }): Promise<Policy> {
    return this.createPolicy({
      name: params.name,
      type: 'constraint',
      scope: params.resource ? 'resource' : 'agent',
      targets: params.targets,
      rules: [{
        condition: {
          type: 'count',
          max_concurrent: params.max_concurrent,
        },
        action: 'deny',
        message: `Concurrency limit exceeded: max ${params.max_concurrent}`,
      }],
      default_action: 'allow',
    });
  }
  
  // ===========================================================================
  // Enforcement
  // ===========================================================================
  
  /**
   * Check if an action is allowed
   */
  async enforce(context: EvaluationContext): Promise<EnforcementDecision> {
    const now = context.timestamp || new Date();
    
    // Get applicable policies, sorted by priority
    const applicablePolicies = this.getApplicablePolicies(context);
    
    for (const policy of applicablePolicies) {
      // Check if policy is in effect
      if (policy.effective_from && now < policy.effective_from) continue;
      if (policy.effective_until && now > policy.effective_until) continue;
      
      // Evaluate each rule
      for (const rule of policy.rules) {
        const violated = await this.evaluateCondition(rule.condition, context, policy);
        
        if (violated) {
          const decision = this.createDecision(policy, rule, context);
          
          // Record violation
          if (decision.result === 'denied' || decision.result === 'throttled') {
            this.recordViolation(policy, rule, context, decision);
          }
          
          return decision;
        }
      }
    }
    
    // No policy violations
    return { allowed: true, result: 'allowed' };
  }
  
  /**
   * Record start of a concurrent action
   */
  async startAction(key: string): Promise<void> {
    const current = this.concurrentCounts.get(key) || 0;
    this.concurrentCounts.set(key, current + 1);
  }
  
  /**
   * Record end of a concurrent action
   */
  async endAction(key: string): Promise<void> {
    const current = this.concurrentCounts.get(key) || 0;
    this.concurrentCounts.set(key, Math.max(0, current - 1));
  }
  
  /**
   * Update quota usage
   */
  async updateQuota(key: string, amount: number): Promise<QuotaState | undefined> {
    const state = this.quotaStates.get(key);
    if (state) {
      state.used += amount;
      return state;
    }
    return undefined;
  }
  
  /**
   * Get current quota state
   */
  getQuotaState(key: string): QuotaState | undefined {
    return this.quotaStates.get(key);
  }
  
  /**
   * Reset quota
   */
  async resetQuota(key: string): Promise<void> {
    const state = this.quotaStates.get(key);
    if (state) {
      state.used = 0;
    }
  }
  
  // ===========================================================================
  // Violations
  // ===========================================================================
  
  /**
   * Get violations
   */
  getViolations(filter?: {
    policy_id?: string;
    agent_id?: string;
    since?: Date;
    limit?: number;
  }): PolicyViolation[] {
    let violations = [...this.violations];
    
    if (filter?.policy_id) {
      violations = violations.filter(v => v.policy_id === filter.policy_id);
    }
    if (filter?.agent_id) {
      violations = violations.filter(v => v.agent_id === filter.agent_id);
    }
    if (filter?.since) {
      violations = violations.filter(v => v.timestamp >= filter.since!);
    }
    
    // Sort by timestamp descending
    violations.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
    
    if (filter?.limit) {
      violations = violations.slice(0, filter.limit);
    }
    
    return violations;
  }
  
  /**
   * Subscribe to violations
   */
  onViolation(callback: (violation: PolicyViolation) => void): () => void {
    this.violationCallbacks.push(callback);
    return () => {
      const index = this.violationCallbacks.indexOf(callback);
      if (index !== -1) this.violationCallbacks.splice(index, 1);
    };
  }
  
  // ===========================================================================
  // Statistics
  // ===========================================================================
  
  /**
   * Get policy engine statistics
   */
  getStats(): {
    total_policies: number;
    active_policies: number;
    total_violations: number;
    violations_last_hour: number;
    rate_limit_states: number;
    quota_states: number;
  } {
    const oneHourAgo = new Date(Date.now() - 3600000);
    const recentViolations = this.violations.filter(v => v.timestamp >= oneHourAgo);
    
    return {
      total_policies: this.policies.size,
      active_policies: Array.from(this.policies.values()).filter(p => p.enabled).length,
      total_violations: this.violations.length,
      violations_last_hour: recentViolations.length,
      rate_limit_states: this.rateLimitStates.size,
      quota_states: this.quotaStates.size,
    };
  }
  
  // ===========================================================================
  // Private Methods
  // ===========================================================================
  
  private getApplicablePolicies(context: EvaluationContext): Policy[] {
    const applicable: Policy[] = [];
    
    for (const policy of this.policies.values()) {
      if (!policy.enabled) continue;
      
      // Check if any target matches
      const matches = policy.targets.some(target => {
        if (target.type === 'all') return true;
        
        if (target.type === 'agent' && target.ids) {
          return target.ids.includes(context.agent_id);
        }
        
        if (target.type === 'resource' && target.ids && context.resource) {
          return target.ids.includes(context.resource);
        }
        
        if (target.pattern) {
          const regex = new RegExp(target.pattern);
          if (target.type === 'agent') return regex.test(context.agent_id);
          if (target.type === 'resource' && context.resource) return regex.test(context.resource);
        }
        
        return false;
      });
      
      if (matches) {
        applicable.push(policy);
      }
    }
    
    // Sort by priority (descending)
    applicable.sort((a, b) => b.priority - a.priority);
    
    return applicable;
  }
  
  private async evaluateCondition(
    condition: PolicyCondition,
    context: EvaluationContext,
    policy: Policy
  ): Promise<boolean> {
    switch (condition.type) {
      case 'rate':
        return this.evaluateRateLimit(condition, context, policy);
      
      case 'quota':
        return this.evaluateQuota(condition, context);
      
      case 'time':
        return this.evaluateTimeCondition(condition, context);
      
      case 'count':
        return this.evaluateConcurrency(condition, context);
      
      case 'property':
        return this.evaluateProperty(condition, context);
      
      case 'custom':
        return condition.evaluator ? condition.evaluator(context) : false;
      
      default:
        return false;
    }
  }
  
  private evaluateRateLimit(condition: PolicyCondition, context: EvaluationContext, policy: Policy): boolean {
    const key = `rate:${policy.id}:${context.agent_id}`;
    const now = Date.now();
    const windowMs = condition.window_ms || 60000;
    
    let state = this.rateLimitStates.get(key);
    
    if (!state || (now - state.window_start.getTime()) > state.window_ms) {
      // Start new window
      state = {
        key,
        count: 0,
        window_start: new Date(),
        window_ms: windowMs,
      };
      this.rateLimitStates.set(key, state);
    }
    
    state.count++;
    
    return state.count > (condition.max_requests || Infinity);
  }
  
  private evaluateQuota(condition: PolicyCondition, context: EvaluationContext): boolean {
    const resource = condition.resource || 'default';
    const key = `quota:${context.agent_id}:${resource}`;
    
    let state = this.quotaStates.get(key);
    
    if (!state) {
      state = {
        key,
        used: 0,
        limit: condition.max_value || Infinity,
      };
      this.quotaStates.set(key, state);
    }
    
    return state.used >= state.limit;
  }
  
  private evaluateTimeCondition(condition: PolicyCondition, context: EvaluationContext): boolean {
    const now = context.timestamp;
    const hours = now.getHours();
    const day = now.getDay();
    
    // Check allowed hours
    if (condition.allowed_hours) {
      const { start, end } = condition.allowed_hours;
      if (start <= end) {
        if (hours < start || hours >= end) return true;  // Violated
      } else {
        // Wraps around midnight
        if (hours < start && hours >= end) return true;  // Violated
      }
    }
    
    // Check allowed days
    if (condition.allowed_days) {
      if (!condition.allowed_days.includes(day)) return true;  // Violated
    }
    
    return false;
  }
  
  private evaluateConcurrency(condition: PolicyCondition, context: EvaluationContext): boolean {
    const key = `concurrent:${context.agent_id}:${context.action}`;
    const current = this.concurrentCounts.get(key) || 0;
    
    return current >= (condition.max_concurrent || Infinity);
  }
  
  private evaluateProperty(condition: PolicyCondition, context: EvaluationContext): boolean {
    if (!condition.property || !context.properties) return false;
    
    const value = context.properties[condition.property];
    const target = condition.value;
    
    switch (condition.operator) {
      case 'eq': return value === target;
      case 'neq': return value !== target;
      case 'gt': return value > target;
      case 'gte': return value >= target;
      case 'lt': return value < target;
      case 'lte': return value <= target;
      case 'contains': return String(value).includes(String(target));
      case 'matches': return new RegExp(target).test(String(value));
      default: return false;
    }
  }
  
  private createDecision(policy: Policy, rule: PolicyRule, context: EvaluationContext): EnforcementDecision {
    const action = rule.action;
    
    switch (action) {
      case 'deny':
        return {
          allowed: false,
          result: 'denied',
          policy_id: policy.id,
          rule_id: rule.id,
          message: rule.message,
        };
      
      case 'throttle':
        // Calculate retry time
        const state = this.rateLimitStates.get(`rate:${policy.id}:${context.agent_id}`);
        const retryAfter = state 
          ? state.window_ms - (Date.now() - state.window_start.getTime())
          : 1000;
        
        return {
          allowed: false,
          result: 'throttled',
          policy_id: policy.id,
          rule_id: rule.id,
          message: rule.message,
          retry_after_ms: Math.max(0, retryAfter),
        };
      
      case 'warn':
        return {
          allowed: true,
          result: 'warned',
          policy_id: policy.id,
          rule_id: rule.id,
          message: rule.message,
          audit_log: true,
        };
      
      case 'audit':
        return {
          allowed: true,
          result: 'allowed',
          policy_id: policy.id,
          rule_id: rule.id,
          audit_log: true,
        };
      
      default:
        return { allowed: true, result: 'allowed' };
    }
  }
  
  private recordViolation(
    policy: Policy,
    rule: PolicyRule,
    context: EvaluationContext,
    decision: EnforcementDecision
  ): void {
    const violation: PolicyViolation = {
      id: `viol_${crypto.randomUUID()}`,
      policy_id: policy.id,
      rule_id: rule.id,
      agent_id: context.agent_id,
      action: context.action,
      timestamp: new Date(),
      context,
      decision,
    };
    
    this.violations.push(violation);
    
    // Notify callbacks
    for (const cb of this.violationCallbacks) {
      try {
        cb(violation);
      } catch (e) {
        // Ignore
      }
    }
  }
  
  private cleanupExpiredStates(): void {
    const now = Date.now();
    
    // Cleanup rate limit states
    for (const [key, state] of this.rateLimitStates) {
      if ((now - state.window_start.getTime()) > state.window_ms * 2) {
        this.rateLimitStates.delete(key);
      }
    }
    
    // Cleanup quota states with reset times
    for (const [key, state] of this.quotaStates) {
      if (state.reset_at && new Date() > state.reset_at) {
        state.used = 0;
        state.reset_at = undefined;
      }
    }
  }
}

export default PolicyEngine;
