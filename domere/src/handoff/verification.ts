/**
 * Dōmere - Multi-Agent Handoff Verification
 * 
 * Secure delegation and verification between AI agents.
 * Ensures chain of custody and authorization in multi-agent systems.
 */

import * as crypto from 'crypto';

// =============================================================================
// Types
// =============================================================================

export interface HandoffToken {
  id: string;
  thread_id: string;
  
  // Delegation chain
  from_agent: string;
  to_agent: string;
  delegation_depth: number;
  parent_handoff_id?: string;
  
  // Intent & constraints
  delegated_intent: string;
  intent_hash: string;
  constraints: string[];
  permissions: Permission[];
  
  // Temporal bounds
  created_at: Date;
  expires_at: Date;
  max_actions?: number;
  
  // Verification
  token: string;
  signature: string;
  status: 'active' | 'used' | 'expired' | 'revoked';
  
  // Tracking
  actions_taken: number;
  verification_count: number;
}

export interface Permission {
  resource: string;
  actions: ('read' | 'write' | 'execute' | 'delegate')[];
  conditions?: Record<string, any>;
}

export interface HandoffVerification {
  valid: boolean;
  handoff_id: string;
  reason?: string;
  remaining_actions?: number;
  expires_in_ms?: number;
  permissions: Permission[];
  constraints: string[];
}

export interface DelegationChain {
  thread_id: string;
  origin_agent: string;
  current_agent: string;
  depth: number;
  handoffs: HandoffToken[];
  total_permissions: Permission[];
  active_constraints: string[];
  integrity_valid: boolean;
}

export interface HandoffPolicy {
  max_delegation_depth: number;
  max_handoff_duration_ms: number;
  require_explicit_permissions: boolean;
  allowed_agents?: string[];
  blocked_agents?: string[];
  default_permissions: Permission[];
  constraint_inheritance: 'strict' | 'additive' | 'none';
}

// =============================================================================
// Handoff Manager
// =============================================================================

export class HandoffManager {
  private handoffs: Map<string, HandoffToken> = new Map();
  private chainsByThread: Map<string, string[]> = new Map();
  private signingKey: Buffer;
  private policy: HandoffPolicy;
  
  constructor(signingKey: string, policy?: Partial<HandoffPolicy>) {
    this.signingKey = crypto.scryptSync(signingKey, 'domere-handoff', 32);
    this.policy = {
      max_delegation_depth: 5,
      max_handoff_duration_ms: 3600000, // 1 hour
      require_explicit_permissions: true,
      default_permissions: [],
      constraint_inheritance: 'strict',
      ...policy,
    };
  }
  
  /**
   * Create a handoff token for delegation
   */
  async createHandoff(params: {
    thread_id: string;
    from_agent: string;
    to_agent: string;
    delegated_intent: string;
    constraints?: string[];
    permissions?: Permission[];
    expires_in_ms?: number;
    max_actions?: number;
    parent_handoff_id?: string;
  }): Promise<HandoffToken> {
    // Validate policy
    if (this.policy.blocked_agents?.includes(params.to_agent)) {
      throw new Error(`Agent ${params.to_agent} is blocked by policy`);
    }
    
    if (this.policy.allowed_agents && !this.policy.allowed_agents.includes(params.to_agent)) {
      throw new Error(`Agent ${params.to_agent} is not in allowed list`);
    }
    
    // Check delegation depth
    let depth = 0;
    let inheritedConstraints: string[] = [];
    let inheritedPermissions: Permission[] = [];
    
    if (params.parent_handoff_id) {
      const parent = this.handoffs.get(params.parent_handoff_id);
      if (!parent) {
        throw new Error(`Parent handoff ${params.parent_handoff_id} not found`);
      }
      if (parent.status !== 'active') {
        throw new Error(`Parent handoff is ${parent.status}`);
      }
      
      depth = parent.delegation_depth + 1;
      
      if (depth > this.policy.max_delegation_depth) {
        throw new Error(`Delegation depth ${depth} exceeds maximum ${this.policy.max_delegation_depth}`);
      }
      
      // Inherit constraints based on policy
      if (this.policy.constraint_inheritance === 'strict') {
        inheritedConstraints = [...parent.constraints];
      } else if (this.policy.constraint_inheritance === 'additive') {
        inheritedConstraints = [...parent.constraints];
      }
      
      // Permissions can only be subset of parent
      inheritedPermissions = parent.permissions;
    }
    
    // Generate token
    const id = `hoff_${crypto.randomUUID()}`;
    const intentHash = crypto.createHash('sha256').update(params.delegated_intent).digest('hex');
    const tokenData = `${id}:${params.from_agent}:${params.to_agent}:${intentHash}:${Date.now()}`;
    const token = crypto.createHash('sha256').update(tokenData).digest('hex');
    
    // Sign token
    const signature = this.sign(token);
    
    // Merge constraints
    const finalConstraints = [...inheritedConstraints, ...(params.constraints || [])];
    
    // Validate permissions against parent
    let finalPermissions = params.permissions || this.policy.default_permissions;
    if (inheritedPermissions.length > 0) {
      finalPermissions = this.intersectPermissions(inheritedPermissions, finalPermissions);
    }
    
    const handoff: HandoffToken = {
      id,
      thread_id: params.thread_id,
      
      from_agent: params.from_agent,
      to_agent: params.to_agent,
      delegation_depth: depth,
      parent_handoff_id: params.parent_handoff_id,
      
      delegated_intent: params.delegated_intent,
      intent_hash: intentHash,
      constraints: finalConstraints,
      permissions: finalPermissions,
      
      created_at: new Date(),
      expires_at: new Date(Date.now() + (params.expires_in_ms || this.policy.max_handoff_duration_ms)),
      max_actions: params.max_actions,
      
      token,
      signature,
      status: 'active',
      
      actions_taken: 0,
      verification_count: 0,
    };
    
    // Store
    this.handoffs.set(id, handoff);
    
    // Track chain
    const chain = this.chainsByThread.get(params.thread_id) || [];
    chain.push(id);
    this.chainsByThread.set(params.thread_id, chain);
    
    return handoff;
  }
  
  /**
   * Verify a handoff token before agent acts
   */
  async verifyHandoff(token: string, agent_id: string): Promise<HandoffVerification> {
    // Find handoff by token
    let handoff: HandoffToken | undefined;
    for (const h of this.handoffs.values()) {
      if (h.token === token) {
        handoff = h;
        break;
      }
    }
    
    if (!handoff) {
      return { valid: false, handoff_id: '', reason: 'Token not found', permissions: [], constraints: [] };
    }
    
    // Verify signature
    if (!this.verifySignature(token, handoff.signature)) {
      return { valid: false, handoff_id: handoff.id, reason: 'Invalid signature', permissions: [], constraints: [] };
    }
    
    // Check status
    if (handoff.status !== 'active') {
      return { valid: false, handoff_id: handoff.id, reason: `Handoff is ${handoff.status}`, permissions: [], constraints: [] };
    }
    
    // Check agent
    if (handoff.to_agent !== agent_id) {
      return { valid: false, handoff_id: handoff.id, reason: `Token issued to ${handoff.to_agent}, not ${agent_id}`, permissions: [], constraints: [] };
    }
    
    // Check expiry
    if (new Date() > handoff.expires_at) {
      handoff.status = 'expired';
      return { valid: false, handoff_id: handoff.id, reason: 'Token expired', permissions: [], constraints: [] };
    }
    
    // Check action limit
    if (handoff.max_actions && handoff.actions_taken >= handoff.max_actions) {
      handoff.status = 'used';
      return { valid: false, handoff_id: handoff.id, reason: 'Action limit reached', permissions: [], constraints: [] };
    }
    
    // Update verification count
    handoff.verification_count++;
    
    return {
      valid: true,
      handoff_id: handoff.id,
      remaining_actions: handoff.max_actions ? handoff.max_actions - handoff.actions_taken : undefined,
      expires_in_ms: handoff.expires_at.getTime() - Date.now(),
      permissions: handoff.permissions,
      constraints: handoff.constraints,
    };
  }
  
  /**
   * Record an action taken under a handoff
   */
  async recordAction(handoffId: string, action: {
    action_type: string;
    action_name: string;
    success: boolean;
  }): Promise<{ allowed: boolean; remaining_actions?: number }> {
    const handoff = this.handoffs.get(handoffId);
    if (!handoff || handoff.status !== 'active') {
      return { allowed: false };
    }
    
    handoff.actions_taken++;
    
    if (handoff.max_actions && handoff.actions_taken >= handoff.max_actions) {
      handoff.status = 'used';
    }
    
    return {
      allowed: true,
      remaining_actions: handoff.max_actions ? handoff.max_actions - handoff.actions_taken : undefined,
    };
  }
  
  /**
   * Revoke a handoff (and all child handoffs)
   */
  async revokeHandoff(handoffId: string, reason?: string): Promise<{ revoked: string[]; reason?: string }> {
    const revoked: string[] = [];
    
    const revoke = (id: string) => {
      const handoff = this.handoffs.get(id);
      if (handoff && handoff.status === 'active') {
        handoff.status = 'revoked';
        revoked.push(id);
        
        // Revoke children
        for (const h of this.handoffs.values()) {
          if (h.parent_handoff_id === id) {
            revoke(h.id);
          }
        }
      }
    };
    
    revoke(handoffId);
    
    return { revoked, reason };
  }
  
  /**
   * Get delegation chain for a thread
   */
  async getDelegationChain(threadId: string): Promise<DelegationChain | null> {
    const handoffIds = this.chainsByThread.get(threadId);
    if (!handoffIds || handoffIds.length === 0) return null;
    
    const handoffs = handoffIds.map(id => this.handoffs.get(id)!).filter(Boolean);
    if (handoffs.length === 0) return null;
    
    // Find origin and current
    const origin = handoffs[0];
    const current = handoffs[handoffs.length - 1];
    
    // Collect active constraints and permissions
    const activeConstraints = [...new Set(handoffs.flatMap(h => h.constraints))];
    const totalPermissions = this.intersectPermissions(
      ...handoffs.map(h => h.permissions)
    );
    
    // Verify chain integrity
    let integrityValid = true;
    for (let i = 1; i < handoffs.length; i++) {
      if (handoffs[i].parent_handoff_id !== handoffs[i - 1].id) {
        integrityValid = false;
        break;
      }
      if (!this.verifySignature(handoffs[i].token, handoffs[i].signature)) {
        integrityValid = false;
        break;
      }
    }
    
    return {
      thread_id: threadId,
      origin_agent: origin.from_agent,
      current_agent: current.to_agent,
      depth: current.delegation_depth,
      handoffs,
      total_permissions: totalPermissions,
      active_constraints: activeConstraints,
      integrity_valid: integrityValid,
    };
  }
  
  /**
   * Check if an action is permitted
   */
  checkPermission(handoffId: string, resource: string, action: 'read' | 'write' | 'execute' | 'delegate'): boolean {
    const handoff = this.handoffs.get(handoffId);
    if (!handoff || handoff.status !== 'active') return false;
    
    for (const perm of handoff.permissions) {
      if (perm.resource === resource || perm.resource === '*') {
        if (perm.actions.includes(action)) {
          return true;
        }
      }
    }
    
    return false;
  }
  
  // ===========================================================================
  // Private Methods
  // ===========================================================================
  
  private sign(data: string): string {
    const hmac = crypto.createHmac('sha256', this.signingKey);
    hmac.update(data);
    return hmac.digest('hex');
  }
  
  private verifySignature(data: string, signature: string): boolean {
    const expected = this.sign(data);
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
  }
  
  private intersectPermissions(...permissionSets: Permission[][]): Permission[] {
    if (permissionSets.length === 0) return [];
    if (permissionSets.length === 1) return permissionSets[0];
    
    const result: Permission[] = [];
    const first = permissionSets[0];
    
    for (const perm of first) {
      let allowed = true;
      let intersectedActions = [...perm.actions];
      
      for (let i = 1; i < permissionSets.length; i++) {
        const matching = permissionSets[i].find(p => p.resource === perm.resource);
        if (!matching) {
          allowed = false;
          break;
        }
        intersectedActions = intersectedActions.filter(a => matching.actions.includes(a));
      }
      
      if (allowed && intersectedActions.length > 0) {
        result.push({ ...perm, actions: intersectedActions as Permission['actions'] });
      }
    }
    
    return result;
  }
}

export default HandoffManager;
