/**
 * Hord - The Vault Protocol
 * Capability Token System
 * 
 * Fine-grained, cryptographically-signed access control tokens.
 */

import type {
  CapabilityToken,
  CapabilityTokenConfig,
  CapabilityConstraints,
  ResourceDescriptor,
  ActionType,
  DelegationRequest,
  IHordStorage,
  DataClassification,
} from '../types.js';
import { CapabilityError, ActionType as AT, DataClassification as DC } from '../types.js';
import { CAPABILITY, canAccessClassification } from '../constants.js';
import { generateId, hmacSign, hmacVerify, keyStore } from '../vault/encryption.js';

// ============================================================================
// Capability Token Manager
// ============================================================================

export class CapabilityManager {
  private storage: IHordStorage;
  
  constructor(storage: IHordStorage) {
    this.storage = storage;
  }
  
  /**
   * Create a new capability token
   */
  async createCapabilityToken(config: CapabilityTokenConfig): Promise<CapabilityToken> {
    if (!keyStore.isInitialized()) {
      throw new CapabilityError('Key store not initialized');
    }
    
    const now = new Date();
    const defaultValidUntil = new Date(now.getTime() + CAPABILITY.DEFAULT_VALIDITY_HOURS * 60 * 60 * 1000);
    
    // Build constraints with defaults
    const constraints: CapabilityConstraints = {
      valid_from: config.constraints?.valid_from || now,
      valid_until: config.constraints?.valid_until || defaultValidUntil,
      max_uses: config.constraints?.max_uses,
      current_uses: 0,
      rate_limit: config.constraints?.rate_limit,
      requires_attestation: config.constraints?.requires_attestation || false,
      allowed_contexts: config.constraints?.allowed_contexts,
      data_classification_max: config.constraints?.data_classification_max || DC.CONFIDENTIAL,
      ip_allowlist: config.constraints?.ip_allowlist,
      requires_mfa: config.constraints?.requires_mfa || false,
    };
    
    // Validate constraints
    this.validateConstraints(constraints);
    
    // Create token
    const tokenId = generateId(CAPABILITY.TOKEN_PREFIX);
    
    const tokenData = {
      id: tokenId,
      agent_id: config.agent_id,
      resource: config.resource,
      actions: config.actions,
      constraints,
      delegatable: config.delegatable || false,
      delegation_depth: 0,
      issued_at: now,
      issuer: 'hord',
      version: CAPABILITY.TOKEN_VERSION,
    };
    
    // Sign the token
    const signature = this.signToken(tokenData);
    
    const token: CapabilityToken = {
      ...tokenData,
      signature,
      revoked: false,
      uses: 0,
    };
    
    // Store token
    await this.storage.saveCapabilityToken(token);
    
    // Log
    await this.storage.logAccess({
      id: generateId('log_'),
      timestamp: now,
      agent_id: config.agent_id,
      action: 'create_capability',
      resource: this.resourceToString(config.resource),
      capability_token_id: tokenId,
      success: true,
      context: { justification: config.justification },
    });
    
    return token;
  }
  
  /**
   * Verify a capability token
   */
  async verifyCapabilityToken(
    tokenId: string,
    agentId: string,
    resource: ResourceDescriptor,
    action: ActionType,
    context?: string
  ): Promise<{ valid: boolean; reason?: string }> {
    // Get token
    const token = await this.storage.getCapabilityToken(tokenId);
    if (!token) {
      return { valid: false, reason: 'Token not found' };
    }
    
    // Check if revoked
    if (token.revoked) {
      return { valid: false, reason: 'Token has been revoked' };
    }
    
    // Verify signature
    if (!this.verifyTokenSignature(token)) {
      return { valid: false, reason: 'Invalid token signature' };
    }
    
    // Check agent
    if (token.agent_id !== agentId) {
      return { valid: false, reason: 'Token belongs to different agent' };
    }
    
    // Check resource
    if (!this.resourceMatches(token.resource, resource)) {
      return { valid: false, reason: 'Resource does not match token' };
    }
    
    // Check action
    if (!token.actions.includes(action)) {
      return { valid: false, reason: `Action '${action}' not permitted by token` };
    }
    
    // Check time validity
    const now = new Date();
    if (now < token.constraints.valid_from) {
      return { valid: false, reason: 'Token not yet valid' };
    }
    if (now > token.constraints.valid_until) {
      return { valid: false, reason: 'Token has expired' };
    }
    
    // Check max uses
    if (token.constraints.max_uses !== undefined && token.uses >= token.constraints.max_uses) {
      return { valid: false, reason: 'Token max uses exceeded' };
    }
    
    // Check rate limit
    if (token.constraints.rate_limit) {
      const rateLimitResult = this.checkRateLimit(token);
      if (!rateLimitResult.allowed) {
        return { valid: false, reason: 'Rate limit exceeded' };
      }
    }
    
    // Check context
    if (token.constraints.allowed_contexts && token.constraints.allowed_contexts.length > 0) {
      if (!context || !token.constraints.allowed_contexts.includes(context)) {
        return { valid: false, reason: 'Invalid context for token' };
      }
    }
    
    return { valid: true };
  }
  
  /**
   * Use a capability token (increments use count)
   */
  async useCapabilityToken(
    tokenId: string,
    agentId: string,
    resource: ResourceDescriptor,
    action: ActionType,
    context?: string
  ): Promise<void> {
    // Verify first
    const verification = await this.verifyCapabilityToken(tokenId, agentId, resource, action, context);
    if (!verification.valid) {
      throw new CapabilityError(`Token verification failed: ${verification.reason}`, { token_id: tokenId });
    }
    
    // Increment use count
    await this.storage.incrementTokenUse(tokenId);
    
    // Log usage
    await this.storage.logAccess({
      id: generateId('log_'),
      timestamp: new Date(),
      agent_id: agentId,
      action: 'use_capability',
      resource: this.resourceToString(resource),
      capability_token_id: tokenId,
      success: true,
      context: { action, context },
    });
  }
  
  /**
   * Delegate a capability token to another agent
   */
  async delegateCapability(request: DelegationRequest): Promise<CapabilityToken> {
    // Get parent token
    const parentToken = await this.storage.getCapabilityToken(request.parent_token_id);
    if (!parentToken) {
      throw new CapabilityError('Parent token not found', { token_id: request.parent_token_id });
    }
    
    // Check if delegatable
    if (!parentToken.delegatable) {
      throw new CapabilityError('Token is not delegatable', { token_id: request.parent_token_id });
    }
    
    // Check delegation depth
    if (parentToken.delegation_depth >= CAPABILITY.MAX_DELEGATION_DEPTH) {
      throw new CapabilityError('Maximum delegation depth exceeded', {
        current_depth: parentToken.delegation_depth,
        max_depth: CAPABILITY.MAX_DELEGATION_DEPTH,
      });
    }
    
    // Verify parent token is still valid
    const verification = await this.verifyCapabilityToken(
      request.parent_token_id,
      parentToken.agent_id,
      parentToken.resource,
      parentToken.actions[0]
    );
    if (!verification.valid) {
      throw new CapabilityError(`Parent token is invalid: ${verification.reason}`);
    }
    
    // Attenuate actions (can only reduce, not expand)
    let delegatedActions = request.attenuated_actions || parentToken.actions;
    delegatedActions = delegatedActions.filter(a => parentToken.actions.includes(a));
    
    if (delegatedActions.length === 0) {
      throw new CapabilityError('No valid actions remain after attenuation');
    }
    
    // Attenuate constraints
    const delegatedConstraints: CapabilityConstraints = {
      ...parentToken.constraints,
      ...request.attenuated_constraints,
      // Ensure we don't expand beyond parent
      valid_from: new Date(Math.max(
        parentToken.constraints.valid_from.getTime(),
        request.attenuated_constraints?.valid_from?.getTime() || 0
      )),
      valid_until: new Date(Math.min(
        parentToken.constraints.valid_until.getTime(),
        request.attenuated_constraints?.valid_until?.getTime() || Infinity
      )),
      current_uses: 0,
    };
    
    // Ensure classification doesn't exceed parent
    if (request.attenuated_constraints?.data_classification_max) {
      if (!canAccessClassification(
        request.attenuated_constraints.data_classification_max,
        parentToken.constraints.data_classification_max
      )) {
        delegatedConstraints.data_classification_max = parentToken.constraints.data_classification_max;
      }
    }
    
    // Create delegated token
    const now = new Date();
    const tokenId = generateId(CAPABILITY.TOKEN_PREFIX);
    
    const tokenData = {
      id: tokenId,
      agent_id: request.delegate_to_agent,
      resource: parentToken.resource,
      actions: delegatedActions,
      constraints: delegatedConstraints,
      delegatable: parentToken.delegatable,
      parent_token_id: request.parent_token_id,
      delegation_depth: parentToken.delegation_depth + 1,
      issued_at: now,
      issuer: parentToken.agent_id,
      version: CAPABILITY.TOKEN_VERSION,
    };
    
    const signature = this.signToken(tokenData);
    
    const token: CapabilityToken = {
      ...tokenData,
      signature,
      revoked: false,
      uses: 0,
    };
    
    await this.storage.saveCapabilityToken(token);
    
    // Log delegation
    await this.storage.logAccess({
      id: generateId('log_'),
      timestamp: now,
      agent_id: parentToken.agent_id,
      action: 'delegate_capability',
      resource: this.resourceToString(parentToken.resource),
      capability_token_id: tokenId,
      success: true,
      context: {
        delegate_to: request.delegate_to_agent,
        justification: request.justification,
      },
    });
    
    return token;
  }
  
  /**
   * Revoke a capability token
   */
  async revokeCapability(tokenId: string, agentId: string, reason?: string): Promise<void> {
    const token = await this.storage.getCapabilityToken(tokenId);
    if (!token) {
      throw new CapabilityError('Token not found', { token_id: tokenId });
    }
    
    // Check permission (owner or issuer can revoke)
    if (token.agent_id !== agentId && token.issuer !== agentId) {
      throw new CapabilityError('Not authorized to revoke this token');
    }
    
    await this.storage.revokeCapabilityToken(tokenId);
    
    // Log revocation
    await this.storage.logAccess({
      id: generateId('log_'),
      timestamp: new Date(),
      agent_id: agentId,
      action: 'revoke_capability',
      resource: this.resourceToString(token.resource),
      capability_token_id: tokenId,
      success: true,
      context: { reason },
    });
  }
  
  /**
   * List capabilities for an agent
   */
  async listCapabilities(agentId: string, includeExpired: boolean = false): Promise<CapabilityToken[]> {
    const tokens = await this.storage.getCapabilityTokensByAgent(agentId);
    
    if (includeExpired) {
      return tokens;
    }
    
    const now = new Date();
    return tokens.filter(t => !t.revoked && t.constraints.valid_until > now);
  }
  
  /**
   * Get a capability token by ID
   */
  async getCapability(tokenId: string): Promise<CapabilityToken | null> {
    return this.storage.getCapabilityToken(tokenId);
  }
  
  // ============================================================================
  // Private Methods
  // ============================================================================
  
  private validateConstraints(constraints: CapabilityConstraints): void {
    // Check validity period
    if (constraints.valid_until <= constraints.valid_from) {
      throw new CapabilityError('valid_until must be after valid_from');
    }
    
    // Check max validity
    const maxValidUntil = new Date(
      constraints.valid_from.getTime() + CAPABILITY.MAX_VALIDITY_DAYS * 24 * 60 * 60 * 1000
    );
    if (constraints.valid_until > maxValidUntil) {
      throw new CapabilityError(`Token validity cannot exceed ${CAPABILITY.MAX_VALIDITY_DAYS} days`);
    }
    
    // Check rate limit
    if (constraints.rate_limit) {
      if (constraints.rate_limit.requests <= 0) {
        throw new CapabilityError('Rate limit requests must be positive');
      }
      if (constraints.rate_limit.window_seconds <= 0) {
        throw new CapabilityError('Rate limit window must be positive');
      }
    }
  }
  
  private signToken(tokenData: Record<string, unknown>): string {
    const masterKey = keyStore.getMasterKey();
    const dataToSign = JSON.stringify(tokenData);
    return hmacSign(dataToSign, masterKey);
  }
  
  private verifyTokenSignature(token: CapabilityToken): boolean {
    const masterKey = keyStore.getMasterKey();
    const { signature, revoked, uses, ...tokenData } = token;
    const dataToVerify = JSON.stringify(tokenData);
    return hmacVerify(dataToVerify, signature, masterKey);
  }
  
  private resourceMatches(tokenResource: ResourceDescriptor, requestedResource: ResourceDescriptor): boolean {
    // Exact match
    if (tokenResource.type === requestedResource.type && tokenResource.id === requestedResource.id) {
      return true;
    }
    
    // Wildcard match
    if (tokenResource.type === 'any') {
      return true;
    }
    
    // Pattern match
    if (tokenResource.pattern) {
      const regex = new RegExp(tokenResource.pattern);
      const resourceString = `${requestedResource.type}:${requestedResource.id}`;
      if (regex.test(resourceString)) {
        return true;
      }
    }
    
    // Path prefix match
    if (tokenResource.path && requestedResource.path) {
      if (requestedResource.path.startsWith(tokenResource.path)) {
        return true;
      }
    }
    
    return false;
  }
  
  private checkRateLimit(token: CapabilityToken): { allowed: boolean; resetAt?: Date } {
    if (!token.constraints.rate_limit) {
      return { allowed: true };
    }
    
    const rateLimit = token.constraints.rate_limit;
    const now = new Date();
    
    // Check if we're in a new window
    if (!rateLimit.current_window_start || 
        now.getTime() - rateLimit.current_window_start.getTime() > rateLimit.window_seconds * 1000) {
      // New window, reset count
      rateLimit.current_window_start = now;
      rateLimit.current_count = 0;
    }
    
    // Check if under limit
    const currentCount = rateLimit.current_count || 0;
    if (currentCount >= rateLimit.requests) {
      const resetAt = new Date(rateLimit.current_window_start!.getTime() + rateLimit.window_seconds * 1000);
      return { allowed: false, resetAt };
    }
    
    // Increment count
    rateLimit.current_count = currentCount + 1;
    
    return { allowed: true };
  }
  
  private resourceToString(resource: ResourceDescriptor): string {
    let str = `${resource.type}:${resource.id}`;
    if (resource.path) {
      str += resource.path;
    }
    return str;
  }
}
