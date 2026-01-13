/**
 * Hord - The Vault Protocol
 * Attestation Service
 * 
 * Cryptographic proof of agent behavior.
 */

import type {
  Attestation,
  AttestationRequest,
  AttestationContext,
  AttestationVerification,
  AttestableAction,
  IHordStorage,
} from '../types.js';
import { AttestationError } from '../types.js';
import { ATTESTATION, SERVER_INFO } from '../constants.js';
import { generateId, hash, hmacSign, hmacVerify, keyStore } from '../vault/encryption.js';

// ============================================================================
// Attestation Service
// ============================================================================

export class AttestationService {
  private storage: IHordStorage;
  private lastAttestationId: string | null = null;
  
  constructor(storage: IHordStorage) {
    this.storage = storage;
  }
  
  /**
   * Create an attestation for an action
   */
  async attest(request: AttestationRequest): Promise<Attestation> {
    if (!keyStore.isInitialized()) {
      throw new AttestationError('Key store not initialized');
    }
    
    const now = new Date();
    const attestationId = generateId('attest_');
    
    // Build context
    const context: AttestationContext = {
      environment: {
        node_version: process.version,
        platform: process.platform,
        ...request.context?.environment,
      },
      caller_chain: request.context?.caller_chain || [],
      policy_version: request.context?.policy_version || '1.0',
      hord_version: SERVER_INFO.version,
      timestamp_source: 'local',
      additional: request.context?.additional || {},
    };
    
    // Calculate hashes if not provided
    const inputsHash = request.inputs_hash || hash(JSON.stringify(request.action));
    const outputsHash = request.outputs_hash || hash(attestationId + now.toISOString());
    
    // Build attestation data
    const attestationData = {
      id: attestationId,
      timestamp: now,
      agent_id: request.agent_id,
      action: request.action,
      inputs_hash: inputsHash,
      outputs_hash: outputsHash,
      context,
      previous_attestation_id: this.lastAttestationId || undefined,
    };
    
    // Sign the attestation
    const signature = this.signAttestation(attestationData);
    
    const attestation: Attestation = {
      ...attestationData,
      signature,
      certificate_chain: [], // Would include cert chain in production
      verified: true,
    };
    
    // Store attestation
    await this.storage.saveAttestation(attestation);
    
    // Update chain
    this.lastAttestationId = attestationId;
    
    // Log
    await this.storage.logAccess({
      id: generateId('log_'),
      timestamp: now,
      agent_id: request.agent_id,
      action: 'create_attestation',
      resource: `attestation:${attestationId}`,
      success: true,
    });
    
    return attestation;
  }
  
  /**
   * Verify an attestation
   */
  async verify(attestationId: string): Promise<AttestationVerification> {
    const attestation = await this.storage.getAttestation(attestationId);
    
    if (!attestation) {
      return {
        attestation_id: attestationId,
        valid: false,
        signature_valid: false,
        certificate_valid: false,
        timestamp_valid: false,
        chain_valid: false,
        errors: ['Attestation not found'],
        verified_at: new Date(),
      };
    }
    
    const errors: string[] = [];
    
    // Verify signature
    const signatureValid = this.verifyAttestationSignature(attestation);
    if (!signatureValid) {
      errors.push('Invalid signature');
    }
    
    // Verify timestamp (not in future, not too old)
    const now = new Date();
    const timestampValid = 
      attestation.timestamp <= now &&
      now.getTime() - attestation.timestamp.getTime() < 365 * 24 * 60 * 60 * 1000; // 1 year
    if (!timestampValid) {
      errors.push('Invalid timestamp');
    }
    
    // Verify chain (if has previous)
    let chainValid = true;
    if (attestation.previous_attestation_id) {
      const previous = await this.storage.getAttestation(attestation.previous_attestation_id);
      if (!previous) {
        chainValid = false;
        errors.push('Previous attestation in chain not found');
      } else if (previous.timestamp >= attestation.timestamp) {
        chainValid = false;
        errors.push('Chain timestamp ordering invalid');
      }
    }
    
    // Certificate verification would go here in production
    const certificateValid = true;
    
    return {
      attestation_id: attestationId,
      valid: signatureValid && timestampValid && chainValid && certificateValid,
      signature_valid: signatureValid,
      certificate_valid: certificateValid,
      timestamp_valid: timestampValid,
      chain_valid: chainValid,
      errors,
      verified_at: now,
    };
  }
  
  /**
   * Get attestation by ID
   */
  async getAttestation(attestationId: string): Promise<Attestation | null> {
    return this.storage.getAttestation(attestationId);
  }
  
  /**
   * Get attestations for an agent
   */
  async getAttestationsForAgent(agentId: string, limit?: number): Promise<Attestation[]> {
    return this.storage.getAttestationsByAgent(agentId, limit);
  }
  
  /**
   * Get attestation chain (follow previous pointers)
   */
  async getAttestationChain(attestationId: string, maxDepth?: number): Promise<Attestation[]> {
    const chain: Attestation[] = [];
    let currentId: string | undefined = attestationId;
    const depth = maxDepth || ATTESTATION.MAX_CHAIN_DEPTH;
    
    while (currentId && chain.length < depth) {
      const attestation = await this.storage.getAttestation(currentId);
      if (!attestation) break;
      
      chain.push(attestation);
      currentId = attestation.previous_attestation_id;
    }
    
    return chain;
  }
  
  /**
   * Export attestations for audit
   */
  async exportForAudit(
    agentId: string,
    options?: {
      start_date?: Date;
      end_date?: Date;
      format?: 'json' | 'csv';
    }
  ): Promise<string> {
    const attestations = await this.storage.getAttestationsByAgent(agentId);
    
    // Filter by date
    let filtered = attestations;
    if (options?.start_date) {
      filtered = filtered.filter(a => a.timestamp >= options.start_date!);
    }
    if (options?.end_date) {
      filtered = filtered.filter(a => a.timestamp <= options.end_date!);
    }
    
    // Sort by timestamp
    filtered.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
    
    if (options?.format === 'csv') {
      const headers = [
        'id',
        'timestamp',
        'agent_id',
        'action_type',
        'action_description',
        'resources_accessed',
        'inputs_hash',
        'outputs_hash',
        'signature',
        'verified',
      ];
      
      const rows = filtered.map(a => [
        a.id,
        a.timestamp.toISOString(),
        a.agent_id,
        a.action.type,
        a.action.description,
        a.action.resources_accessed.join(';'),
        a.inputs_hash,
        a.outputs_hash,
        a.signature,
        String(a.verified),
      ]);
      
      return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    }
    
    return JSON.stringify(filtered, null, 2);
  }
  
  /**
   * Create a quick attestation for common actions
   */
  async attestAction(
    agentId: string,
    actionType: string,
    description: string,
    resourcesAccessed: string[],
    options?: {
      capabilities_used?: string[];
      sandbox_id?: string;
      duration_ms?: number;
      result?: 'success' | 'failure' | 'partial';
    }
  ): Promise<Attestation> {
    const action: AttestableAction = {
      type: actionType,
      description,
      resources_accessed: resourcesAccessed,
      capabilities_used: options?.capabilities_used || [],
      sandbox_id: options?.sandbox_id,
      duration_ms: options?.duration_ms || 0,
      result: options?.result || 'success',
    };
    
    return this.attest({
      agent_id: agentId,
      action,
    });
  }
  
  // ============================================================================
  // Private Methods
  // ============================================================================
  
  private signAttestation(attestationData: Record<string, unknown>): string {
    const masterKey = keyStore.getMasterKey();
    const dataToSign = this.canonicalize(attestationData);
    return hmacSign(dataToSign, masterKey);
  }
  
  private verifyAttestationSignature(attestation: Attestation): boolean {
    try {
      const masterKey = keyStore.getMasterKey();
      const { signature, certificate_chain, verified, ...data } = attestation;
      const dataToVerify = this.canonicalize(data);
      return hmacVerify(dataToVerify, signature, masterKey);
    } catch {
      return false;
    }
  }
  
  private canonicalize(obj: Record<string, unknown>): string {
    // Sort keys for consistent serialization
    return JSON.stringify(obj, Object.keys(obj).sort());
  }
}
