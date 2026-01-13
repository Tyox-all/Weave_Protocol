/**
 * Hord - The Vault Protocol
 * Vault Manager
 * 
 * Manages encrypted vaults for AI agent state, memories, and credentials.
 */

import type {
  Vault,
  VaultConfig,
  VaultContents,
  StoredCredential,
  Memory,
  Artifact,
  AccessPolicy,
  IHordStorage,
  DataClassification,
} from '../types.js';
import { VaultError, DataClassification as DC } from '../types.js';
import {
  encrypt,
  decrypt,
  generateId,
  generateKey,
  hash,
  keyStore,
  type EncryptedData,
} from './encryption.js';
import { canAccessClassification } from '../constants.js';

// ============================================================================
// Vault Manager
// ============================================================================

export class VaultManager {
  private storage: IHordStorage;
  private openVaults: Map<string, { vault: Vault; contents: VaultContents; key: Buffer }> = new Map();
  
  constructor(storage: IHordStorage) {
    this.storage = storage;
  }
  
  /**
   * Create a new encrypted vault
   */
  async createVault(config: VaultConfig): Promise<Vault> {
    // Check if key store is initialized
    if (!keyStore.isInitialized()) {
      throw new VaultError('Key store not initialized. Call initialize() first.');
    }
    
    // Generate vault ID and encryption key
    const vaultId = config.id || generateId('vault_');
    const keyInfo = keyStore.generateKey('encryption');
    
    // Create vault metadata
    const vault: Vault = {
      id: vaultId,
      agent_id: config.agent_id,
      name: config.name,
      description: config.description,
      created_at: new Date(),
      updated_at: new Date(),
      encryption: {
        algorithm: 'aes-256-gcm',
        key_derivation: config.key_derivation || 'pbkdf2',
        key_id: keyInfo.id,
        iv: '',  // Will be set on each encryption
      },
      access_policy: config.access_policy,
      sealed: true,
      version: 1,
    };
    
    // Create empty vault contents
    const contents: VaultContents = {
      memories: [],
      credentials: [],
      state: {},
      artifacts: [],
    };
    
    // Encrypt and store contents
    const encryptedContents = this.encryptContents(contents, keyInfo.key);
    
    // Save vault and contents
    await this.storage.saveVault(vault);
    await this.storage.saveVaultContents(vaultId, JSON.stringify(encryptedContents));
    
    // Log access
    await this.storage.logAccess({
      id: generateId('log_'),
      timestamp: new Date(),
      agent_id: config.agent_id,
      action: 'create_vault',
      resource: `vault:${vaultId}`,
      success: true,
    });
    
    return vault;
  }
  
  /**
   * Open a vault for reading/writing
   */
  async openVault(vaultId: string, agentId: string, context?: string): Promise<Vault> {
    // Get vault metadata
    const vault = await this.storage.getVault(vaultId);
    if (!vault) {
      throw new VaultError('Vault not found', { vault_id: vaultId });
    }
    
    // Check access policy
    this.checkAccessPolicy(vault, agentId, context);
    
    // Check if already open
    if (this.openVaults.has(vaultId)) {
      return vault;
    }
    
    // Get encryption key
    const keyInfo = keyStore.getKey(vault.encryption.key_id);
    if (!keyInfo) {
      throw new VaultError('Vault encryption key not found', { vault_id: vaultId });
    }
    
    // Get and decrypt contents
    const encryptedContentsStr = await this.storage.getVaultContents(vaultId);
    if (!encryptedContentsStr) {
      throw new VaultError('Vault contents not found', { vault_id: vaultId });
    }
    
    const encryptedContents = JSON.parse(encryptedContentsStr) as EncryptedData;
    const contents = this.decryptContents(encryptedContents, keyInfo.key);
    
    // Mark as open
    vault.sealed = false;
    this.openVaults.set(vaultId, { vault, contents, key: keyInfo.key });
    
    // Log access
    await this.storage.logAccess({
      id: generateId('log_'),
      timestamp: new Date(),
      agent_id: agentId,
      action: 'open_vault',
      resource: `vault:${vaultId}`,
      success: true,
      context: { context },
    });
    
    return vault;
  }
  
  /**
   * Seal (close) a vault
   */
  async sealVault(vaultId: string, agentId: string): Promise<void> {
    const openVault = this.openVaults.get(vaultId);
    if (!openVault) {
      throw new VaultError('Vault is not open', { vault_id: vaultId });
    }
    
    // Encrypt and save contents
    const encryptedContents = this.encryptContents(openVault.contents, openVault.key);
    await this.storage.saveVaultContents(vaultId, JSON.stringify(encryptedContents));
    
    // Update vault metadata
    openVault.vault.sealed = true;
    openVault.vault.updated_at = new Date();
    openVault.vault.version++;
    await this.storage.updateVault(openVault.vault);
    
    // Clear from memory
    openVault.key.fill(0);  // Zero out key
    this.openVaults.delete(vaultId);
    
    // Log access
    await this.storage.logAccess({
      id: generateId('log_'),
      timestamp: new Date(),
      agent_id: agentId,
      action: 'seal_vault',
      resource: `vault:${vaultId}`,
      success: true,
    });
  }
  
  /**
   * Store a credential in a vault
   */
  async storeCredential(
    vaultId: string,
    agentId: string,
    credential: {
      name: string;
      type: StoredCredential['type'];
      value: string;
      classification?: DataClassification;
      expires_at?: Date;
      metadata?: Record<string, unknown>;
    }
  ): Promise<string> {
    const openVault = this.getOpenVault(vaultId);
    
    // Check if credential with same name exists
    const existingIndex = openVault.contents.credentials.findIndex(c => c.name === credential.name);
    
    // Encrypt the credential value (double encryption)
    const encryptedValue = encrypt(credential.value, openVault.key);
    
    const storedCredential: StoredCredential = {
      id: generateId('cred_'),
      name: credential.name,
      type: credential.type,
      value_encrypted: JSON.stringify(encryptedValue),
      classification: credential.classification || DC.SECRET,
      created_at: new Date(),
      expires_at: credential.expires_at,
      access_count: 0,
      metadata: credential.metadata || {},
    };
    
    if (existingIndex >= 0) {
      // Update existing
      storedCredential.id = openVault.contents.credentials[existingIndex].id;
      openVault.contents.credentials[existingIndex] = storedCredential;
    } else {
      // Add new
      openVault.contents.credentials.push(storedCredential);
    }
    
    // Log access
    await this.storage.logAccess({
      id: generateId('log_'),
      timestamp: new Date(),
      agent_id: agentId,
      action: 'store_credential',
      resource: `vault:${vaultId}/credentials/${credential.name}`,
      success: true,
    });
    
    return storedCredential.id;
  }
  
  /**
   * Retrieve a credential from a vault
   */
  async retrieveCredential(
    vaultId: string,
    agentId: string,
    credentialName: string,
    requiredClassification?: DataClassification
  ): Promise<string> {
    const openVault = this.getOpenVault(vaultId);
    
    // Find credential
    const credential = openVault.contents.credentials.find(c => c.name === credentialName);
    if (!credential) {
      throw new VaultError('Credential not found', { vault_id: vaultId, credential: credentialName });
    }
    
    // Check classification
    if (requiredClassification && !canAccessClassification(credential.classification, requiredClassification)) {
      throw new VaultError('Insufficient classification level', {
        required: credential.classification,
        provided: requiredClassification,
      });
    }
    
    // Check expiration
    if (credential.expires_at && credential.expires_at < new Date()) {
      throw new VaultError('Credential has expired', { credential: credentialName });
    }
    
    // Decrypt the credential value
    const encryptedValue = JSON.parse(credential.value_encrypted) as EncryptedData;
    const decryptedValue = decrypt(encryptedValue, openVault.key);
    
    // Update access tracking
    credential.access_count++;
    credential.last_accessed = new Date();
    
    // Log access
    await this.storage.logAccess({
      id: generateId('log_'),
      timestamp: new Date(),
      agent_id: agentId,
      action: 'retrieve_credential',
      resource: `vault:${vaultId}/credentials/${credentialName}`,
      success: true,
    });
    
    return decryptedValue.toString('utf-8');
  }
  
  /**
   * Store a memory in a vault
   */
  async storeMemory(
    vaultId: string,
    agentId: string,
    memory: {
      content: string;
      embedding?: number[];
      classification?: DataClassification;
      metadata?: Record<string, unknown>;
    }
  ): Promise<string> {
    const openVault = this.getOpenVault(vaultId);
    
    const storedMemory: Memory = {
      id: generateId('mem_'),
      content: memory.content,
      embedding: memory.embedding,
      created_at: new Date(),
      metadata: memory.metadata || {},
      classification: memory.classification || DC.INTERNAL,
    };
    
    openVault.contents.memories.push(storedMemory);
    
    // Log access
    await this.storage.logAccess({
      id: generateId('log_'),
      timestamp: new Date(),
      agent_id: agentId,
      action: 'store_memory',
      resource: `vault:${vaultId}/memories/${storedMemory.id}`,
      success: true,
    });
    
    return storedMemory.id;
  }
  
  /**
   * Retrieve memories from a vault
   */
  async retrieveMemories(
    vaultId: string,
    agentId: string,
    options?: {
      limit?: number;
      since?: Date;
      classification_max?: DataClassification;
    }
  ): Promise<Memory[]> {
    const openVault = this.getOpenVault(vaultId);
    
    let memories = openVault.contents.memories;
    
    // Filter by date
    if (options?.since) {
      memories = memories.filter(m => m.created_at >= options.since!);
    }
    
    // Filter by classification
    if (options?.classification_max) {
      memories = memories.filter(m => 
        canAccessClassification(m.classification, options.classification_max!)
      );
    }
    
    // Sort by date descending
    memories = memories.sort((a, b) => b.created_at.getTime() - a.created_at.getTime());
    
    // Apply limit
    if (options?.limit) {
      memories = memories.slice(0, options.limit);
    }
    
    // Log access
    await this.storage.logAccess({
      id: generateId('log_'),
      timestamp: new Date(),
      agent_id: agentId,
      action: 'retrieve_memories',
      resource: `vault:${vaultId}/memories`,
      success: true,
      context: { count: memories.length },
    });
    
    return memories;
  }
  
  /**
   * Store state in a vault
   */
  async storeState(
    vaultId: string,
    agentId: string,
    key: string,
    value: unknown
  ): Promise<void> {
    const openVault = this.getOpenVault(vaultId);
    
    openVault.contents.state[key] = value;
    
    // Log access
    await this.storage.logAccess({
      id: generateId('log_'),
      timestamp: new Date(),
      agent_id: agentId,
      action: 'store_state',
      resource: `vault:${vaultId}/state/${key}`,
      success: true,
    });
  }
  
  /**
   * Retrieve state from a vault
   */
  async retrieveState(
    vaultId: string,
    agentId: string,
    key?: string
  ): Promise<unknown> {
    const openVault = this.getOpenVault(vaultId);
    
    // Log access
    await this.storage.logAccess({
      id: generateId('log_'),
      timestamp: new Date(),
      agent_id: agentId,
      action: 'retrieve_state',
      resource: `vault:${vaultId}/state${key ? '/' + key : ''}`,
      success: true,
    });
    
    if (key) {
      return openVault.contents.state[key];
    }
    return openVault.contents.state;
  }
  
  /**
   * Store an artifact in a vault
   */
  async storeArtifact(
    vaultId: string,
    agentId: string,
    artifact: {
      type: Artifact['type'];
      content: string | Buffer;
      classification?: DataClassification;
      metadata?: Record<string, unknown>;
    }
  ): Promise<string> {
    const openVault = this.getOpenVault(vaultId);
    
    const contentBuffer = typeof artifact.content === 'string'
      ? Buffer.from(artifact.content, 'utf-8')
      : artifact.content;
    
    // Encrypt the artifact content
    const encryptedContent = encrypt(contentBuffer, openVault.key);
    
    const storedArtifact: Artifact = {
      id: generateId('art_'),
      type: artifact.type,
      content_hash: hash(contentBuffer),
      content_encrypted: JSON.stringify(encryptedContent),
      classification: artifact.classification || DC.INTERNAL,
      created_at: new Date(),
      metadata: artifact.metadata || {},
    };
    
    openVault.contents.artifacts.push(storedArtifact);
    
    // Log access
    await this.storage.logAccess({
      id: generateId('log_'),
      timestamp: new Date(),
      agent_id: agentId,
      action: 'store_artifact',
      resource: `vault:${vaultId}/artifacts/${storedArtifact.id}`,
      success: true,
    });
    
    return storedArtifact.id;
  }
  
  /**
   * List vaults for an agent
   */
  async listVaults(agentId: string): Promise<Vault[]> {
    return this.storage.getVaultsByAgent(agentId);
  }
  
  /**
   * Get vault info (without opening)
   */
  async getVaultInfo(vaultId: string): Promise<Vault | null> {
    return this.storage.getVault(vaultId);
  }
  
  /**
   * Delete a vault
   */
  async deleteVault(vaultId: string, agentId: string): Promise<void> {
    // Check if vault exists
    const vault = await this.storage.getVault(vaultId);
    if (!vault) {
      throw new VaultError('Vault not found', { vault_id: vaultId });
    }
    
    // Check ownership
    if (vault.agent_id !== agentId) {
      throw new VaultError('Access denied: not vault owner', { vault_id: vaultId });
    }
    
    // Close if open
    if (this.openVaults.has(vaultId)) {
      await this.sealVault(vaultId, agentId);
    }
    
    // Delete vault and contents
    await this.storage.deleteVault(vaultId);
    
    // Delete encryption key
    keyStore.deleteKey(vault.encryption.key_id);
    
    // Log access
    await this.storage.logAccess({
      id: generateId('log_'),
      timestamp: new Date(),
      agent_id: agentId,
      action: 'delete_vault',
      resource: `vault:${vaultId}`,
      success: true,
    });
  }
  
  // ============================================================================
  // Private Methods
  // ============================================================================
  
  private getOpenVault(vaultId: string): { vault: Vault; contents: VaultContents; key: Buffer } {
    const openVault = this.openVaults.get(vaultId);
    if (!openVault) {
      throw new VaultError('Vault is not open. Call openVault() first.', { vault_id: vaultId });
    }
    return openVault;
  }
  
  private checkAccessPolicy(vault: Vault, agentId: string, context?: string): void {
    const policy = vault.access_policy;
    
    // Check allowed agents
    if (policy.allowed_agents && policy.allowed_agents.length > 0) {
      if (!policy.allowed_agents.includes(agentId) && vault.agent_id !== agentId) {
        throw new VaultError('Access denied: agent not in allowlist', { vault_id: vault.id });
      }
    } else if (vault.agent_id !== agentId) {
      throw new VaultError('Access denied: not vault owner', { vault_id: vault.id });
    }
    
    // Check allowed contexts
    if (policy.allowed_contexts && policy.allowed_contexts.length > 0) {
      if (!context || !policy.allowed_contexts.includes(context)) {
        throw new VaultError('Access denied: invalid context', { 
          vault_id: vault.id,
          context,
          allowed: policy.allowed_contexts,
        });
      }
    }
    
    // Check time restrictions
    if (policy.time_restrictions && policy.time_restrictions.length > 0) {
      const now = new Date();
      const currentDay = now.getDay();
      const currentHour = now.getHours();
      
      const allowed = policy.time_restrictions.some(restriction => {
        const dayAllowed = !restriction.days_of_week || 
          restriction.days_of_week.includes(currentDay);
        const hourAllowed = 
          (restriction.start_hour === undefined || currentHour >= restriction.start_hour) &&
          (restriction.end_hour === undefined || currentHour < restriction.end_hour);
        return dayAllowed && hourAllowed;
      });
      
      if (!allowed) {
        throw new VaultError('Access denied: outside allowed time window', { vault_id: vault.id });
      }
    }
  }
  
  private encryptContents(contents: VaultContents, key: Buffer): EncryptedData {
    const json = JSON.stringify(contents);
    return encrypt(json, key);
  }
  
  private decryptContents(encryptedContents: EncryptedData, key: Buffer): VaultContents {
    const decrypted = decrypt(encryptedContents, key);
    return JSON.parse(decrypted.toString('utf-8')) as VaultContents;
  }
}
