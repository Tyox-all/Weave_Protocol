/**
 * Hord Service - Wraps @weave_protocol/hord
 */

import crypto from 'crypto';

export class HordService {
  private vaults: Map<string, any> = new Map();
  private secrets: Map<string, Map<string, any>> = new Map();
  private capabilities: Map<string, any> = new Map();
  private attestations: Map<string, any> = new Map();
  private redactions: Map<string, any> = new Map();
  
  // ==========================================================================
  // Vault Management
  // ==========================================================================
  
  async createVault(name: string, description?: string, config?: any) {
    const id = `vault_${crypto.randomUUID()}`;
    const vault = {
      id,
      name,
      description,
      config: config || {},
      created_at: new Date().toISOString(),
      secret_count: 0
    };
    this.vaults.set(id, vault);
    this.secrets.set(id, new Map());
    return vault;
  }
  
  async listVaults() {
    return Array.from(this.vaults.values());
  }
  
  async getVault(id: string) {
    const vault = this.vaults.get(id);
    if (!vault) throw new Error(`Vault not found: ${id}`);
    return vault;
  }
  
  async deleteVault(id: string) {
    if (!this.vaults.has(id)) throw new Error(`Vault not found: ${id}`);
    this.vaults.delete(id);
    this.secrets.delete(id);
    return { success: true, deleted: id };
  }
  
  // ==========================================================================
  // Secrets Management
  // ==========================================================================
  
  async storeSecret(vaultId: string, key: string, value: string, metadata?: any) {
    const vaultSecrets = this.secrets.get(vaultId);
    if (!vaultSecrets) throw new Error(`Vault not found: ${vaultId}`);
    
    // Encrypt value (simplified - in production use proper encryption)
    const encrypted = this.encrypt(value);
    
    const secret = {
      key,
      encrypted_value: encrypted,
      metadata,
      created_at: new Date().toISOString(),
      version: 1
    };
    
    vaultSecrets.set(key, secret);
    
    // Update vault secret count
    const vault = this.vaults.get(vaultId);
    if (vault) vault.secret_count = vaultSecrets.size;
    
    return { success: true, key, vault_id: vaultId };
  }
  
  async retrieveSecret(vaultId: string, key: string, capabilityToken?: string) {
    // Verify capability if provided
    if (capabilityToken) {
      const cap = this.capabilities.get(capabilityToken);
      if (!cap || cap.vault_id !== vaultId || !cap.permissions.includes('read')) {
        throw new Error('Invalid or insufficient capability token');
      }
      if (new Date(cap.expires_at) < new Date()) {
        throw new Error('Capability token expired');
      }
    }
    
    const vaultSecrets = this.secrets.get(vaultId);
    if (!vaultSecrets) throw new Error(`Vault not found: ${vaultId}`);
    
    const secret = vaultSecrets.get(key);
    if (!secret) throw new Error(`Secret not found: ${key}`);
    
    // Decrypt value
    const decrypted = this.decrypt(secret.encrypted_value);
    
    return {
      key,
      value: decrypted,
      metadata: secret.metadata,
      retrieved_at: new Date().toISOString()
    };
  }
  
  async deleteSecret(vaultId: string, key: string) {
    const vaultSecrets = this.secrets.get(vaultId);
    if (!vaultSecrets) throw new Error(`Vault not found: ${vaultId}`);
    
    if (!vaultSecrets.has(key)) throw new Error(`Secret not found: ${key}`);
    vaultSecrets.delete(key);
    
    return { success: true, deleted: key };
  }
  
  // ==========================================================================
  // Capability Tokens
  // ==========================================================================
  
  async createCapability(vaultId: string, permissions: string[], expiresIn?: number) {
    if (!this.vaults.has(vaultId)) throw new Error(`Vault not found: ${vaultId}`);
    
    const token = `cap_${crypto.randomUUID()}`;
    const expiresAt = new Date(Date.now() + (expiresIn || 3600000)); // Default 1 hour
    
    const capability = {
      token,
      vault_id: vaultId,
      permissions,
      created_at: new Date().toISOString(),
      expires_at: expiresAt.toISOString()
    };
    
    this.capabilities.set(token, capability);
    
    return { token, expires_at: capability.expires_at, permissions };
  }
  
  async verifyCapability(token: string) {
    const cap = this.capabilities.get(token);
    if (!cap) return { valid: false, reason: 'Token not found' };
    if (new Date(cap.expires_at) < new Date()) return { valid: false, reason: 'Token expired' };
    return { valid: true, vault_id: cap.vault_id, permissions: cap.permissions };
  }
  
  async revokeCapability(token: string) {
    if (!this.capabilities.has(token)) throw new Error('Token not found');
    this.capabilities.delete(token);
    return { success: true, revoked: token };
  }
  
  // ==========================================================================
  // Redaction
  // ==========================================================================
  
  async redact(content: string, _policyId?: string, types?: string[]) {
    const redactionId = `red_${crypto.randomUUID()}`;
    const redactTypes = types || ['pii', 'secrets'];
    
    let redacted = content;
    const replacements: any[] = [];
    
    if (redactTypes.includes('pii')) {
      // Redact emails
      redacted = redacted.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, (match) => {
        const token = `[EMAIL_${replacements.length}]`;
        replacements.push({ token, original: match, type: 'email' });
        return token;
      });
      
      // Redact phone numbers
      redacted = redacted.replace(/\b(\+1)?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, (match) => {
        const token = `[PHONE_${replacements.length}]`;
        replacements.push({ token, original: match, type: 'phone' });
        return token;
      });
      
      // Redact SSN
      redacted = redacted.replace(/\b\d{3}-\d{2}-\d{4}\b/g, (match) => {
        const token = `[SSN_${replacements.length}]`;
        replacements.push({ token, original: match, type: 'ssn' });
        return token;
      });
    }
    
    if (redactTypes.includes('secrets')) {
      // Redact API keys
      redacted = redacted.replace(/sk-[a-zA-Z0-9]{32,}/g, (match) => {
        const token = `[API_KEY_${replacements.length}]`;
        replacements.push({ token, original: match, type: 'api_key' });
        return token;
      });
    }
    
    // Store for potential restoration
    this.redactions.set(redactionId, { replacements, created_at: new Date().toISOString() });
    
    return {
      redaction_id: redactionId,
      original_length: content.length,
      redacted_content: redacted,
      redacted_length: redacted.length,
      replacements_count: replacements.length,
      reversible: true
    };
  }
  
  async restoreRedacted(redactedContent: string, redactionId: string) {
    const redaction = this.redactions.get(redactionId);
    if (!redaction) throw new Error(`Redaction not found: ${redactionId}`);
    
    let restored = redactedContent;
    for (const { token, original } of redaction.replacements) {
      restored = restored.replace(token, original);
    }
    
    return { restored_content: restored };
  }
  
  // ==========================================================================
  // Sandbox
  // ==========================================================================
  
  async sandboxExecute(code: string, language: string, options?: { timeout?: number; memory_limit?: number }) {
    const timeout = options?.timeout || 5000;
    const startTime = Date.now();
    
    // In production, this would use actual sandboxing (VM2, isolated-vm, Docker, etc.)
    // For now, we simulate safe execution
    
    try {
      let result;
      
      if (language === 'javascript') {
        // Very basic JS evaluation (NOT PRODUCTION SAFE)
        // In production, use vm2 or isolated-vm
        result = { output: 'Sandbox execution simulated', language };
      } else if (language === 'python') {
        result = { output: 'Python sandbox not implemented', language };
      } else {
        throw new Error(`Unsupported language: ${language}`);
      }
      
      return {
        success: true,
        result,
        execution_time_ms: Date.now() - startTime,
        memory_used: 0,
        sandbox_id: `sbx_${crypto.randomUUID()}`
      };
    } catch (error) {
      return {
        success: false,
        error: String(error),
        execution_time_ms: Date.now() - startTime
      };
    }
  }
  
  // ==========================================================================
  // Attestation
  // ==========================================================================
  
  async createAttestation(content: string, metadata?: any) {
    const id = `att_${crypto.randomUUID()}`;
    const hash = crypto.createHash('sha256').update(content).digest('hex');
    
    const attestation = {
      id,
      content_hash: hash,
      content_length: content.length,
      metadata,
      created_at: new Date().toISOString(),
      algorithm: 'sha256'
    };
    
    this.attestations.set(id, attestation);
    
    return attestation;
  }
  
  async verifyAttestation(attestationId: string, content?: string) {
    const attestation = this.attestations.get(attestationId);
    if (!attestation) throw new Error(`Attestation not found: ${attestationId}`);
    
    if (content) {
      const hash = crypto.createHash('sha256').update(content).digest('hex');
      const matches = hash === attestation.content_hash;
      return { valid: matches, attestation, computed_hash: hash };
    }
    
    return { valid: true, attestation };
  }
  
  // ==========================================================================
  // Function Call Interface (for OpenAI/Gemini)
  // ==========================================================================
  
  async call(fn: string, args: any) {
    switch (fn) {
      case 'hord_create_vault':
        return this.createVault(args.name, args.description, args.config);
      case 'hord_store_secret':
        return this.storeSecret(args.vault_id, args.key, args.value, args.metadata);
      case 'hord_redact':
        return this.redact(args.content, args.policy_id, args.types);
      case 'hord_sandbox_execute':
        return this.sandboxExecute(args.code, args.language, args);
      default:
        throw new Error(`Unknown function: ${fn}`);
    }
  }
  
  // ==========================================================================
  // Helpers
  // ==========================================================================
  
  private encrypt(value: string): string {
    // Simplified encryption - in production use proper key management
    const key = crypto.scryptSync('weave-secret-key', 'salt', 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(value, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
  }
  
  private decrypt(encrypted: string): string {
    const key = crypto.scryptSync('weave-secret-key', 'salt', 32);
    const [ivHex, encryptedData] = encrypted.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  // =============================================================================
  // Yoxallismus Cipher
  // =============================================================================

  async yoxallismusLock(
    data: string,
    key: string,
    options?: { tumblers?: number; entropy_ratio?: number; revolving?: boolean }
  ): Promise<{ locked: string; info: object }> {
    const { YoxallismusCipher } = await import("@weave_protocol/hord");
    
    const cipher = new YoxallismusCipher({
      key,
      tumblers: options?.tumblers,
      entropy_ratio: options?.entropy_ratio,
      revolving: options?.revolving
    });
    
    const locked = cipher.encode(data);
    
    return {
      locked,
      info: cipher.getInfo()
    };
  }

  async yoxallismusUnlock(data: string, key: string): Promise<{ unlocked: string }> {
    const { YoxallismusCipher } = await import("@weave_protocol/hord");
    
    const cipher = new YoxallismusCipher({ key });
    const unlocked = cipher.decode(data);
    
    return { unlocked };
  }

}
