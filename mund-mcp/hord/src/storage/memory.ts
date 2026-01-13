/**
 * Hord - The Vault Protocol
 * In-Memory Storage
 */

import type {
  IHordStorage,
  Vault,
  CapabilityToken,
  Sandbox,
  SandboxResult,
  RedactionPolicy,
  TokenizationMap,
  Attestation,
  AccessLogEntry,
  AccessLogFilters,
} from '../types.js';

export class MemoryStorage implements IHordStorage {
  private vaults: Map<string, Vault> = new Map();
  private vaultContents: Map<string, string> = new Map();
  private capabilityTokens: Map<string, CapabilityToken> = new Map();
  private sandboxes: Map<string, Sandbox> = new Map();
  private sandboxResults: Map<string, SandboxResult[]> = new Map();
  private redactionPolicies: Map<string, RedactionPolicy> = new Map();
  private tokenMappings: Map<string, TokenizationMap[string]> = new Map();
  private attestations: Map<string, Attestation> = new Map();
  private accessLog: AccessLogEntry[] = [];
  
  // ============================================================================
  // Vaults
  // ============================================================================
  
  async saveVault(vault: Vault): Promise<void> {
    this.vaults.set(vault.id, { ...vault });
  }
  
  async getVault(id: string): Promise<Vault | null> {
    const vault = this.vaults.get(id);
    return vault ? { ...vault } : null;
  }
  
  async getVaultsByAgent(agentId: string): Promise<Vault[]> {
    return Array.from(this.vaults.values())
      .filter(v => v.agent_id === agentId)
      .map(v => ({ ...v }));
  }
  
  async updateVault(vault: Vault): Promise<void> {
    if (!this.vaults.has(vault.id)) {
      throw new Error('Vault not found');
    }
    this.vaults.set(vault.id, { ...vault });
  }
  
  async deleteVault(id: string): Promise<void> {
    this.vaults.delete(id);
    this.vaultContents.delete(id);
  }
  
  async saveVaultContents(vaultId: string, contents: string): Promise<void> {
    this.vaultContents.set(vaultId, contents);
  }
  
  async getVaultContents(vaultId: string): Promise<string | null> {
    return this.vaultContents.get(vaultId) || null;
  }
  
  // ============================================================================
  // Capability Tokens
  // ============================================================================
  
  async saveCapabilityToken(token: CapabilityToken): Promise<void> {
    this.capabilityTokens.set(token.id, { ...token });
  }
  
  async getCapabilityToken(id: string): Promise<CapabilityToken | null> {
    const token = this.capabilityTokens.get(id);
    return token ? { ...token } : null;
  }
  
  async getCapabilityTokensByAgent(agentId: string): Promise<CapabilityToken[]> {
    return Array.from(this.capabilityTokens.values())
      .filter(t => t.agent_id === agentId)
      .map(t => ({ ...t }));
  }
  
  async revokeCapabilityToken(id: string): Promise<void> {
    const token = this.capabilityTokens.get(id);
    if (token) {
      token.revoked = true;
      this.capabilityTokens.set(id, token);
    }
  }
  
  async incrementTokenUse(id: string): Promise<void> {
    const token = this.capabilityTokens.get(id);
    if (token) {
      token.uses++;
      this.capabilityTokens.set(id, token);
    }
  }
  
  // ============================================================================
  // Sandboxes
  // ============================================================================
  
  async saveSandbox(sandbox: Sandbox): Promise<void> {
    this.sandboxes.set(sandbox.id, { ...sandbox });
  }
  
  async getSandbox(id: string): Promise<Sandbox | null> {
    const sandbox = this.sandboxes.get(id);
    return sandbox ? { ...sandbox } : null;
  }
  
  async updateSandboxStatus(id: string, status: Sandbox['status']): Promise<void> {
    const sandbox = this.sandboxes.get(id);
    if (sandbox) {
      sandbox.status = status;
      this.sandboxes.set(id, sandbox);
    }
  }
  
  async saveSandboxResult(result: SandboxResult): Promise<void> {
    const results = this.sandboxResults.get(result.sandbox_id) || [];
    results.push({ ...result });
    this.sandboxResults.set(result.sandbox_id, results);
  }
  
  async getSandboxResult(id: string): Promise<SandboxResult | null> {
    for (const results of this.sandboxResults.values()) {
      const result = results.find(r => r.id === id);
      if (result) return { ...result };
    }
    return null;
  }
  
  async getSandboxResults(sandboxId: string): Promise<SandboxResult[]> {
    return (this.sandboxResults.get(sandboxId) || []).map(r => ({ ...r }));
  }
  
  // ============================================================================
  // Redaction Policies
  // ============================================================================
  
  async saveRedactionPolicy(policy: RedactionPolicy): Promise<void> {
    this.redactionPolicies.set(policy.id, { ...policy });
  }
  
  async getRedactionPolicy(id: string): Promise<RedactionPolicy | null> {
    const policy = this.redactionPolicies.get(id);
    return policy ? { ...policy } : null;
  }
  
  async listRedactionPolicies(): Promise<RedactionPolicy[]> {
    return Array.from(this.redactionPolicies.values()).map(p => ({ ...p }));
  }
  
  // ============================================================================
  // Tokenization
  // ============================================================================
  
  async saveTokenMapping(token: string, mapping: TokenizationMap[string]): Promise<void> {
    this.tokenMappings.set(token, { ...mapping });
  }
  
  async getTokenMapping(token: string): Promise<TokenizationMap[string] | null> {
    const mapping = this.tokenMappings.get(token);
    return mapping ? { ...mapping } : null;
  }
  
  // ============================================================================
  // Attestations
  // ============================================================================
  
  async saveAttestation(attestation: Attestation): Promise<void> {
    this.attestations.set(attestation.id, { ...attestation });
  }
  
  async getAttestation(id: string): Promise<Attestation | null> {
    const attestation = this.attestations.get(id);
    return attestation ? { ...attestation } : null;
  }
  
  async getAttestationsByAgent(agentId: string, limit?: number): Promise<Attestation[]> {
    let attestations = Array.from(this.attestations.values())
      .filter(a => a.agent_id === agentId)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
    
    if (limit) {
      attestations = attestations.slice(0, limit);
    }
    
    return attestations.map(a => ({ ...a }));
  }
  
  async getAttestationChain(id: string): Promise<Attestation[]> {
    const chain: Attestation[] = [];
    let currentId: string | undefined = id;
    
    while (currentId && chain.length < 1000) {
      const attestation = this.attestations.get(currentId);
      if (!attestation) break;
      
      chain.push({ ...attestation });
      currentId = attestation.previous_attestation_id;
    }
    
    return chain;
  }
  
  // ============================================================================
  // Access Log
  // ============================================================================
  
  async logAccess(entry: AccessLogEntry): Promise<void> {
    this.accessLog.push({ ...entry });
    
    // Keep only last 10000 entries
    if (this.accessLog.length > 10000) {
      this.accessLog = this.accessLog.slice(-10000);
    }
  }
  
  async getAccessLog(filters: AccessLogFilters): Promise<AccessLogEntry[]> {
    let entries = [...this.accessLog];
    
    if (filters.agent_id) {
      entries = entries.filter(e => e.agent_id === filters.agent_id);
    }
    if (filters.action) {
      entries = entries.filter(e => e.action === filters.action);
    }
    if (filters.resource) {
      entries = entries.filter(e => e.resource.includes(filters.resource!));
    }
    if (filters.start_date) {
      entries = entries.filter(e => e.timestamp >= filters.start_date!);
    }
    if (filters.end_date) {
      entries = entries.filter(e => e.timestamp <= filters.end_date!);
    }
    if (filters.success !== undefined) {
      entries = entries.filter(e => e.success === filters.success);
    }
    
    // Sort by timestamp descending
    entries.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
    
    // Apply pagination
    if (filters.offset) {
      entries = entries.slice(filters.offset);
    }
    if (filters.limit) {
      entries = entries.slice(0, filters.limit);
    }
    
    return entries;
  }
}
