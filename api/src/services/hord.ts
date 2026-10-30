/**
 * Hord Service - backed by @weave_protocol/hord
 *
 * Vaults, capability tokens, PII tokenization, attestations and the sandbox
 * are Hord's own services (in-memory storage, like the Hord MCP server).
 * Hord scopes everything to an agent; routes pass the caller's X-Agent-Id
 * (default "api").
 *
 * The vault master key comes from HORD_MASTER_KEY / HORD_MASTER_KEY_FILE, as
 * for the Hord server; without one, a random key is used for this process.
 */

import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  createStorage, keyStore,
  VaultManager, CapabilityManager, RedactionEngine, SandboxManager, AttestationService,
  ActionType, DataClassification, IsolationLevel, SANDBOX,
  type StoredCredential,
} from '@weave_protocol/hord';

export class NotSupportedError extends Error {}

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

function masterKey(): string | Buffer {
  if (process.env.HORD_MASTER_KEY) return process.env.HORD_MASTER_KEY;
  if (process.env.HORD_MASTER_KEY_FILE) return readFileSync(process.env.HORD_MASTER_KEY_FILE, 'utf8').trim();
  return randomBytes(32);
}

export class HordService {
  private storage = createStorage('memory');
  private vaults = new VaultManager(this.storage);
  private capabilities = new CapabilityManager(this.storage);
  private redaction = new RedactionEngine(this.storage);
  private sandbox = new SandboxManager(this.storage);
  private attestation = new AttestationService(this.storage);

  constructor() {
    if (!keyStore.isInitialized()) keyStore.initialize(masterKey());
  }

  // ==========================================================================
  // Vault Management
  // ==========================================================================

  async createVault(name: string, description?: string, config?: any, agentId = 'api') {
    const vault = await this.vaults.createVault({
      agent_id: agentId,
      name,
      description,
      access_policy: {
        require_attestation: !!config?.require_attestation,
        allowed_contexts: config?.allowed_contexts,
      },
    });
    return { success: true, vault_id: vault.id, vault };
  }

  async listVaults(agentId = 'api') {
    return this.vaults.listVaults(agentId);
  }

  async getVault(id: string) {
    return this.vaults.getVaultInfo(id);
  }

  async deleteVault(id: string, agentId = 'api') {
    await this.vaults.deleteVault(id, agentId);
    return { success: true, deleted: id };
  }

  // ==========================================================================
  // Secrets (stored encrypted; the vault is sealed again after each call)
  // ==========================================================================

  async storeSecret(vaultId: string, key: string, value: string, metadata?: any, agentId = 'api') {
    const credentialId = await this.withOpenVault(vaultId, agentId, () =>
      this.vaults.storeCredential(vaultId, agentId, {
        name: key,
        type: (metadata?.type as StoredCredential['type']) || 'other',
        value,
        metadata,
      }),
    );
    return { success: true, vault_id: vaultId, key, credential_id: credentialId };
  }

  async retrieveSecret(vaultId: string, key: string, capabilityToken?: string, agentId = 'api') {
    if (capabilityToken) {
      const check = await this.capabilities.verifyCapabilityToken(capabilityToken, agentId, { type: 'vault', id: vaultId }, ActionType.READ);
      if (!check.valid) throw new Error(`Capability rejected: ${check.reason ?? 'invalid'}`);
    }
    const value = await this.withOpenVault(vaultId, agentId, () => this.vaults.retrieveCredential(vaultId, agentId, key));
    return { vault_id: vaultId, key, value };
  }

  async deleteSecret(_vaultId: string, _key: string) {
    throw new NotSupportedError('Hord does not support deleting a single credential; delete the vault instead.');
  }

  // ==========================================================================
  // Capability Tokens
  // ==========================================================================

  async createCapability(vaultId: string, permissions: string[], expiresIn?: number, agentId = 'api') {
    const actions = (permissions?.length ? permissions : ['read']) as ActionType[];
    const token = await this.capabilities.createCapabilityToken({
      agent_id: agentId,
      resource: { type: 'vault', id: vaultId },
      actions,
      constraints: expiresIn
        ? { valid_from: new Date(), valid_until: new Date(Date.now() + expiresIn * 1000), data_classification_max: DataClassification.CONFIDENTIAL }
        : undefined,
    });
    return { success: true, token: token.id, capability: token };
  }

  /** Verify a token for its own resource and an action (default: its first action). */
  async verifyCapability(token: string, agentId = 'api', action?: string) {
    const cap = await this.capabilities.getCapability(token);
    if (!cap) return { valid: false, reason: 'Token not found' };
    const result = await this.capabilities.verifyCapabilityToken(token, agentId, cap.resource, (action as ActionType) || cap.actions[0]);
    return { ...result, resource: cap.resource, actions: cap.actions };
  }

  async revokeCapability(token: string, agentId = 'api', reason?: string) {
    await this.capabilities.revokeCapability(token, agentId, reason);
    return { success: true, revoked: token };
  }

  // ==========================================================================
  // Redaction (PII tokenization; reversible with restore)
  // ==========================================================================

  async redact(content: string, policyId?: string, _types?: string[]) {
    if (policyId) {
      const redacted = await this.redaction.redact(content, policyId);
      return { redacted: redacted.data, policy_id: policyId, redacted_data: redacted };
    }
    const { tokenized, tokens } = await this.redaction.tokenizePII(content);
    return { redacted: tokenized, tokens, count: tokens.length };
  }

  async restoreRedacted(redactedContent: string, _redactionId?: string) {
    return { restored: await this.redaction.deTokenize(redactedContent) };
  }

  // ==========================================================================
  // Sandbox (Hord's isolated executor)
  // ==========================================================================

  async sandboxExecute(code: string, language: string, options?: { timeout?: number; memory_limit?: number; declared_intent?: string }) {
    const box = await this.sandbox.createSandbox({
      type: 'code',
      isolation_level: IsolationLevel.PROCESS,
      resource_limits: { ...SANDBOX.DEFAULT_LIMITS, memory_mb: options?.memory_limit || 256 },
      network_policy: SANDBOX.DEFAULT_NETWORK_POLICY,
      filesystem_policy: SANDBOX.DEFAULT_FILESYSTEM_POLICY,
      timeout_ms: options?.timeout || 5000,
    });
    try {
      const result = await this.sandbox.execute({
        sandbox_id: box.id,
        type: 'code',
        language,
        content: code,
        declared_intent: options?.declared_intent || 'API sandbox execution',
      });
      return {
        status: result.status,
        exit_code: result.exit_code,
        stdout: result.stdout,
        stderr: result.stderr,
        duration_ms: result.duration_ms,
        resource_usage: result.resource_usage,
        promotion_recommendation: result.promotion_recommendation,
        security_events: result.security_events,
        isolation: result.isolation,
      };
    } finally {
      await this.sandbox.destroy(box.id).catch(() => {});
    }
  }

  // ==========================================================================
  // Attestation
  // ==========================================================================

  async createAttestation(content: string, metadata?: any, agentId = 'api') {
    const attestation = await this.attestation.attest({
      agent_id: agentId,
      action: {
        type: metadata?.action_type || 'api_attestation',
        description: metadata?.description || 'Content attested via the Weave API',
        resources_accessed: metadata?.resources || [],
        capabilities_used: [],
        duration_ms: 0,
        result: 'success',
      },
      inputs_hash: sha256(content ?? ''),
    });
    return { success: true, attestation_id: attestation.id, attestation };
  }

  async verifyAttestation(attestationId: string, content?: string) {
    const verification = await this.attestation.verify(attestationId);
    if (content === undefined) return verification;
    const stored = await this.attestation.getAttestation(attestationId);
    const contentMatches = !!stored && stored.inputs_hash === sha256(content);
    return {
      ...verification,
      content_matches: contentMatches,
      valid: verification.valid && contentMatches,
      errors: contentMatches ? verification.errors : [...verification.errors, 'Content does not match the attested hash'],
    };
  }

  // ==========================================================================
  // Function calling
  // ==========================================================================

  async call(fn: string, args: any) {
    switch (fn) {
      case 'hord_create_vault':
        return this.createVault(args.name, args.description, args.config);
      case 'hord_store_secret':
        return this.storeSecret(args.vault_id, args.key, args.value, args.metadata);
      case 'hord_retrieve_secret':
        return this.retrieveSecret(args.vault_id, args.key, args.capability_token);
      case 'hord_redact':
        return this.redact(args.content, args.policy_id, args.types);
      case 'hord_sandbox_execute':
        return this.sandboxExecute(args.code, args.language, { timeout: args.timeout });
      case 'hord_attest':
        return this.createAttestation(args.content, args.metadata);
      default:
        throw new Error(`Unknown function: ${fn}`);
    }
  }

  private async withOpenVault<T>(vaultId: string, agentId: string, fn: () => Promise<T>): Promise<T> {
    await this.vaults.openVault(vaultId, agentId);
    try {
      return await fn();
    } finally {
      await this.vaults.sealVault(vaultId, agentId).catch(() => {});
    }
  }
}
