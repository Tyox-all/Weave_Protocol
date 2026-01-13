/**
 * Hord - The Vault Protocol
 * MCP Tools
 */

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { VaultManager } from '../vault/manager.js';
import type { CapabilityManager } from '../capability/token.js';
import type { SandboxManager } from '../sandbox/executor.js';
import type { RedactionEngine } from '../redaction/engine.js';
import type { AttestationService } from '../attestation/service.js';
import { DataClassification, ActionType, IsolationLevel } from '../types.js';

// ============================================================================
// Tool Registration
// ============================================================================

export function registerAllTools(
  server: McpServer,
  vaultManager: VaultManager,
  capabilityManager: CapabilityManager,
  sandboxManager: SandboxManager,
  redactionEngine: RedactionEngine,
  attestationService: AttestationService
): void {
  registerVaultTools(server, vaultManager);
  registerCapabilityTools(server, capabilityManager);
  registerSandboxTools(server, sandboxManager);
  registerRedactionTools(server, redactionEngine);
  registerAttestationTools(server, attestationService);
}

// ============================================================================
// Vault Tools
// ============================================================================

function registerVaultTools(server: McpServer, vaultManager: VaultManager): void {
  server.tool(
    'hord_create_vault',
    'Create a new encrypted vault for storing agent state, memories, and credentials',
    {
      agent_id: z.string().describe('ID of the agent that will own this vault'),
      name: z.string().describe('Human-readable name for the vault'),
      description: z.string().optional().describe('Description of the vault purpose'),
      require_attestation: z.boolean().optional().describe('Require attestation for access'),
      allowed_contexts: z.array(z.string()).optional().describe('Contexts where access is allowed'),
    },
    async ({ agent_id, name, description, require_attestation, allowed_contexts }) => {
      const vault = await vaultManager.createVault({
        agent_id,
        name,
        description,
        access_policy: {
          require_attestation,
          allowed_contexts,
        },
      });
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            vault_id: vault.id,
            name: vault.name,
            created_at: vault.created_at,
          }, null, 2),
        }],
      };
    }
  );
  
  server.tool(
    'hord_open_vault',
    'Open a vault for reading and writing',
    {
      vault_id: z.string().describe('ID of the vault to open'),
      agent_id: z.string().describe('ID of the agent requesting access'),
      context: z.string().optional().describe('Context for this access'),
    },
    async ({ vault_id, agent_id, context }) => {
      const vault = await vaultManager.openVault(vault_id, agent_id, context);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            vault_id: vault.id,
            status: 'open',
          }, null, 2),
        }],
      };
    }
  );
  
  server.tool(
    'hord_seal_vault',
    'Close and re-encrypt a vault',
    {
      vault_id: z.string().describe('ID of the vault to seal'),
      agent_id: z.string().describe('ID of the agent'),
    },
    async ({ vault_id, agent_id }) => {
      await vaultManager.sealVault(vault_id, agent_id);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            vault_id,
            status: 'sealed',
          }, null, 2),
        }],
      };
    }
  );
  
  server.tool(
    'hord_store_secret',
    'Store an encrypted credential in a vault',
    {
      vault_id: z.string().describe('ID of the vault'),
      agent_id: z.string().describe('ID of the agent'),
      name: z.string().describe('Name/identifier for the secret'),
      value: z.string().describe('The secret value to store'),
      type: z.enum(['api_key', 'password', 'token', 'certificate', 'private_key', 'other']).describe('Type of secret'),
      classification: z.enum(['public', 'internal', 'confidential', 'secret', 'top_secret']).optional().describe('Data classification'),
    },
    async ({ vault_id, agent_id, name, value, type, classification }) => {
      const credentialId = await vaultManager.storeCredential(vault_id, agent_id, {
        name,
        value,
        type,
        classification: classification as DataClassification,
      });
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            credential_id: credentialId,
            name,
            stored: true,
          }, null, 2),
        }],
      };
    }
  );
  
  server.tool(
    'hord_retrieve_secret',
    'Retrieve a credential from a vault',
    {
      vault_id: z.string().describe('ID of the vault'),
      agent_id: z.string().describe('ID of the agent'),
      name: z.string().describe('Name of the secret to retrieve'),
    },
    async ({ vault_id, agent_id, name }) => {
      const value = await vaultManager.retrieveCredential(vault_id, agent_id, name);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            name,
            value,
          }, null, 2),
        }],
      };
    }
  );
  
  server.tool(
    'hord_list_vaults',
    'List all vaults accessible to an agent',
    {
      agent_id: z.string().describe('ID of the agent'),
    },
    async ({ agent_id }) => {
      const vaults = await vaultManager.listVaults(agent_id);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            count: vaults.length,
            vaults: vaults.map(v => ({
              id: v.id,
              name: v.name,
              created_at: v.created_at,
              sealed: v.sealed,
            })),
          }, null, 2),
        }],
      };
    }
  );
  
  server.tool(
    'hord_store_memory',
    'Store a memory in a vault',
    {
      vault_id: z.string().describe('ID of the vault'),
      agent_id: z.string().describe('ID of the agent'),
      content: z.string().describe('Memory content to store'),
      classification: z.enum(['public', 'internal', 'confidential', 'secret', 'top_secret']).optional(),
    },
    async ({ vault_id, agent_id, content, classification }) => {
      const memoryId = await vaultManager.storeMemory(vault_id, agent_id, {
        content,
        classification: classification as DataClassification,
      });
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            memory_id: memoryId,
          }, null, 2),
        }],
      };
    }
  );
  
  server.tool(
    'hord_retrieve_memories',
    'Retrieve memories from a vault',
    {
      vault_id: z.string().describe('ID of the vault'),
      agent_id: z.string().describe('ID of the agent'),
      limit: z.number().optional().describe('Maximum number of memories to return'),
    },
    async ({ vault_id, agent_id, limit }) => {
      const memories = await vaultManager.retrieveMemories(vault_id, agent_id, { limit });
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            count: memories.length,
            memories: memories.map(m => ({
              id: m.id,
              content: m.content,
              created_at: m.created_at,
              classification: m.classification,
            })),
          }, null, 2),
        }],
      };
    }
  );
}

// ============================================================================
// Capability Tools
// ============================================================================

function registerCapabilityTools(server: McpServer, capabilityManager: CapabilityManager): void {
  server.tool(
    'hord_request_capability',
    'Request a capability token for accessing a resource',
    {
      agent_id: z.string().describe('ID of the agent requesting capability'),
      resource_type: z.enum(['vault', 'secret', 'file', 'api', 'network', 'sandbox', 'any']).describe('Type of resource'),
      resource_id: z.string().describe('ID of the specific resource'),
      actions: z.array(z.enum(['read', 'write', 'execute', 'delete', 'delegate'])).describe('Actions to permit'),
      justification: z.string().optional().describe('Reason for requesting capability'),
      validity_hours: z.number().optional().describe('How long the token should be valid'),
      delegatable: z.boolean().optional().describe('Whether the token can be delegated'),
    },
    async ({ agent_id, resource_type, resource_id, actions, justification, validity_hours, delegatable }) => {
      const validUntil = validity_hours 
        ? new Date(Date.now() + validity_hours * 60 * 60 * 1000)
        : undefined;
      
      const token = await capabilityManager.createCapabilityToken({
        agent_id,
        resource: { type: resource_type, id: resource_id },
        actions: actions as ActionType[],
        justification,
        delegatable,
        constraints: validUntil ? { 
          valid_from: new Date(), 
          valid_until: validUntil, 
          data_classification_max: DataClassification.CONFIDENTIAL 
        } : undefined,
      });
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            token_id: token.id,
            valid_until: token.constraints.valid_until,
            actions: token.actions,
            delegatable: token.delegatable,
          }, null, 2),
        }],
      };
    }
  );
  
  server.tool(
    'hord_verify_capability',
    'Verify if a capability token is valid for an action',
    {
      token_id: z.string().describe('ID of the capability token'),
      agent_id: z.string().describe('ID of the agent'),
      resource_type: z.enum(['vault', 'secret', 'file', 'api', 'network', 'sandbox', 'any']).describe('Type of resource'),
      resource_id: z.string().describe('ID of the resource'),
      action: z.enum(['read', 'write', 'execute', 'delete', 'delegate']).describe('Action to verify'),
    },
    async ({ token_id, agent_id, resource_type, resource_id, action }) => {
      const result = await capabilityManager.verifyCapabilityToken(
        token_id,
        agent_id,
        { type: resource_type, id: resource_id },
        action as ActionType
      );
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            valid: result.valid,
            reason: result.reason,
          }, null, 2),
        }],
      };
    }
  );
  
  server.tool(
    'hord_revoke_capability',
    'Revoke a capability token',
    {
      token_id: z.string().describe('ID of the token to revoke'),
      agent_id: z.string().describe('ID of the agent revoking'),
      reason: z.string().optional().describe('Reason for revocation'),
    },
    async ({ token_id, agent_id, reason }) => {
      await capabilityManager.revokeCapability(token_id, agent_id, reason);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            token_id,
            revoked: true,
          }, null, 2),
        }],
      };
    }
  );
  
  server.tool(
    'hord_list_capabilities',
    'List capability tokens for an agent',
    {
      agent_id: z.string().describe('ID of the agent'),
      include_expired: z.boolean().optional().describe('Include expired tokens'),
    },
    async ({ agent_id, include_expired }) => {
      const tokens = await capabilityManager.listCapabilities(agent_id, include_expired);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            count: tokens.length,
            tokens: tokens.map(t => ({
              id: t.id,
              resource: t.resource,
              actions: t.actions,
              valid_until: t.constraints.valid_until,
              revoked: t.revoked,
              uses: t.uses,
            })),
          }, null, 2),
        }],
      };
    }
  );
  
  server.tool(
    'hord_delegate_capability',
    'Delegate a capability to another agent',
    {
      token_id: z.string().describe('ID of the parent token'),
      delegate_to: z.string().describe('Agent ID to delegate to'),
      actions: z.array(z.enum(['read', 'write', 'execute', 'delete', 'delegate'])).optional().describe('Subset of actions'),
      justification: z.string().describe('Reason for delegation'),
    },
    async ({ token_id, delegate_to, actions, justification }) => {
      const token = await capabilityManager.delegateCapability({
        parent_token_id: token_id,
        delegate_to_agent: delegate_to,
        attenuated_actions: actions as ActionType[],
        justification,
      });
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            delegated_token_id: token.id,
            delegate_to,
            actions: token.actions,
            delegation_depth: token.delegation_depth,
          }, null, 2),
        }],
      };
    }
  );
}

// ============================================================================
// Sandbox Tools
// ============================================================================

function registerSandboxTools(server: McpServer, sandboxManager: SandboxManager): void {
  server.tool(
    'hord_create_sandbox',
    'Create an isolated execution environment',
    {
      type: z.enum(['code', 'command', 'network', 'file']).describe('Type of sandbox'),
      isolation_level: z.enum(['process', 'container', 'vm']).optional().describe('Isolation level'),
      timeout_ms: z.number().optional().describe('Timeout in milliseconds'),
      memory_mb: z.number().optional().describe('Memory limit in MB'),
      allow_network: z.boolean().optional().describe('Allow network access'),
    },
    async ({ type, isolation_level, timeout_ms, memory_mb, allow_network }) => {
      const sandbox = await sandboxManager.createSandbox({
        type,
        isolation_level: (isolation_level as IsolationLevel) || IsolationLevel.PROCESS,
        resource_limits: {
          cpu_seconds: (timeout_ms || 30000) / 1000,
          memory_mb: memory_mb || 512,
          disk_mb: 100,
          network_bytes: allow_network ? 10 * 1024 * 1024 : 0,
          max_processes: 10,
        },
        network_policy: {
          allow_outbound: allow_network || false,
          dns_policy: allow_network ? 'allow' : 'block',
        },
        filesystem_policy: {
          writable_paths: ['/tmp'],
          readable_paths: ['/usr', '/lib', '/bin'],
          blocked_paths: ['/etc/passwd', '/etc/shadow'],
          allow_symlinks: false,
        },
        timeout_ms,
      });
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            sandbox_id: sandbox.id,
            status: sandbox.status,
            isolation_level: sandbox.config.isolation_level,
          }, null, 2),
        }],
      };
    }
  );
  
  server.tool(
    'hord_execute_in_sandbox',
    'Execute code or command in a sandbox',
    {
      sandbox_id: z.string().describe('ID of the sandbox'),
      type: z.enum(['code', 'command']).describe('Execution type'),
      content: z.string().describe('Code or command to execute'),
      language: z.string().optional().describe('Language for code execution'),
      declared_intent: z.string().describe('What this execution is supposed to do'),
    },
    async ({ sandbox_id, type, content, language, declared_intent }) => {
      const result = await sandboxManager.execute({
        sandbox_id,
        type,
        content,
        language,
        declared_intent,
      });
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: result.status === 'success',
            result_id: result.id,
            status: result.status,
            exit_code: result.exit_code,
            stdout: result.stdout.slice(0, 1000),
            stderr: result.stderr.slice(0, 1000),
            duration_ms: result.duration_ms,
            promotion_recommendation: result.promotion_recommendation,
            recommendation_reasons: result.recommendation_reasons,
            security_events_count: result.security_events.length,
          }, null, 2),
        }],
      };
    }
  );
  
  server.tool(
    'hord_promote_sandbox_result',
    'Promote a sandbox result for real execution',
    {
      sandbox_id: z.string().describe('ID of the sandbox'),
      result_id: z.string().describe('ID of the result to promote'),
    },
    async ({ sandbox_id, result_id }) => {
      const result = await sandboxManager.promote(sandbox_id, result_id);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            promoted: result.promoted,
            reason: result.reason,
          }, null, 2),
        }],
      };
    }
  );
  
  server.tool(
    'hord_destroy_sandbox',
    'Destroy a sandbox and clean up resources',
    {
      sandbox_id: z.string().describe('ID of the sandbox to destroy'),
    },
    async ({ sandbox_id }) => {
      await sandboxManager.destroy(sandbox_id);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            sandbox_id,
            destroyed: true,
          }, null, 2),
        }],
      };
    }
  );
  
  server.tool(
    'hord_get_sandbox_results',
    'Get results from a sandbox',
    {
      sandbox_id: z.string().describe('ID of the sandbox'),
    },
    async ({ sandbox_id }) => {
      const results = await sandboxManager.getResults(sandbox_id);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            count: results.length,
            results: results.map(r => ({
              id: r.id,
              status: r.status,
              duration_ms: r.duration_ms,
              promotion_recommendation: r.promotion_recommendation,
            })),
          }, null, 2),
        }],
      };
    }
  );
}

// ============================================================================
// Redaction Tools
// ============================================================================

function registerRedactionTools(server: McpServer, redactionEngine: RedactionEngine): void {
  server.tool(
    'hord_create_redaction_policy',
    'Create a policy for redacting sensitive data',
    {
      name: z.string().describe('Policy name'),
      description: z.string().optional().describe('Policy description'),
      rules: z.array(z.object({
        field_pattern: z.string().describe('JSONPath or field name to match'),
        data_type: z.enum(['ssn', 'credit_card', 'email', 'phone', 'ip_address', 'name', 'address', 'date_of_birth', 'api_key', 'password', 'custom']),
        strategy_type: z.enum(['mask', 'hash', 'tokenize', 'generalize']),
        reversible: z.boolean(),
      })).describe('Redaction rules'),
    },
    async ({ name, description, rules }) => {
      const policy = await redactionEngine.createPolicy({
        name,
        description,
        rules: rules.map(r => ({
          field_pattern: r.field_pattern,
          data_type: r.data_type,
          strategy: r.strategy_type === 'mask' 
            ? { type: 'mask' as const, char: '*', preserve_length: false }
            : r.strategy_type === 'hash'
            ? { type: 'hash' as const, algorithm: 'sha256' as const, salted: true }
            : r.strategy_type === 'tokenize'
            ? { type: 'tokenize' as const, format_preserving: true }
            : { type: 'generalize' as const, level: 2 },
          reversible: r.reversible,
        })),
      });
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            policy_id: policy.id,
            name: policy.name,
            rules_count: policy.rules.length,
          }, null, 2),
        }],
      };
    }
  );
  
  server.tool(
    'hord_redact_content',
    'Redact sensitive data from content',
    {
      content: z.string().describe('JSON content to redact'),
      policy_id: z.string().describe('ID of the redaction policy to apply'),
    },
    async ({ content, policy_id }) => {
      const parsed = JSON.parse(content);
      const redacted = await redactionEngine.redact(parsed, policy_id);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            redacted_data: redacted.data,
            reversible_count: redacted.reversible_count,
            irreversible_count: redacted.irreversible_count,
            redaction_map_id: redacted.redaction_map_encrypted ? 'stored' : undefined,
          }, null, 2),
        }],
      };
    }
  );
  
  server.tool(
    'hord_tokenize_pii',
    'Tokenize PII in text',
    {
      text: z.string().describe('Text containing PII to tokenize'),
    },
    async ({ text }) => {
      const result = await redactionEngine.tokenizePII(text);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            tokenized: result.tokenized,
            tokens_created: result.tokens.length,
            tokens: result.tokens,
          }, null, 2),
        }],
      };
    }
  );
  
  server.tool(
    'hord_detokenize',
    'Reverse tokenization to get original values',
    {
      text: z.string().describe('Text containing tokens to reverse'),
    },
    async ({ text }) => {
      const original = await redactionEngine.deTokenize(text);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            original,
          }, null, 2),
        }],
      };
    }
  );
  
  server.tool(
    'hord_list_redaction_policies',
    'List all redaction policies',
    {},
    async () => {
      const policies = await redactionEngine.listPolicies();
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            count: policies.length,
            policies: policies.map(p => ({
              id: p.id,
              name: p.name,
              rules_count: p.rules.length,
              created_at: p.created_at,
            })),
          }, null, 2),
        }],
      };
    }
  );
}

// ============================================================================
// Attestation Tools
// ============================================================================

function registerAttestationTools(server: McpServer, attestationService: AttestationService): void {
  server.tool(
    'hord_attest_action',
    'Create a cryptographic attestation for an action',
    {
      agent_id: z.string().describe('ID of the agent'),
      action_type: z.string().describe('Type of action'),
      description: z.string().describe('Description of the action'),
      resources_accessed: z.array(z.string()).describe('Resources that were accessed'),
      result: z.enum(['success', 'failure', 'partial']).optional().describe('Result of the action'),
    },
    async ({ agent_id, action_type, description, resources_accessed, result }) => {
      const attestation = await attestationService.attestAction(
        agent_id,
        action_type,
        description,
        resources_accessed,
        { result }
      );
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            attestation_id: attestation.id,
            timestamp: attestation.timestamp,
            signature: attestation.signature.slice(0, 16) + '...',
          }, null, 2),
        }],
      };
    }
  );
  
  server.tool(
    'hord_verify_attestation',
    'Verify an attestation is valid',
    {
      attestation_id: z.string().describe('ID of the attestation to verify'),
    },
    async ({ attestation_id }) => {
      const verification = await attestationService.verify(attestation_id);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            attestation_id,
            valid: verification.valid,
            signature_valid: verification.signature_valid,
            timestamp_valid: verification.timestamp_valid,
            chain_valid: verification.chain_valid,
            errors: verification.errors,
            verified_at: verification.verified_at,
          }, null, 2),
        }],
      };
    }
  );
  
  server.tool(
    'hord_get_attestations',
    'Get attestations for an agent',
    {
      agent_id: z.string().describe('ID of the agent'),
      limit: z.number().optional().describe('Maximum number to return'),
    },
    async ({ agent_id, limit }) => {
      const attestations = await attestationService.getAttestationsForAgent(agent_id, limit);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            count: attestations.length,
            attestations: attestations.map(a => ({
              id: a.id,
              timestamp: a.timestamp,
              action_type: a.action.type,
              action_description: a.action.description,
              result: a.action.result,
            })),
          }, null, 2),
        }],
      };
    }
  );
  
  server.tool(
    'hord_get_attestation_chain',
    'Get the chain of attestations',
    {
      attestation_id: z.string().describe('ID of the attestation to start from'),
      max_depth: z.number().optional().describe('Maximum chain depth'),
    },
    async ({ attestation_id, max_depth }) => {
      const chain = await attestationService.getAttestationChain(attestation_id, max_depth);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            chain_length: chain.length,
            chain: chain.map(a => ({
              id: a.id,
              timestamp: a.timestamp,
              action_type: a.action.type,
              previous_id: a.previous_attestation_id,
            })),
          }, null, 2),
        }],
      };
    }
  );
  
  server.tool(
    'hord_export_audit_log',
    'Export attestations for audit',
    {
      agent_id: z.string().describe('ID of the agent'),
      format: z.enum(['json', 'csv']).optional().describe('Export format'),
    },
    async ({ agent_id, format }) => {
      const exported = await attestationService.exportForAudit(agent_id, { format });
      
      return {
        content: [{
          type: 'text',
          text: format === 'csv' ? exported : JSON.stringify({
            success: true,
            format: format || 'json',
            data: JSON.parse(exported),
          }, null, 2),
        }],
      };
    }
  );
}
