/**
 * Hord REST API Routes
 * Vault Protocol - Cryptographic Containment
 */

import { Router, Request, Response } from 'express';
import { HordService, NotSupportedError } from '../services/hord.js';

/** Hord scopes vaults, secrets and capabilities to an agent. */
const agentOf = (req: Request) => (req.get('x-agent-id') || 'api').slice(0, 128);

/** Map Hord errors to HTTP statuses instead of a blanket 500. */
function fail(res: Response, error: unknown) {
  const msg = error instanceof Error ? error.message : String(error);
  const status = error instanceof NotSupportedError ? 501
    : /not found/i.test(msg) ? 404
    : /denied|not allowed|unauthori[sz]ed|capability rejected|revoked|expired|access policy/i.test(msg) ? 403
    : 500;
  res.status(status).json({ error: msg });
}

const router = Router();
const hord = new HordService();

// =============================================================================
// Vault Management
// =============================================================================

/**
 * POST /api/v1/hord/vaults
 * Create a new vault
 */
router.post('/vaults', async (req: Request, res: Response) => {
  try {
    const { name, description, config } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: 'name is required' });
    }
    
    const result = await hord.createVault(name, description, config, agentOf(req));
    res.json(result);
  } catch (error) {
    fail(res, error);
  }
});

/**
 * GET /api/v1/hord/vaults
 * List all vaults
 */
router.get('/vaults', async (req: Request, res: Response) => {
  try {
    const vaults = await hord.listVaults(agentOf(req));
    res.json(vaults);
  } catch (error) {
    fail(res, error);
  }
});

/**
 * GET /api/v1/hord/vaults/:id
 * Get vault details
 */
router.get('/vaults/:id', async (req: Request, res: Response) => {
  try {
    const vault = await hord.getVault(req.params.id);
    res.json(vault);
  } catch (error) {
    fail(res, error);
  }
});

/**
 * DELETE /api/v1/hord/vaults/:id
 * Delete a vault
 */
router.delete('/vaults/:id', async (req: Request, res: Response) => {
  try {
    const result = await hord.deleteVault(req.params.id, agentOf(req));
    res.json(result);
  } catch (error) {
    fail(res, error);
  }
});

// =============================================================================
// Secrets Management
// =============================================================================

/**
 * POST /api/v1/hord/vaults/:id/secrets
 * Store a secret in vault
 */
router.post('/vaults/:id/secrets', async (req: Request, res: Response) => {
  try {
    const { key, value, metadata } = req.body;
    
    if (!key || !value) {
      return res.status(400).json({ error: 'key and value are required' });
    }
    
    const result = await hord.storeSecret(req.params.id, key, value, metadata, agentOf(req));
    res.json(result);
  } catch (error) {
    fail(res, error);
  }
});

/**
 * GET /api/v1/hord/vaults/:id/secrets/:key
 * Retrieve a secret (requires capability token)
 */
router.get('/vaults/:id/secrets/:key', async (req: Request, res: Response) => {
  try {
    const token = req.headers['x-capability-token'] as string;
    const result = await hord.retrieveSecret(req.params.id, req.params.key, token, agentOf(req));
    res.json(result);
  } catch (error) {
    fail(res, error);
  }
});

/**
 * DELETE /api/v1/hord/vaults/:id/secrets/:key
 * Delete a secret
 */
router.delete('/vaults/:id/secrets/:key', async (req: Request, res: Response) => {
  try {
    const result = await hord.deleteSecret(req.params.id, req.params.key);
    res.json(result);
  } catch (error) {
    fail(res, error);
  }
});

// =============================================================================
// Capability Tokens
// =============================================================================

/**
 * POST /api/v1/hord/capabilities
 * Create a capability token
 */
router.post('/capabilities', async (req: Request, res: Response) => {
  try {
    const { vault_id, permissions, expires_in } = req.body;
    
    if (!vault_id || !permissions) {
      return res.status(400).json({ error: 'vault_id and permissions are required' });
    }
    
    const result = await hord.createCapability(vault_id, permissions, expires_in, agentOf(req));
    res.json(result);
  } catch (error) {
    fail(res, error);
  }
});

/**
 * POST /api/v1/hord/capabilities/verify
 * Verify a capability token
 */
router.post('/capabilities/verify', async (req: Request, res: Response) => {
  try {
    const { token, action } = req.body;
    
    if (!token) {
      return res.status(400).json({ error: 'token is required' });
    }
    
    const result = await hord.verifyCapability(token, agentOf(req), action);
    res.json(result);
  } catch (error) {
    fail(res, error);
  }
});

/**
 * POST /api/v1/hord/capabilities/revoke
 * Revoke a capability token
 */
router.post('/capabilities/revoke', async (req: Request, res: Response) => {
  try {
    const { token, reason } = req.body;
    
    if (!token) {
      return res.status(400).json({ error: 'token is required' });
    }
    
    const result = await hord.revokeCapability(token, agentOf(req), reason);
    res.json(result);
  } catch (error) {
    fail(res, error);
  }
});

// =============================================================================
// Redaction
// =============================================================================

/**
 * POST /api/v1/hord/redact
 * Redact sensitive information from content
 */
router.post('/redact', async (req: Request, res: Response) => {
  try {
    const { content, policy_id, types } = req.body;
    
    if (!content) {
      return res.status(400).json({ error: 'content is required' });
    }
    
    const result = await hord.redact(content, policy_id, types);
    res.json(result);
  } catch (error) {
    fail(res, error);
  }
});

/**
 * POST /api/v1/hord/redact/restore
 * Restore redacted content (if reversible)
 */
router.post('/redact/restore', async (req: Request, res: Response) => {
  try {
    const { redacted_content, redaction_id } = req.body;
    
    if (!redacted_content || !redaction_id) {
      return res.status(400).json({ error: 'redacted_content and redaction_id are required' });
    }
    
    const result = await hord.restoreRedacted(redacted_content, redaction_id);
    res.json(result);
  } catch (error) {
    fail(res, error);
  }
});

// =============================================================================
// Sandbox
// =============================================================================

/**
 * POST /api/v1/hord/sandbox/execute
 * Execute code in secure sandbox
 */
router.post('/sandbox/execute', async (req: Request, res: Response) => {
  try {
    const { code, language, timeout, memory_limit } = req.body;
    
    if (!code || !language) {
      return res.status(400).json({ error: 'code and language are required' });
    }
    
    const result = await hord.sandboxExecute(code, language, { timeout, memory_limit });
    res.json(result);
  } catch (error) {
    fail(res, error);
  }
});

// =============================================================================
// Attestation
// =============================================================================

/**
 * POST /api/v1/hord/attest
 * Create attestation for content
 */
router.post('/attest', async (req: Request, res: Response) => {
  try {
    const { content, metadata } = req.body;
    
    if (!content) {
      return res.status(400).json({ error: 'content is required' });
    }
    
    const result = await hord.createAttestation(content, metadata, agentOf(req));
    res.json(result);
  } catch (error) {
    fail(res, error);
  }
});

/**
 * POST /api/v1/hord/attest/verify
 * Verify an attestation
 */
router.post('/attest/verify', async (req: Request, res: Response) => {
  try {
    const { attestation_id, content } = req.body;
    
    if (!attestation_id) {
      return res.status(400).json({ error: 'attestation_id is required' });
    }
    
    const result = await hord.verifyAttestation(attestation_id, content);
    res.json(result);
  } catch (error) {
    fail(res, error);
  }
});


// =============================================================================
// Yoxallismus Cipher
// =============================================================================

/**
 * /api/v1/hord/yoxallismus/*  (410 Gone)
 * Hord's v1 YoxallismusCipher output can never be decrypted (advisory
 * YOXALL-2026-003). Use @weave_protocol/yoxallismus instead.
 */
router.all('/yoxallismus/*', (_req: Request, res: Response) => {
  res.status(410).json({
    error: 'The Yoxallismus v1 cipher endpoints are removed: its output could never be decrypted.',
    advisory: 'https://github.com/Tyox-all/Weave_Protocol/blob/main/yoxallismus/SECURITY_ADVISORIES.md',
    use_instead: '@weave_protocol/yoxallismus (seal/open, Double Ratchet)',
  });
});

export { router as hordRoutes };
