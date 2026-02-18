/**
 * Hord REST API Routes
 * Vault Protocol - Cryptographic Containment
 */

import { Router, Request, Response } from 'express';
import { HordService } from '../services/hord.js';

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
    
    const result = await hord.createVault(name, description, config);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

/**
 * GET /api/v1/hord/vaults
 * List all vaults
 */
router.get('/vaults', async (_req: Request, res: Response) => {
  try {
    const vaults = await hord.listVaults();
    res.json(vaults);
  } catch (error) {
    res.status(500).json({ error: String(error) });
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
    res.status(500).json({ error: String(error) });
  }
});

/**
 * DELETE /api/v1/hord/vaults/:id
 * Delete a vault
 */
router.delete('/vaults/:id', async (req: Request, res: Response) => {
  try {
    const result = await hord.deleteVault(req.params.id);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
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
    
    const result = await hord.storeSecret(req.params.id, key, value, metadata);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

/**
 * GET /api/v1/hord/vaults/:id/secrets/:key
 * Retrieve a secret (requires capability token)
 */
router.get('/vaults/:id/secrets/:key', async (req: Request, res: Response) => {
  try {
    const token = req.headers['x-capability-token'] as string;
    const result = await hord.retrieveSecret(req.params.id, req.params.key, token);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
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
    res.status(500).json({ error: String(error) });
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
    
    const result = await hord.createCapability(vault_id, permissions, expires_in);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

/**
 * POST /api/v1/hord/capabilities/verify
 * Verify a capability token
 */
router.post('/capabilities/verify', async (req: Request, res: Response) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({ error: 'token is required' });
    }
    
    const result = await hord.verifyCapability(token);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

/**
 * POST /api/v1/hord/capabilities/revoke
 * Revoke a capability token
 */
router.post('/capabilities/revoke', async (req: Request, res: Response) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({ error: 'token is required' });
    }
    
    const result = await hord.revokeCapability(token);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
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
    res.status(500).json({ error: String(error) });
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
    res.status(500).json({ error: String(error) });
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
    res.status(500).json({ error: String(error) });
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
    
    const result = await hord.createAttestation(content, metadata);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
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
    res.status(500).json({ error: String(error) });
  }
});


// =============================================================================
// Yoxallismus Cipher
// =============================================================================

/**
 * POST /api/v1/hord/yoxallismus/lock
 * Lock data with Yoxallismus vault cipher
 */
router.post("/yoxallismus/lock", async (req: Request, res: Response) => {
  try {
    const { data, key, tumblers, entropy_ratio, revolving } = req.body;
    
    if (!data || !key) {
      return res.status(400).json({ error: "data and key are required" });
    }
    
    const result = await hord.yoxallismusLock(data, key, { tumblers, entropy_ratio, revolving });
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

/**
 * POST /api/v1/hord/yoxallismus/unlock
 * Unlock data with Yoxallismus vault cipher
 */
router.post("/yoxallismus/unlock", async (req: Request, res: Response) => {
  try {
    const { data, key } = req.body;
    
    if (!data || !key) {
      return res.status(400).json({ error: "data and key are required" });
    }
    
    const result = await hord.yoxallismusUnlock(data, key);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

/**
 * GET /api/v1/hord/yoxallismus/info
 * Get Yoxallismus cipher info
 */
router.get("/yoxallismus/info", async (_req: Request, res: Response) => {
  try {
    res.json({
      name: "Yoxallismus Vault Cipher",
      description: "Dual-mechanism obfuscation (tumbler + deadbolt)",
      options: {
        tumblers: { default: 7, min: 1, max: 12, description: "Number of dial positions" },
        entropy_ratio: { default: 0.2, min: 0.1, max: 0.5, description: "Decoy byte ratio" },
        revolving: { default: true, description: "Pattern changes per block" },
        block_size: { default: 64, description: "Processing block size" }
      }
    });
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

export { router as hordRoutes };
