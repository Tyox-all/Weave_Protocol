/**
 * Mund REST API Routes
 * Guardian Protocol - Pattern Detection & Threat Scanning
 */

import { Router, Request, Response } from 'express';
import { MundService } from '../services/mund.js';

/** Bad input (unknown scan type, malformed rule) is a 400; anything else a 500. */
function fail(res: Response, error: unknown) {
  const msg = error instanceof Error ? error.message : String(error);
  res.status(/unknown scan type|rule needs|not a valid regular expression/i.test(msg) ? 400 : 500).json({ error: msg });
}

const router = Router();
const mund = new MundService();

// =============================================================================
// Scanning Endpoints
// =============================================================================

/**
 * POST /api/v1/mund/scan
 * Full security scan on content
 */
router.post('/scan', async (req: Request, res: Response) => {
  try {
    const { content, scan_types } = req.body;
    
    if (!content) {
      return res.status(400).json({ error: 'content is required' });
    }
    
    const result = await mund.scan(content, scan_types);
    res.json(result);
  } catch (error) {
    fail(res, error);
  }
});

/**
 * POST /api/v1/mund/scan/secrets
 * Scan for secrets and credentials
 */
router.post('/scan/secrets', async (req: Request, res: Response) => {
  try {
    const { content } = req.body;
    
    if (!content) {
      return res.status(400).json({ error: 'content is required' });
    }
    
    const result = await mund.scanSecrets(content);
    res.json(result);
  } catch (error) {
    fail(res, error);
  }
});

/**
 * POST /api/v1/mund/scan/pii
 * Scan for personally identifiable information
 */
router.post('/scan/pii', async (req: Request, res: Response) => {
  try {
    const { content } = req.body;
    
    if (!content) {
      return res.status(400).json({ error: 'content is required' });
    }
    
    const result = await mund.scanPII(content);
    res.json(result);
  } catch (error) {
    fail(res, error);
  }
});

/**
 * POST /api/v1/mund/scan/injection
 * Detect prompt injection attempts
 */
router.post('/scan/injection', async (req: Request, res: Response) => {
  try {
    const { content } = req.body;
    
    if (!content) {
      return res.status(400).json({ error: 'content is required' });
    }
    
    const result = await mund.scanInjection(content);
    res.json(result);
  } catch (error) {
    fail(res, error);
  }
});

/**
 * POST /api/v1/mund/scan/exfiltration
 * Detect data exfiltration patterns
 */
router.post('/scan/exfiltration', async (req: Request, res: Response) => {
  try {
    const { content } = req.body;
    
    if (!content) {
      return res.status(400).json({ error: 'content is required' });
    }
    
    const result = await mund.scanExfiltration(content);
    res.json(result);
  } catch (error) {
    fail(res, error);
  }
});

/**
 * POST /api/v1/mund/scan/code
 * Analyze code for security issues
 */
router.post('/scan/code', async (req: Request, res: Response) => {
  try {
    const { code, language } = req.body;
    
    if (!code) {
      return res.status(400).json({ error: 'code is required' });
    }
    
    const result = await mund.analyzeCode(code, language);
    res.json(result);
  } catch (error) {
    fail(res, error);
  }
});

// =============================================================================
// Rules Management
// =============================================================================

/**
 * GET /api/v1/mund/rules
 * Get all detection rules
 */
router.get('/rules', async (_req: Request, res: Response) => {
  try {
    const rules = await mund.getRules();
    res.json(rules);
  } catch (error) {
    fail(res, error);
  }
});

/**
 * POST /api/v1/mund/rules
 * Add a custom detection rule
 */
router.post('/rules', async (req: Request, res: Response) => {
  try {
    const rule = req.body;
    const result = await mund.addRule(rule);
    res.json(result);
  } catch (error) {
    fail(res, error);
  }
});

/**
 * PUT /api/v1/mund/rules/:id/enable
 * Enable a rule
 */
router.put('/rules/:id/enable', async (req: Request, res: Response) => {
  try {
    const result = await mund.enableRule(req.params.id);
    res.json(result);
  } catch (error) {
    fail(res, error);
  }
});

/**
 * PUT /api/v1/mund/rules/:id/disable
 * Disable a rule
 */
router.put('/rules/:id/disable', async (req: Request, res: Response) => {
  try {
    const result = await mund.disableRule(req.params.id);
    res.json(result);
  } catch (error) {
    fail(res, error);
  }
});

// =============================================================================
// Stats
// =============================================================================

/**
 * GET /api/v1/mund/stats
 * Get scanning statistics
 */
router.get('/stats', async (_req: Request, res: Response) => {
  try {
    const stats = await mund.getStats();
    res.json(stats);
  } catch (error) {
    fail(res, error);
  }
});

export { router as mundRoutes };
