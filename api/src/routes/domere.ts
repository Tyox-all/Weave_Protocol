/**
 * Dōmere REST API Routes
 * Judge Protocol - Thread Identity & Blockchain Anchoring
 */

import { Router, Request, Response } from 'express';
import { DomereService } from '../services/domere.js';

const router = Router();
const domere = new DomereService();

// =============================================================================
// Thread Management
// =============================================================================

/**
 * POST /api/v1/domere/threads
 * Create a new thread
 */
router.post('/threads', async (req: Request, res: Response) => {
  try {
    const { origin_type, origin_identity, intent, constraints, metadata } = req.body;
    
    if (!origin_type || !origin_identity || !intent) {
      return res.status(400).json({ error: 'origin_type, origin_identity, and intent are required' });
    }
    
    const result = await domere.createThread({
      origin_type,
      origin_identity,
      intent,
      constraints,
      metadata
    });
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

/**
 * GET /api/v1/domere/threads
 * List threads
 */
router.get('/threads', async (req: Request, res: Response) => {
  try {
    const { status, origin_identity, limit } = req.query;
    const threads = await domere.listThreads({
      status: status as string,
      origin_identity: origin_identity as string,
      limit: limit ? parseInt(limit as string) : undefined
    });
    res.json(threads);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

/**
 * GET /api/v1/domere/threads/:id
 * Get thread details
 */
router.get('/threads/:id', async (req: Request, res: Response) => {
  try {
    const thread = await domere.getThread(req.params.id);
    res.json(thread);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

/**
 * POST /api/v1/domere/threads/:id/hops
 * Add a hop to thread
 */
router.post('/threads/:id/hops', async (req: Request, res: Response) => {
  try {
    const { agent_id, agent_type, received_intent, actions } = req.body;
    
    if (!agent_id || !agent_type || !received_intent || !actions) {
      return res.status(400).json({ 
        error: 'agent_id, agent_type, received_intent, and actions are required' 
      });
    }
    
    const result = await domere.addHop({
      thread_id: req.params.id,
      agent_id,
      agent_type,
      received_intent,
      actions
    });
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

/**
 * POST /api/v1/domere/threads/:id/close
 * Close a thread
 */
router.post('/threads/:id/close', async (req: Request, res: Response) => {
  try {
    const { outcome } = req.body;
    
    if (!outcome) {
      return res.status(400).json({ error: 'outcome is required (success, failure, abandoned)' });
    }
    
    const result = await domere.closeThread(req.params.id, outcome);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

/**
 * POST /api/v1/domere/threads/:id/verify
 * Verify thread integrity
 */
router.post('/threads/:id/verify', async (req: Request, res: Response) => {
  try {
    const result = await domere.verifyThread(req.params.id);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

// =============================================================================
// Intent & Drift
// =============================================================================

/**
 * POST /api/v1/domere/intent/analyze
 * Analyze intent
 */
router.post('/intent/analyze', async (req: Request, res: Response) => {
  try {
    const { content } = req.body;
    
    if (!content) {
      return res.status(400).json({ error: 'content is required' });
    }
    
    const result = await domere.analyzeIntent(content);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

/**
 * POST /api/v1/domere/drift/check
 * Check intent drift
 */
router.post('/drift/check', async (req: Request, res: Response) => {
  try {
    const { original_intent, current_intent, constraints } = req.body;
    
    if (!original_intent || !current_intent) {
      return res.status(400).json({ error: 'original_intent and current_intent are required' });
    }
    
    const result = await domere.checkDrift(original_intent, current_intent, constraints);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

/**
 * POST /api/v1/domere/intent/compare
 * Compare two intents
 */
router.post('/intent/compare', async (req: Request, res: Response) => {
  try {
    const { intent1, intent2 } = req.body;
    
    if (!intent1 || !intent2) {
      return res.status(400).json({ error: 'intent1 and intent2 are required' });
    }
    
    const result = await domere.compareIntents(intent1, intent2);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

// =============================================================================
// Language Analysis
// =============================================================================

/**
 * POST /api/v1/domere/language/detect
 * Detect language in content
 */
router.post('/language/detect', async (req: Request, res: Response) => {
  try {
    const { content } = req.body;
    
    if (!content) {
      return res.status(400).json({ error: 'content is required' });
    }
    
    const result = await domere.detectLanguage(content);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

/**
 * POST /api/v1/domere/language/analyze
 * Full semantic analysis
 */
router.post('/language/analyze', async (req: Request, res: Response) => {
  try {
    const { content } = req.body;
    
    if (!content) {
      return res.status(400).json({ error: 'content is required' });
    }
    
    const result = await domere.analyzeContent(content);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

/**
 * POST /api/v1/domere/injection/check
 * Check for prompt injection
 */
router.post('/injection/check', async (req: Request, res: Response) => {
  try {
    const { content } = req.body;
    
    if (!content) {
      return res.status(400).json({ error: 'content is required' });
    }
    
    const result = await domere.checkInjection(content);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

// =============================================================================
// Blockchain Anchoring (PAID)
// =============================================================================

/**
 * GET /api/v1/domere/anchor/estimate
 * Estimate anchoring cost
 */
router.get('/anchor/estimate', async (req: Request, res: Response) => {
  try {
    const { network } = req.query;
    
    if (!network) {
      return res.status(400).json({ error: 'network query param is required (solana, ethereum)' });
    }
    
    const result = await domere.estimateAnchorCost(network as string);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

/**
 * POST /api/v1/domere/anchor/prepare
 * Prepare anchor transaction (returns unsigned tx for client signing)
 */
router.post('/anchor/prepare', async (req: Request, res: Response) => {
  try {
    const { thread_id, network } = req.body;
    
    if (!thread_id || !network) {
      return res.status(400).json({ error: 'thread_id and network are required' });
    }
    
    const result = await domere.prepareAnchor(thread_id, network);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

/**
 * POST /api/v1/domere/anchor/submit
 * Submit signed transaction
 */
router.post('/anchor/submit', async (req: Request, res: Response) => {
  try {
    const { network, signed_transaction } = req.body;
    
    if (!network || !signed_transaction) {
      return res.status(400).json({ error: 'network and signed_transaction are required' });
    }
    
    const result = await domere.submitAnchor(network, signed_transaction);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

/**
 * POST /api/v1/domere/anchor/verify
 * Verify an on-chain anchor
 */
router.post('/anchor/verify', async (req: Request, res: Response) => {
  try {
    const { network, thread_id, merkle_root } = req.body;
    
    if (!network || !thread_id || !merkle_root) {
      return res.status(400).json({ error: 'network, thread_id, and merkle_root are required' });
    }
    
    const result = await domere.verifyAnchor(network, thread_id, merkle_root);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

/**
 * GET /api/v1/domere/anchor/:thread_id/status
 * Get anchor status for thread
 */
router.get('/anchor/:thread_id/status', async (req: Request, res: Response) => {
  try {
    const result = await domere.getAnchorStatus(req.params.thread_id);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});


// =============================================================================
// Compliance (SOC2, HIPAA, PCI-DSS, ISO27001)
// =============================================================================

/**
 * POST /api/v1/domere/compliance/checkpoint
 */
router.post("/compliance/checkpoint", async (req: Request, res: Response) => {
  try {
    const { thread_id, framework, control, event_type, event_description, data_classification, agent_id, user_id, risk_level, sign } = req.body;
    if (!thread_id || !framework || !control || !event_type || !agent_id) {
      return res.status(400).json({ error: "thread_id, framework, control, event_type, and agent_id are required" });
    }
    const result = await domere.createCheckpoint({ thread_id, framework, control, event_type, event_description, data_classification, agent_id, user_id, risk_level, sign });
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

/**
 * POST /api/v1/domere/compliance/cardholder (PCI-DSS)
 */
router.post("/compliance/cardholder", async (req: Request, res: Response) => {
  try {
    const { thread_id, agent_id, data_type, action, masked, encrypted, business_justification } = req.body;
    if (!thread_id || !agent_id || !data_type || !action || !business_justification) {
      return res.status(400).json({ error: "thread_id, agent_id, data_type, action, and business_justification are required" });
    }
    const result = await domere.logCardholderDataAccess({ thread_id, agent_id, data_type, action, masked: masked ?? false, encrypted: encrypted ?? false, business_justification });
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

/**
 * POST /api/v1/domere/compliance/incident (ISO27001)
 */
router.post("/compliance/incident", async (req: Request, res: Response) => {
  try {
    const { thread_id, agent_id, incident_id, incident_type, severity, status, affected_assets, description } = req.body;
    if (!thread_id || !agent_id || !incident_id || !incident_type || !severity || !status) {
      return res.status(400).json({ error: "thread_id, agent_id, incident_id, incident_type, severity, and status are required" });
    }
    const result = await domere.logSecurityIncident({ thread_id, agent_id, incident_id, incident_type, severity, status, affected_assets: affected_assets || [], description });
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

/**
 * POST /api/v1/domere/compliance/asset (ISO27001)
 */
router.post("/compliance/asset", async (req: Request, res: Response) => {
  try {
    const { thread_id, agent_id, asset_id, asset_type, action, classification } = req.body;
    if (!thread_id || !agent_id || !asset_id || !asset_type || !action || !classification) {
      return res.status(400).json({ error: "thread_id, agent_id, asset_id, asset_type, action, and classification are required" });
    }
    const result = await domere.logAssetEvent({ thread_id, agent_id, asset_id, asset_type, action, classification });
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

/**
 * POST /api/v1/domere/compliance/report
 */
router.post("/compliance/report", async (req: Request, res: Response) => {
  try {
    const { framework, period_start, period_end } = req.body;
    if (!framework || !period_start || !period_end) {
      return res.status(400).json({ error: "framework, period_start, and period_end are required" });
    }
    const result = await domere.generateComplianceReport({ framework, period_start: new Date(period_start), period_end: new Date(period_end) });
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

/**
 * GET /api/v1/domere/compliance/frameworks
 */
router.get("/compliance/frameworks", async (_req: Request, res: Response) => {
  res.json({
    frameworks: [
      { id: "SOC2", name: "SOC 2 Type II", controls: ["CC6.1", "CC6.2", "CC6.3", "CC6.4"] },
      { id: "HIPAA", name: "HIPAA", controls: ["ACCESS_CONTROL", "AUDIT_CONTROLS", "INTEGRITY"] },
      { id: "PCI-DSS", name: "PCI-DSS v4.0", controls: ["REQ1", "REQ2", "REQ3", "REQ4", "REQ5", "REQ6", "REQ7", "REQ8", "REQ9", "REQ10", "REQ11", "REQ12"] },
      { id: "ISO27001", name: "ISO 27001:2022", controls: ["A5", "A6", "A7", "A8", "A9", "A10", "A11", "A12", "A13", "A14", "A15", "A16", "A17", "A18"] }
    ]
  });
});

export { router as domereRoutes };
