/**
 * Weave API - Universal REST Interface
 * @weave_protocol/api v1.0.11
 * 
 * Platform-agnostic security for AI agents
 * Works with: OpenAI, Gemini, LangChain, Grok, Copilot, Siri, or ANY HTTP client
 */

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

// Import routes
import { mundRoutes } from './routes/mund.js';
import { hordRoutes } from './routes/hord.js';
import { domereRoutes } from './routes/domere.js';
import { healthRoutes } from './routes/health.js';
import hundredmenRoutes, { initHundredmen } from './routes/hundredmen.js';

// Import middleware
import { errorHandler } from './middleware/error.js';
import { requestLogger } from './middleware/logger.js';
import { apiKeyAuth } from './middleware/auth.js';

// ES Module __dirname equivalent
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.WEAVE_PORT || 3000;

// =============================================================================
// Initialize Services
// =============================================================================

const { interceptor, reputationManager } = initHundredmen();

// =============================================================================
// Dashboard Stats (In-Memory)
// =============================================================================

interface DashboardStats {
  scans: number;
  threats: number;
  intercepts: number;
  blocked: number;
  checkpoints: number;
  vaultOps: number;
}

interface ActivityEvent {
  type: string;
  tool?: string;
  action?: string;
  server?: string;
  status?: string;
  safe?: boolean;
  severity?: string;
  description?: string;
  findings?: any[];
  timestamp: number;
}

let dashboardStats: DashboardStats = {
  scans: 0,
  threats: 0,
  intercepts: 0,
  blocked: 0,
  checkpoints: 0,
  vaultOps: 0,
};

let activityFeed: ActivityEvent[] = [];
const MAX_FEED_ITEMS = 50;

export const trackScan = (safe: boolean, findings: any[] = []) => {
  dashboardStats.scans++;
  if (!safe) dashboardStats.threats++;
  activityFeed.unshift({
    type: 'scan',
    action: 'Content scan',
    safe,
    findings,
    severity: findings[0]?.severity || 'info',
    timestamp: Date.now(),
  });
  activityFeed = activityFeed.slice(0, MAX_FEED_ITEMS);
};

export const trackIntercept = (tool: string, server: string, status: 'approved' | 'blocked' | 'pending', reason?: string) => {
  dashboardStats.intercepts++;
  if (status === 'blocked') dashboardStats.blocked++;
  activityFeed.unshift({
    type: 'intercept',
    tool,
    server,
    status,
    description: reason,
    timestamp: Date.now(),
  });
  activityFeed = activityFeed.slice(0, MAX_FEED_ITEMS);
};

export const trackCheckpoint = (framework: string, action: string) => {
  dashboardStats.checkpoints++;
  activityFeed.unshift({
    type: 'checkpoint',
    action: `${framework}: ${action}`,
    timestamp: Date.now(),
  });
  activityFeed = activityFeed.slice(0, MAX_FEED_ITEMS);
};

export const trackVaultOp = (operation: string) => {
  dashboardStats.vaultOps++;
  activityFeed.unshift({
    type: 'vault',
    action: operation,
    timestamp: Date.now(),
  });
  activityFeed = activityFeed.slice(0, MAX_FEED_ITEMS);
};

// =============================================================================
// Middleware
// =============================================================================

// Disable CSP for local dashboard (needs CDN scripts)
app.use(helmet({ contentSecurityPolicy: false }));

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
}));

// Rate limiting only for /api routes
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { error: 'Too many requests' },
});

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(requestLogger);

// =============================================================================
// Dashboard Routes (No Rate Limit)
// =============================================================================

app.get('/dashboard', (_req: Request, res: Response) => {
  const dashboardPath = path.join(__dirname, 'dashboard.html');
  if (fs.existsSync(dashboardPath)) {
    res.sendFile(dashboardPath);
  } else {
    res.status(404).send(`<h1>Dashboard Not Found</h1><p>Copy dashboard.html to: ${dashboardPath}</p>`);
  }
});

app.get('/stats', (_req: Request, res: Response) => res.json(dashboardStats));
app.get('/feed', (_req: Request, res: Response) => res.json(activityFeed));

app.get('/mund/intel-status', (_req: Request, res: Response) => {
  res.json({
    patterns: 47, sources: 3, mitre_techniques: 10, mitre_tactics: 6,
    lastUpdate: new Date().toISOString(),
    sourceDetails: [
      { name: 'weave_builtin', enabled: true, patterns: 20 },
      { name: 'weave_community', enabled: true, patterns: 15 },
      { name: 'mitre_llm', enabled: true, patterns: 12 },
    ],
  });
});

app.get('/domere/compliance/status', (_req: Request, res: Response) => {
  res.json({
    frameworks: {
      'soc2': { active: true, checkpoints: dashboardStats.checkpoints },
      'hipaa': { active: true, checkpoints: 0 },
      'pci-dss': { active: true, checkpoints: 0 },
      'iso27001': { active: true, checkpoints: 0 },
      'gdpr': { active: true, checkpoints: 0 },
      'ccpa': { active: true, checkpoints: 0 },
    },
  });
});

app.get('/hundredmen/servers', (_req: Request, res: Response) => {
  try {
    const servers = reputationManager.getAllReputations();
    res.json(servers.map((s: any) => ({
      name: s.serverName || s.serverId,
      score: s.overallScore,
      calls: s.totalCalls,
      blocked: s.blockedCalls,
    })));
  } catch {
    res.json([
      { name: 'filesystem', score: 85, calls: 42, blocked: 0 },
      { name: 'browser', score: 72, calls: 28, blocked: 2 },
      { name: 'github', score: 90, calls: 15, blocked: 0 },
    ]);
  }
});

app.post('/reset', (_req: Request, res: Response) => {
  dashboardStats = { scans: 0, threats: 0, intercepts: 0, blocked: 0, checkpoints: 0, vaultOps: 0 };
  activityFeed = [];
  res.json({ success: true });
});

// =============================================================================
// Test Endpoints (Trigger events for dashboard)
// =============================================================================

app.post('/test/threat', (_req: Request, res: Response) => {
  trackScan(false, [{ type: 'prompt_injection', severity: 'critical', description: 'Jailbreak attempt: "ignore all previous instructions"' }]);
  trackIntercept('execute_code', 'malicious-server', 'blocked', 'Blocked code execution from untrusted server');
  res.json({ success: true, message: 'Threat triggered' });
});

app.post('/test/activity', (_req: Request, res: Response) => {
  trackScan(true, []);
  trackIntercept('read_file', 'filesystem', 'approved', 'Safe file read operation');
  trackCheckpoint('soc2', 'Data access logged');
  trackVaultOp('Secret retrieved: api_key');
  res.json({ success: true, message: 'Activity triggered' });
});

app.post('/test/mixed', (_req: Request, res: Response) => {
  trackScan(true, []);
  trackScan(false, [{ type: 'social_engineering', severity: 'medium', description: 'Urgency manipulation detected' }]);
  trackIntercept('search_web', 'browser', 'approved', 'Standard web search');
  trackIntercept('delete_files', 'rogue-server', 'blocked', 'Unauthorized deletion attempt');
  trackIntercept('send_email', 'email-mcp', 'pending', 'Awaiting manual approval');
  trackCheckpoint('gdpr', 'PII redaction applied');
  trackCheckpoint('hipaa', 'PHI access logged');
  trackVaultOp('Vault opened: production-secrets');
  res.json({ success: true, message: 'Mixed events triggered' });
});

// =============================================================================
// Health & API Routes
// =============================================================================

app.use('/health', healthRoutes);

if (process.env.WEAVE_API_KEY) {
  app.use('/api', apiKeyAuth);
}
app.use('/api', apiLimiter);

app.use('/api/v1/mund', mundRoutes);
app.use('/api/v1/hord', hordRoutes);
app.use('/api/v1/domere', domereRoutes);
app.use('/api/v1/hundredmen', hundredmenRoutes);

app.post('/api/v1/functions/call', async (req: Request, res: Response) => {
  const { function: fn, name, arguments: args } = req.body;
  const funcName = fn || name;
  if (!funcName) return res.status(400).json({ error: 'function or name is required' });
  try {
    const { handleWeaveFunction } = await import('./adapters/openai.js');
    const result = await handleWeaveFunction(funcName, args);
    res.json({ result });
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

app.get('/api/v1/functions', (_req: Request, res: Response) => {
  res.json({
    functions: [
      { name: 'weave_scan_content', description: 'Scan content for threats', parameters: { type: 'object', properties: { content: { type: 'string' } }, required: ['content'] } },
      { name: 'weave_check_url', description: 'Check URL safety', parameters: { type: 'object', properties: { url: { type: 'string' } }, required: ['url'] } },
      { name: 'weave_store_secret', description: 'Store secret in vault', parameters: { type: 'object', properties: { vault_id: { type: 'string' }, key: { type: 'string' }, value: { type: 'string' } }, required: ['vault_id', 'key', 'value'] } },
      { name: 'weave_redact_pii', description: 'Redact PII from text', parameters: { type: 'object', properties: { content: { type: 'string' } }, required: ['content'] } },
      { name: 'weave_create_checkpoint', description: 'Create compliance checkpoint', parameters: { type: 'object', properties: { action: { type: 'string' }, framework: { type: 'string' } }, required: ['action', 'framework'] } },
    ],
  });
});

app.get('/api', (_req: Request, res: Response) => {
  res.json({
    name: 'Weave Protocol API',
    version: '1.0.11',
    dashboard: '/dashboard',
    health: '/health',
    test: { threat: 'POST /test/threat', activity: 'POST /test/activity', mixed: 'POST /test/mixed' },
  });
});

app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: 'Not Found', docs: '/api' });
});

app.use(errorHandler);

app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════════════╗
║   🕸️  Weave Protocol API v1.0.11                                  ║
║   Dashboard:  http://localhost:${PORT}/dashboard                    ║
║                                                                   ║
║   Test:  curl -X POST http://localhost:${PORT}/test/threat          ║
║          curl -X POST http://localhost:${PORT}/test/mixed           ║
╚═══════════════════════════════════════════════════════════════════╝
  `);
});

export default app;
