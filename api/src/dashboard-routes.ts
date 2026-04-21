import { Router, Request, Response } from 'express';
import * as path from 'path';
import * as fs from 'fs';

const router = Router();

// In-memory stores for current session
let stats = {
  scans: 0,
  threats: 0,
  intercepts: 0,
  blocked: 0,
  checkpoints: 0,
  vaultOps: 0,
};

let activityFeed: Array<{
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
}> = [];

// Keep feed to last 50 items
const MAX_FEED_ITEMS = 50;

// Export functions for other routes to call when events happen
export const trackScan = (safe: boolean, findings: any[] = []) => {
  stats.scans++;
  if (!safe) stats.threats++;
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
  stats.intercepts++;
  if (status === 'blocked') stats.blocked++;
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
  stats.checkpoints++;
  activityFeed.unshift({
    type: 'checkpoint',
    action: `${framework}: ${action}`,
    timestamp: Date.now(),
  });
  activityFeed = activityFeed.slice(0, MAX_FEED_ITEMS);
};

export const trackVaultOp = (operation: string) => {
  stats.vaultOps++;
  activityFeed.unshift({
    type: 'vault',
    action: operation,
    timestamp: Date.now(),
  });
  activityFeed = activityFeed.slice(0, MAX_FEED_ITEMS);
};

// GET /api/stats - overall stats
router.get('/stats', (_req: Request, res: Response) => {
  res.json(stats);
});

// GET /api/feed - live activity feed
router.get('/feed', (_req: Request, res: Response) => {
  res.json(activityFeed);
});

// GET /api/mund/intel-status - threat intel status
router.get('/mund/intel-status', (_req: Request, res: Response) => {
  // This would ideally call into Mund's threat intel module
  // For now, return current known status
  res.json({
    patterns: 47,
    sources: 3,
    mitre_techniques: 10,
    mitre_tactics: 6,
    lastUpdate: new Date().toISOString(),
    sourceDetails: [
      { name: 'weave_builtin', enabled: true, patterns: 20, autoUpdate: false },
      { name: 'weave_community', enabled: true, patterns: 15, autoUpdate: true, interval: '24h' },
      { name: 'mitre_llm', enabled: true, patterns: 12, autoUpdate: true, interval: '7d' },
    ],
  });
});

// GET /api/domere/compliance/status - compliance framework status
router.get('/domere/compliance/status', (_req: Request, res: Response) => {
  res.json({
    frameworks: {
      'soc2': { active: true, checkpoints: stats.checkpoints },
      'hipaa': { active: true, checkpoints: 0 },
      'pci-dss': { active: true, checkpoints: 0 },
      'iso27001': { active: true, checkpoints: 0 },
      'gdpr': { active: true, checkpoints: 0 },
      'ccpa': { active: true, checkpoints: 0 },
    },
  });
});

// GET /api/hundredmen/servers - MCP server reputation
router.get('/hundredmen/servers', (_req: Request, res: Response) => {
  // This would pull from Hundredmen's reputation manager
  // Return sample data for now
  res.json([
    { name: 'filesystem', score: 85, calls: 42, blocked: 0 },
    { name: 'browser', score: 72, calls: 28, blocked: 2 },
    { name: 'github', score: 90, calls: 15, blocked: 0 },
  ]);
});

// GET /dashboard - serve the dashboard HTML
router.get('/dashboard', (_req: Request, res: Response) => {
  const dashboardPath = path.join(__dirname, 'dashboard.html');
  if (fs.existsSync(dashboardPath)) {
    res.sendFile(dashboardPath);
  } else {
    res.status(404).send('Dashboard not found. Place dashboard.html in the src directory.');
  }
});

// POST /api/reset - reset stats (for testing)
router.post('/reset', (_req: Request, res: Response) => {
  stats = { scans: 0, threats: 0, intercepts: 0, blocked: 0, checkpoints: 0, vaultOps: 0 };
  activityFeed = [];
  res.json({ success: true });
});

export default router;
