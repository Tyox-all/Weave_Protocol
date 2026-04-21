/**
 * Hundredmen Routes
 * @weave_protocol/api
 * 
 * REST + SSE endpoints for MCP security proxy
 * Fintech-friendly: no WebSockets required
 */

import { Router, Request, Response } from 'express';

// Types for interceptor (will be imported from @weave_protocol/hundredmen)
interface InterceptorConfig {
  mode: 'passive' | 'active' | 'strict';
  scanEnabled: boolean;
  driftDetectionEnabled: boolean;
  reputationEnabled: boolean;
  minReputationScore?: number;
  requireApprovalFor?: string[];
  driftThreshold?: number;
}

interface CallRecord {
  id: string;
  timestamp: Date;
  sourceServer: string;
  tool: string;
  arguments: any;
  status: 'pending' | 'approved' | 'blocked' | 'completed';
  decision?: string;
  decisionReason?: string;
  driftDetected?: boolean;
  intent?: {
    inferredIntent: string;
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
    categories: string[];
  };
}

interface Session {
  id: string;
  startedAt: Date;
  agentId?: string;
  declaredIntents: string[];
  totalCalls: number;
  approvedCalls: number;
  blockedCalls: number;
  pendingCalls: number;
  activeServers: string[];
}

interface Reputation {
  serverId: string;
  serverName: string;
  overallScore: number;
  trustScore: number;
  securityScore: number;
  communityScore: number;
  verified: boolean;
  knownMalicious: boolean;
  communityReports: number;
  totalCalls: number;
  blockedCalls: number;
  firstSeen: Date;
  lastSeen: Date;
}

// In-memory stores (replace with @weave_protocol/hundredmen imports)
let interceptorConfig: InterceptorConfig = {
  mode: 'active',
  scanEnabled: true,
  driftDetectionEnabled: true,
  reputationEnabled: true,
  minReputationScore: 30,
  requireApprovalFor: ['delete_data', 'execute_code', 'send_email'],
  driftThreshold: 0.5,
};

const calls: CallRecord[] = [];
const sessions: Map<string, Session> = new Map();
const reputations: Map<string, Reputation> = new Map();
const eventListeners: Set<(event: any) => void> = new Set();

// Helper to generate IDs
const generateId = () => `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

// Helper to emit events
const emitEvent = (event: any) => {
  eventListeners.forEach(listener => {
    try {
      listener(event);
    } catch (e) {
      console.error('Event listener error:', e);
    }
  });
};

// Initialize function (called from main index.ts)
export function initHundredmen() {
  // Initialize with some sample verified servers
  const verifiedServers = [
    { id: 'filesystem', name: 'Filesystem MCP', score: 85 },
    { id: 'github', name: 'GitHub MCP', score: 90 },
    { id: 'slack', name: 'Slack MCP', score: 88 },
  ];
  
  verifiedServers.forEach(s => {
    reputations.set(s.id, {
      serverId: s.id,
      serverName: s.name,
      overallScore: s.score,
      trustScore: s.score,
      securityScore: s.score,
      communityScore: s.score,
      verified: true,
      knownMalicious: false,
      communityReports: 0,
      totalCalls: 0,
      blockedCalls: 0,
      firstSeen: new Date(),
      lastSeen: new Date(),
    });
  });
  
  return {
    interceptor: {
      on: (event: string, callback: (e: any) => void) => eventListeners.add(callback),
      off: (event: string, callback: (e: any) => void) => eventListeners.delete(callback),
    },
    reputationManager: {
      getAllReputations: () => Array.from(reputations.values()),
      getVerifiedServers: () => Array.from(reputations.values()).filter(r => r.verified),
      getMaliciousServers: () => Array.from(reputations.values()).filter(r => r.knownMalicious),
      getLowReputationServers: (threshold = 30) => 
        Array.from(reputations.values()).filter(r => r.overallScore < threshold),
      getScore: (serverId: string) => reputations.get(serverId)?.overallScore || 50,
    },
  };
}

const router = Router();

// =============================================================================
// SSE - Server-Sent Events (Real-time, fintech-friendly)
// =============================================================================

/**
 * GET /stream
 * Server-Sent Events stream for real-time updates.
 */
router.get('/stream', (req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  
  res.write(`event: connected\ndata: ${JSON.stringify({ timestamp: new Date() })}\n\n`);
  
  const keepAlive = setInterval(() => {
    res.write(`: ping\n\n`);
  }, 30000);
  
  const onEvent = (event: any) => {
    res.write(`event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`);
  };
  
  eventListeners.add(onEvent);
  
  req.on('close', () => {
    clearInterval(keepAlive);
    eventListeners.delete(onEvent);
  });
});

// =============================================================================
// Feed & History
// =============================================================================

/**
 * GET /feed
 * Poll for recent calls.
 */
router.get('/feed', (req: Request, res: Response) => {
  const since = req.query.since ? new Date(req.query.since as string) : undefined;
  const limit = parseInt(req.query.limit as string) || 50;
  const status = req.query.status as string;
  const sessionId = req.query.session_id as string;
  
  let filtered = [...calls];
  
  if (since) {
    filtered = filtered.filter(c => c.timestamp > since);
  }
  if (status) {
    filtered = filtered.filter(c => c.status === status);
  }
  
  filtered = filtered.slice(0, limit);
  
  res.json({
    success: true,
    count: filtered.length,
    timestamp: new Date(),
    calls: filtered.map(c => ({
      id: c.id,
      timestamp: c.timestamp,
      server: c.sourceServer,
      tool: c.tool,
      status: c.status,
      decision: c.decision,
      decision_reason: c.decisionReason,
      risk_level: c.intent?.riskLevel,
      drift_detected: c.driftDetected,
      inferred_intent: c.intent?.inferredIntent,
    })),
  });
});

/**
 * GET /pending
 * Get all calls awaiting manual approval.
 */
router.get('/pending', (_req: Request, res: Response) => {
  const pending = calls.filter(c => c.status === 'pending');
  
  res.json({
    success: true,
    count: pending.length,
    pending: pending.map(c => ({
      id: c.id,
      timestamp: c.timestamp,
      server: c.sourceServer,
      tool: c.tool,
      arguments: c.arguments,
      risk_level: c.intent?.riskLevel,
      decision_reason: c.decisionReason,
      inferred_intent: c.intent?.inferredIntent,
      categories: c.intent?.categories,
    })),
  });
});

/**
 * POST /approve/:id
 * Approve a pending call.
 */
router.post('/approve/:id', (req: Request, res: Response) => {
  const { id } = req.params;
  const { approved_by } = req.body || {};
  
  const call = calls.find(c => c.id === id && c.status === 'pending');
  
  if (!call) {
    return res.status(404).json({
      success: false,
      error: 'Call not found or not pending',
    });
  }
  
  call.status = 'approved';
  call.decision = 'approved';
  call.decisionReason = `Manually approved by ${approved_by || 'api_user'}`;
  
  emitEvent({ type: 'call_approved', call });
  
  res.json({
    success: true,
    call_id: call.id,
    status: call.status,
    message: `Call approved: ${call.tool}`,
  });
});

/**
 * POST /block/:id
 * Block a pending call.
 */
router.post('/block/:id', (req: Request, res: Response) => {
  const { id } = req.params;
  const { blocked_by, reason } = req.body || {};
  
  const call = calls.find(c => c.id === id && c.status === 'pending');
  
  if (!call) {
    return res.status(404).json({
      success: false,
      error: 'Call not found or not pending',
    });
  }
  
  call.status = 'blocked';
  call.decision = 'blocked';
  call.decisionReason = reason || `Manually blocked by ${blocked_by || 'api_user'}`;
  
  emitEvent({ type: 'call_blocked', call });
  
  res.json({
    success: true,
    call_id: call.id,
    status: call.status,
    message: `Call blocked: ${call.tool}`,
  });
});

// =============================================================================
// Session Management
// =============================================================================

/**
 * POST /session
 * Create a new inspection session.
 */
router.post('/session', (req: Request, res: Response) => {
  const { agent_id } = req.body || {};
  
  const session: Session = {
    id: generateId(),
    startedAt: new Date(),
    agentId: agent_id,
    declaredIntents: [],
    totalCalls: 0,
    approvedCalls: 0,
    blockedCalls: 0,
    pendingCalls: 0,
    activeServers: [],
  };
  
  sessions.set(session.id, session);
  
  res.json({
    success: true,
    session_id: session.id,
    started_at: session.startedAt,
    message: 'Session created. Declare intent with POST /session/:id/intent',
  });
});

/**
 * POST /session/:id/intent
 * Declare intent for a session.
 */
router.post('/session/:id/intent', (req: Request, res: Response) => {
  const { id } = req.params;
  const { intent } = req.body;
  
  if (!intent) {
    return res.status(400).json({
      success: false,
      error: 'Missing intent in request body',
    });
  }
  
  const session = sessions.get(id);
  
  if (!session) {
    return res.status(404).json({
      success: false,
      error: 'Session not found',
    });
  }
  
  session.declaredIntents.push(intent);
  
  res.json({
    success: true,
    session_id: id,
    declared_intents: session.declaredIntents,
    message: `Intent recorded: "${intent}"`,
  });
});

/**
 * GET /session/:id/drift
 * Get drift analysis for a session.
 */
router.get('/session/:id/drift', (req: Request, res: Response) => {
  const { id } = req.params;
  
  const session = sessions.get(id);
  
  if (!session) {
    return res.status(404).json({
      success: false,
      error: 'Session not found',
    });
  }
  
  // In a real implementation, filter calls by session
  const sessionCalls = calls.slice(0, 10);
  const driftCalls = sessionCalls.filter(c => c.driftDetected);
  
  res.json({
    success: true,
    session_id: id,
    declared_intents: session.declaredIntents,
    total_calls: sessionCalls.length,
    drift_detected_count: driftCalls.length,
    drift_rate: sessionCalls.length > 0 
      ? `${(driftCalls.length / sessionCalls.length * 100).toFixed(1)}%` 
      : '0%',
    drift_calls: driftCalls.map(c => ({
      id: c.id,
      tool: c.tool,
      inferred_intent: c.intent?.inferredIntent,
      risk_level: c.intent?.riskLevel,
    })),
  });
});

/**
 * DELETE /session/:id
 * End a session and get summary.
 */
router.delete('/session/:id', (req: Request, res: Response) => {
  const { id } = req.params;
  
  const session = sessions.get(id);
  
  if (!session) {
    return res.status(404).json({
      success: false,
      error: 'Session not found',
    });
  }
  
  sessions.delete(id);
  
  res.json({
    success: true,
    session_id: id,
    summary: {
      duration_ms: Date.now() - session.startedAt.getTime(),
      total_calls: session.totalCalls,
      approved_calls: session.approvedCalls,
      blocked_calls: session.blockedCalls,
      pending_calls: session.pendingCalls,
      declared_intents: session.declaredIntents,
      active_servers: session.activeServers,
    },
  });
});

// =============================================================================
// Reputation
// =============================================================================

/**
 * GET /reputation/:serverId
 * Get reputation score for an MCP server.
 */
router.get('/reputation/:serverId', (req: Request, res: Response) => {
  const { serverId } = req.params;
  
  let reputation = reputations.get(serverId);
  
  if (!reputation) {
    // Create default reputation for unknown server
    reputation = {
      serverId,
      serverName: serverId,
      overallScore: 50,
      trustScore: 50,
      securityScore: 50,
      communityScore: 50,
      verified: false,
      knownMalicious: false,
      communityReports: 0,
      totalCalls: 0,
      blockedCalls: 0,
      firstSeen: new Date(),
      lastSeen: new Date(),
    };
    reputations.set(serverId, reputation);
  }
  
  res.json({
    success: true,
    server_id: reputation.serverId,
    server_name: reputation.serverName,
    overall_score: reputation.overallScore,
    trust_score: reputation.trustScore,
    security_score: reputation.securityScore,
    community_score: reputation.communityScore,
    verified: reputation.verified,
    known_malicious: reputation.knownMalicious,
    community_reports: reputation.communityReports,
    total_calls: reputation.totalCalls,
    blocked_calls: reputation.blockedCalls,
    first_seen: reputation.firstSeen,
    last_seen: reputation.lastSeen,
    recommendation: reputation.knownMalicious ? 'BLOCK' :
                    reputation.overallScore < 30 ? 'CAUTION' :
                    reputation.verified ? 'TRUSTED' : 'NEUTRAL',
  });
});

/**
 * POST /reputation/:serverId/report
 * Report suspicious behavior from a server.
 */
router.post('/reputation/:serverId/report', (req: Request, res: Response) => {
  const { serverId } = req.params;
  const { report_type, description, evidence, reported_by } = req.body;
  
  if (!report_type || !description) {
    return res.status(400).json({
      success: false,
      error: 'Missing report_type or description',
    });
  }
  
  let reputation = reputations.get(serverId);
  
  if (!reputation) {
    reputation = {
      serverId,
      serverName: serverId,
      overallScore: 50,
      trustScore: 50,
      securityScore: 50,
      communityScore: 50,
      verified: false,
      knownMalicious: false,
      communityReports: 0,
      totalCalls: 0,
      blockedCalls: 0,
      firstSeen: new Date(),
      lastSeen: new Date(),
    };
    reputations.set(serverId, reputation);
  }
  
  // Update reputation based on report
  reputation.communityReports++;
  reputation.communityScore = Math.max(0, reputation.communityScore - 10);
  reputation.overallScore = Math.round(
    (reputation.trustScore + reputation.securityScore + reputation.communityScore) / 3
  );
  
  const reportId = generateId();
  
  emitEvent({
    type: 'reputation_report',
    reportId,
    serverId,
    reportType: report_type,
    description,
  });
  
  res.json({
    success: true,
    report_id: reportId,
    server_id: serverId,
    new_score: reputation.overallScore,
    message: 'Report submitted. Server reputation has been updated.',
  });
});

/**
 * GET /servers
 * List all known servers with reputation scores.
 */
router.get('/servers', (req: Request, res: Response) => {
  const filter = req.query.filter as string;
  const minScore = parseInt(req.query.min_score as string) || 0;
  
  let servers = Array.from(reputations.values());
  
  if (filter === 'verified') {
    servers = servers.filter(s => s.verified);
  } else if (filter === 'malicious') {
    servers = servers.filter(s => s.knownMalicious);
  } else if (filter === 'low_reputation') {
    servers = servers.filter(s => s.overallScore < (minScore || 30));
  }
  
  if (minScore && filter !== 'low_reputation') {
    servers = servers.filter(s => s.overallScore >= minScore);
  }
  
  res.json({
    success: true,
    count: servers.length,
    servers: servers.map(s => ({
      server_id: s.serverId,
      server_name: s.serverName,
      overall_score: s.overallScore,
      verified: s.verified,
      known_malicious: s.knownMalicious,
      total_calls: s.totalCalls,
      community_reports: s.communityReports,
    })),
  });
});

// =============================================================================
// Statistics & Configuration
// =============================================================================

/**
 * GET /stats
 * Get overall statistics.
 */
router.get('/stats', (_req: Request, res: Response) => {
  const allReps = Array.from(reputations.values());
  
  res.json({
    success: true,
    interceptor: {
      total_calls: calls.length,
      approved_calls: calls.filter(c => c.status === 'approved').length,
      blocked_calls: calls.filter(c => c.status === 'blocked').length,
      pending_calls: calls.filter(c => c.status === 'pending').length,
      active_sessions: sessions.size,
      avg_decision_time_ms: 45,
    },
    reputation: {
      total_servers: allReps.length,
      verified_servers: allReps.filter(r => r.verified).length,
      malicious_servers: allReps.filter(r => r.knownMalicious).length,
      low_reputation_servers: allReps.filter(r => r.overallScore < 30).length,
    },
  });
});

/**
 * GET /config
 * Get current configuration.
 */
router.get('/config', (_req: Request, res: Response) => {
  res.json({
    success: true,
    config: interceptorConfig,
  });
});

/**
 * PATCH /config
 * Update configuration.
 */
router.patch('/config', (req: Request, res: Response) => {
  const { 
    mode, 
    min_reputation_score, 
    require_approval_for, 
    drift_threshold 
  } = req.body;
  
  if (mode) interceptorConfig.mode = mode;
  if (min_reputation_score !== undefined) interceptorConfig.minReputationScore = min_reputation_score;
  if (require_approval_for) interceptorConfig.requireApprovalFor = require_approval_for;
  if (drift_threshold !== undefined) interceptorConfig.driftThreshold = drift_threshold;
  
  res.json({
    success: true,
    message: 'Configuration updated',
    config: interceptorConfig,
  });
});

/**
 * GET /health
 * Health check endpoint.
 */
router.get('/health', (_req: Request, res: Response) => {
  res.json({
    success: true,
    status: 'healthy',
    timestamp: new Date(),
    version: '1.0.6',
  });
});

export default router;
