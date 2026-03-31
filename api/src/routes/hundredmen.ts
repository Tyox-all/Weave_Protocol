/**
 * Hundredmen Routes
 * @weave_protocol/api
 * 
 * REST + SSE endpoints for hundredmen (fintech-friendly, no WebSockets)
 */

import { Router, Request, Response } from 'express';
import { Interceptor } from '@weave_protocol/hundredmen';
import { ReputationManager } from '@weave_protocol/hundredmen';

// Shared instances (initialized once)
let interceptor: Interceptor;
let reputationManager: ReputationManager;

export function initHundredmen() {
  interceptor = new Interceptor({
    mode: 'active',
    scanEnabled: true,
    driftDetectionEnabled: true,
    reputationEnabled: true,
  });
  
  reputationManager = new ReputationManager();
  
  // Wire up reputation checker
  interceptor.setReputationChecker(async (serverId: string) => {
    return reputationManager.getScore(serverId);
  });
  
  return { interceptor, reputationManager };
}

const router = Router();

// ============================================================================
// SSE - Server-Sent Events (Real-time, fintech-friendly)
// ============================================================================

/**
 * GET /hundredmen/stream
 * 
 * Server-Sent Events stream for real-time updates.
 * Works through corporate proxies, no WebSocket required.
 * 
 * Events emitted:
 * - call_intercepted
 * - call_approved
 * - call_blocked
 * - call_completed
 * - drift_detected
 * - reputation_alert
 */
router.get('/stream', (req: Request, res: Response) => {
  // SSE headers
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no'); // Disable nginx buffering
  
  // Send initial connection event
  res.write(`event: connected\ndata: ${JSON.stringify({ timestamp: new Date() })}\n\n`);
  
  // Keep-alive ping every 30 seconds
  const keepAlive = setInterval(() => {
    res.write(`: ping\n\n`);
  }, 30000);
  
  // Forward interceptor events to SSE
  const onEvent = (event: any) => {
    res.write(`event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`);
  };
  
  interceptor.on('event', onEvent);
  
  // Cleanup on disconnect
  req.on('close', () => {
    clearInterval(keepAlive);
    interceptor.off('event', onEvent);
  });
});

// ============================================================================
// REST Polling (Always works, even in strictest environments)
// ============================================================================

/**
 * GET /hundredmen/feed
 * 
 * Poll for recent events. Use ?since=<ISO timestamp> for incremental updates.
 */
router.get('/feed', (req: Request, res: Response) => {
  const since = req.query.since ? new Date(req.query.since as string) : undefined;
  const limit = parseInt(req.query.limit as string) || 50;
  const status = req.query.status as string | undefined;
  const sessionId = req.query.session_id as string | undefined;
  
  const calls = interceptor.getCallHistory({
    since,
    limit,
    status: status as any,
    sessionId,
  });
  
  res.json({
    success: true,
    count: calls.length,
    timestamp: new Date(),
    calls: calls.map(c => ({
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
 * GET /hundredmen/pending
 * 
 * Get all calls awaiting manual approval.
 */
router.get('/pending', (_req: Request, res: Response) => {
  const pending = interceptor.getPendingApprovals();
  
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
 * POST /hundredmen/approve/:id
 * 
 * Approve a pending call.
 */
router.post('/approve/:id', (req: Request, res: Response) => {
  const { id } = req.params;
  const { approved_by } = req.body || {};
  
  const call = interceptor.approveCall(id, approved_by);
  
  if (!call) {
    return res.status(404).json({
      success: false,
      error: 'Call not found or not pending',
    });
  }
  
  res.json({
    success: true,
    call_id: call.id,
    status: call.status,
    message: `Call approved: ${call.tool}`,
  });
});

/**
 * POST /hundredmen/block/:id
 * 
 * Block a pending call.
 */
router.post('/block/:id', (req: Request, res: Response) => {
  const { id } = req.params;
  const { blocked_by, reason } = req.body || {};
  
  const call = interceptor.blockCall(id, blocked_by, reason);
  
  if (!call) {
    return res.status(404).json({
      success: false,
      error: 'Call not found or not pending',
    });
  }
  
  res.json({
    success: true,
    call_id: call.id,
    status: call.status,
    message: `Call blocked: ${call.tool}`,
  });
});

// ============================================================================
// Session Management
// ============================================================================

/**
 * POST /hundredmen/session
 * 
 * Create a new inspection session.
 */
router.post('/session', (req: Request, res: Response) => {
  const { agent_id } = req.body || {};
  
  const session = interceptor.createSession(agent_id);
  
  res.json({
    success: true,
    session_id: session.id,
    started_at: session.startedAt,
    message: 'Session created. Declare intent with POST /hundredmen/session/:id/intent',
  });
});

/**
 * POST /hundredmen/session/:id/intent
 * 
 * Declare intent for a session (enables drift detection).
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
  
  interceptor.declareIntent(id, intent);
  const session = interceptor.getSession(id);
  
  if (!session) {
    return res.status(404).json({
      success: false,
      error: 'Session not found',
    });
  }
  
  res.json({
    success: true,
    session_id: id,
    declared_intents: session.declaredIntents,
    message: `Intent recorded: "${intent}"`,
  });
});

/**
 * DELETE /hundredmen/session/:id
 * 
 * End a session and get summary.
 */
router.delete('/session/:id', (req: Request, res: Response) => {
  const { id } = req.params;
  const { reason } = req.body || {};
  
  const session = interceptor.getSession(id);
  
  if (!session) {
    return res.status(404).json({
      success: false,
      error: 'Session not found',
    });
  }
  
  interceptor.terminateSession(id, reason);
  
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

/**
 * GET /hundredmen/session/:id/drift
 * 
 * Get drift analysis for a session.
 */
router.get('/session/:id/drift', (req: Request, res: Response) => {
  const { id } = req.params;
  
  const session = interceptor.getSession(id);
  
  if (!session) {
    return res.status(404).json({
      success: false,
      error: 'Session not found',
    });
  }
  
  const calls = interceptor.getCallHistory({ sessionId: id });
  const driftCalls = calls.filter(c => c.driftDetected);
  
  res.json({
    success: true,
    session_id: id,
    declared_intents: session.declaredIntents,
    total_calls: calls.length,
    drift_detected_count: driftCalls.length,
    drift_rate: calls.length > 0 
      ? `${(driftCalls.length / calls.length * 100).toFixed(1)}%` 
      : '0%',
    drift_calls: driftCalls.map(c => ({
      id: c.id,
      tool: c.tool,
      inferred_intent: c.intent?.inferredIntent,
      risk_level: c.intent?.riskLevel,
    })),
  });
});

// ============================================================================
// Reputation
// ============================================================================

/**
 * GET /hundredmen/reputation/:serverId
 * 
 * Get reputation score for an MCP server.
 */
router.get('/reputation/:serverId', (req: Request, res: Response) => {
  const { serverId } = req.params;
  
  const reputation = reputationManager.getReputation(serverId);
  
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
 * POST /hundredmen/reputation/:serverId/report
 * 
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
  
  const report = reputationManager.submitReport(
    serverId,
    reported_by || 'api_user',
    report_type,
    description,
    evidence
  );
  
  const reputation = reputationManager.getReputation(serverId);
  
  res.json({
    success: true,
    report_id: report.id,
    server_id: serverId,
    new_score: reputation.overallScore,
    message: 'Report submitted. Server reputation has been updated.',
  });
});

/**
 * GET /hundredmen/servers
 * 
 * List all known servers with reputation scores.
 */
router.get('/servers', (req: Request, res: Response) => {
  const filter = req.query.filter as string;
  const minScore = parseInt(req.query.min_score as string) || 0;
  
  let servers = reputationManager.getAllReputations();
  
  if (filter === 'verified') {
    servers = reputationManager.getVerifiedServers();
  } else if (filter === 'malicious') {
    servers = reputationManager.getMaliciousServers();
  } else if (filter === 'low_reputation') {
    servers = reputationManager.getLowReputationServers(minScore || 30);
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

// ============================================================================
// Statistics & Configuration
// ============================================================================

/**
 * GET /hundredmen/stats
 * 
 * Get overall statistics.
 */
router.get('/stats', (_req: Request, res: Response) => {
  const stats = interceptor.getStats();
  const maliciousCount = reputationManager.getMaliciousServers().length;
  const lowRepCount = reputationManager.getLowReputationServers().length;
  
  res.json({
    success: true,
    interceptor: {
      total_calls: stats.totalCalls,
      approved_calls: stats.approvedCalls,
      blocked_calls: stats.blockedCalls,
      pending_calls: stats.pendingCalls,
      active_sessions: stats.activeSessions,
      avg_decision_time_ms: stats.avgDecisionTimeMs,
    },
    reputation: {
      total_servers: reputationManager.getAllReputations().length,
      verified_servers: reputationManager.getVerifiedServers().length,
      malicious_servers: maliciousCount,
      low_reputation_servers: lowRepCount,
    },
  });
});

/**
 * GET /hundredmen/config
 * 
 * Get current configuration.
 */
router.get('/config', (_req: Request, res: Response) => {
  res.json({
    success: true,
    config: interceptor.getConfig(),
  });
});

/**
 * PATCH /hundredmen/config
 * 
 * Update configuration.
 */
router.patch('/config', (req: Request, res: Response) => {
  const { 
    mode, 
    min_reputation_score, 
    require_approval_for, 
    drift_threshold 
  } = req.body;
  
  const config: any = {};
  
  if (mode) config.mode = mode;
  if (min_reputation_score !== undefined) config.minReputationScore = min_reputation_score;
  if (require_approval_for) config.requireApprovalFor = require_approval_for;
  if (drift_threshold !== undefined) config.driftThreshold = drift_threshold;
  
  interceptor.setConfig(config);
  
  res.json({
    success: true,
    message: 'Configuration updated',
    config: interceptor.getConfig(),
  });
});

// ============================================================================
// Health Check
// ============================================================================

/**
 * GET /hundredmen/health
 * 
 * Health check endpoint.
 */
router.get('/health', (_req: Request, res: Response) => {
  res.json({
    success: true,
    status: 'healthy',
    timestamp: new Date(),
    version: '1.0.0',
  });
});

export default router;
