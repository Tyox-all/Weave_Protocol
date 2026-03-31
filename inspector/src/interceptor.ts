/**
 * Core Interceptor
 * @weave_protocol/inspector
 * 
 * Intercepts MCP tool calls, analyzes them, and gates execution
 */

import { randomUUID } from 'crypto';
import { EventEmitter } from 'events';
import {
  InterceptedCall,
  CallStatus,
  CallDecision,
  IntentAnalysis,
  IntentCategory,
  RiskLevel,
  ScanResult,
  ScanIssue,
  DriftAnalysis,
  DriftDeviation,
  InspectorConfig,
  DEFAULT_CONFIG,
  LiveFeedEvent,
  LiveFeedEventType,
  InspectorSession,
} from './types.js';

// ============================================================================
// Intent Analyzer
// ============================================================================

const TOOL_INTENT_MAP: Record<string, IntentCategory[]> = {
  // File operations
  'read_file': ['read_data', 'file_system'],
  'write_file': ['write_data', 'file_system'],
  'delete_file': ['delete_data', 'file_system'],
  'list_directory': ['read_data', 'file_system'],
  'create_directory': ['write_data', 'file_system'],
  
  // Code execution
  'execute': ['execute_code'],
  'run_command': ['execute_code'],
  'bash': ['execute_code'],
  'shell': ['execute_code'],
  'eval': ['execute_code'],
  
  // Database
  'query': ['database', 'read_data'],
  'insert': ['database', 'write_data'],
  'update': ['database', 'write_data'],
  'delete': ['database', 'delete_data'],
  'sql': ['database'],
  
  // Network
  'fetch': ['network_access', 'external_api'],
  'request': ['network_access', 'external_api'],
  'http': ['network_access', 'external_api'],
  'api': ['network_access', 'external_api'],
  'webhook': ['network_access', 'external_api'],
  
  // Messaging
  'send_email': ['messaging', 'network_access'],
  'send_message': ['messaging'],
  'slack': ['messaging', 'external_api'],
  'discord': ['messaging', 'external_api'],
  
  // Auth
  'login': ['authentication'],
  'authenticate': ['authentication'],
  'oauth': ['authentication', 'network_access'],
  'token': ['authentication'],
  'credential': ['authentication'],
};

const RISK_KEYWORDS: Record<RiskLevel, string[]> = {
  critical: [
    'delete_all', 'drop_database', 'rm -rf', 'format', 'sudo',
    'password', 'secret', 'credential', 'private_key', 'api_key',
    'transfer_funds', 'send_money', 'payment',
  ],
  high: [
    'delete', 'remove', 'drop', 'truncate', 'execute', 'eval',
    'admin', 'root', 'system', 'config', 'env',
    'email_all', 'broadcast', 'publish',
  ],
  medium: [
    'update', 'modify', 'write', 'create', 'insert',
    'upload', 'download', 'export', 'import',
  ],
  low: [
    'read', 'get', 'list', 'query', 'search', 'view',
  ],
};

export function analyzeIntent(
  tool: string,
  args: Record<string, unknown>,
  declaredIntent?: string
): IntentAnalysis {
  const toolLower = tool.toLowerCase();
  const argsStr = JSON.stringify(args).toLowerCase();
  
  // Determine categories
  const categories: IntentCategory[] = [];
  for (const [pattern, cats] of Object.entries(TOOL_INTENT_MAP)) {
    if (toolLower.includes(pattern)) {
      categories.push(...cats);
    }
  }
  if (categories.length === 0) {
    categories.push('unknown');
  }
  
  // Determine risk level
  let riskLevel: RiskLevel = 'low';
  const flags: string[] = [];
  
  for (const [level, keywords] of Object.entries(RISK_KEYWORDS) as [RiskLevel, string[]][]) {
    for (const keyword of keywords) {
      if (toolLower.includes(keyword) || argsStr.includes(keyword)) {
        if (riskLevel === 'low' || 
            (riskLevel === 'medium' && (level === 'high' || level === 'critical')) ||
            (riskLevel === 'high' && level === 'critical')) {
          riskLevel = level;
        }
        flags.push(`${level}: contains "${keyword}"`);
      }
    }
  }
  
  // Infer intent
  const inferredIntent = inferIntentDescription(tool, args, categories);
  
  // Calculate confidence
  let confidence = 0.7;
  if (categories.includes('unknown')) confidence -= 0.3;
  if (flags.length > 0) confidence -= 0.1;
  if (declaredIntent) confidence += 0.1;
  confidence = Math.max(0.1, Math.min(1.0, confidence));
  
  return {
    declaredIntent,
    inferredIntent,
    confidence,
    categories: [...new Set(categories)],
    riskLevel,
    flags,
  };
}

function inferIntentDescription(
  tool: string,
  args: Record<string, unknown>,
  categories: IntentCategory[]
): string {
  const parts: string[] = [];
  
  // Action verb
  if (categories.includes('read_data')) parts.push('Read');
  else if (categories.includes('write_data')) parts.push('Write');
  else if (categories.includes('delete_data')) parts.push('Delete');
  else if (categories.includes('execute_code')) parts.push('Execute');
  else parts.push('Perform');
  
  // Target
  if (args.path || args.file || args.filename) {
    parts.push(`file "${args.path || args.file || args.filename}"`);
  } else if (args.url || args.endpoint) {
    parts.push(`request to "${args.url || args.endpoint}"`);
  } else if (args.query || args.sql) {
    parts.push('database query');
  } else if (args.command || args.cmd) {
    parts.push(`command "${String(args.command || args.cmd).slice(0, 50)}..."`);
  } else {
    parts.push(`${tool} operation`);
  }
  
  return parts.join(' ');
}

// ============================================================================
// Drift Detector
// ============================================================================

export function detectDrift(
  call: InterceptedCall,
  sessionContext: { declaredIntents: string[]; previousCalls: InterceptedCall[] }
): DriftAnalysis {
  const deviations: DriftDeviation[] = [];
  let maxSeverity: RiskLevel = 'low';
  
  // Check against declared intents
  if (sessionContext.declaredIntents.length > 0) {
    const intentMatch = sessionContext.declaredIntents.some(intent =>
      call.intent?.inferredIntent.toLowerCase().includes(intent.toLowerCase()) ||
      intent.toLowerCase().includes(call.tool.toLowerCase())
    );
    
    if (!intentMatch) {
      deviations.push({
        type: 'tool_mismatch',
        expected: sessionContext.declaredIntents.join(', '),
        actual: call.tool,
        severity: 'medium',
        description: `Tool "${call.tool}" not in declared intents`,
      });
      maxSeverity = 'medium';
    }
  }
  
  // Check for scope expansion
  const previousTools = sessionContext.previousCalls.map(c => c.tool);
  const previousCategories = new Set(
    sessionContext.previousCalls.flatMap(c => c.intent?.categories || [])
  );
  
  const newCategories = (call.intent?.categories || []).filter(
    cat => !previousCategories.has(cat)
  );
  
  if (newCategories.length > 0 && sessionContext.previousCalls.length > 3) {
    const riskyNew = newCategories.filter(cat =>
      ['delete_data', 'execute_code', 'authentication'].includes(cat)
    );
    
    if (riskyNew.length > 0) {
      deviations.push({
        type: 'scope_expansion',
        expected: Array.from(previousCategories).join(', '),
        actual: newCategories.join(', '),
        severity: 'high',
        description: `New risky capabilities: ${riskyNew.join(', ')}`,
      });
      maxSeverity = 'high';
    }
  }
  
  // Check for data access patterns
  if (call.intent?.categories.includes('read_data') && 
      call.scanResult?.issues.some(i => i.category === 'pii')) {
    deviations.push({
      type: 'data_access',
      expected: 'non-sensitive data',
      actual: 'PII detected in arguments',
      severity: 'high',
      description: 'Accessing potentially sensitive personal data',
    });
    maxSeverity = 'high';
  }
  
  // Determine recommendation
  let recommendation: 'proceed' | 'review' | 'block' = 'proceed';
  if (maxSeverity === 'critical') recommendation = 'block';
  else if (maxSeverity === 'high' || deviations.length >= 2) recommendation = 'review';
  
  return {
    callId: call.id,
    detected: deviations.length > 0,
    severity: maxSeverity,
    declared: {
      intent: sessionContext.declaredIntents.join('; ') || 'none',
      expectedTools: previousTools.slice(-5),
      expectedActions: Array.from(previousCategories),
    },
    actual: {
      tool: call.tool,
      action: call.intent?.inferredIntent || 'unknown',
      scope: (call.intent?.categories || []).join(', '),
    },
    deviations,
    recommendation,
  };
}

// ============================================================================
// Core Interceptor Class
// ============================================================================

export class Interceptor extends EventEmitter {
  private config: InspectorConfig;
  private sessions: Map<string, InspectorSession> = new Map();
  private calls: Map<string, InterceptedCall> = new Map();
  private pendingApprovals: Map<string, InterceptedCall> = new Map();
  
  // External integrations (set via setters)
  private scanner?: (content: string) => Promise<ScanResult>;
  private reputationChecker?: (serverId: string) => Promise<number>;
  private blockchainAnchor?: (data: unknown) => Promise<string>;
  
  constructor(config: Partial<InspectorConfig> = {}) {
    super();
    this.config = { ...DEFAULT_CONFIG, ...config };
  }
  
  // ==========================================================================
  // Configuration
  // ==========================================================================
  
  setConfig(config: Partial<InspectorConfig>): void {
    this.config = { ...this.config, ...config };
  }
  
  getConfig(): InspectorConfig {
    return { ...this.config };
  }
  
  setScanner(scanner: (content: string) => Promise<ScanResult>): void {
    this.scanner = scanner;
  }
  
  setReputationChecker(checker: (serverId: string) => Promise<number>): void {
    this.reputationChecker = checker;
  }
  
  setBlockchainAnchor(anchor: (data: unknown) => Promise<string>): void {
    this.blockchainAnchor = anchor;
  }
  
  // ==========================================================================
  // Session Management
  // ==========================================================================
  
  createSession(agentId?: string): InspectorSession {
    const session: InspectorSession = {
      id: randomUUID(),
      agentId,
      startedAt: new Date(),
      lastActivityAt: new Date(),
      totalCalls: 0,
      approvedCalls: 0,
      blockedCalls: 0,
      pendingCalls: 0,
      declaredIntents: [],
      activeServers: [],
      status: 'active',
    };
    
    this.sessions.set(session.id, session);
    return session;
  }
  
  getSession(sessionId: string): InspectorSession | undefined {
    return this.sessions.get(sessionId);
  }
  
  declareIntent(sessionId: string, intent: string): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.declaredIntents.push(intent);
      session.lastActivityAt = new Date();
    }
  }
  
  terminateSession(sessionId: string, reason?: string): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.status = 'terminated';
      session.terminatedAt = new Date();
      session.terminationReason = reason;
    }
  }
  
  // ==========================================================================
  // Core Interception
  // ==========================================================================
  
  async intercept(
    sessionId: string,
    server: string,
    tool: string,
    args: Record<string, unknown>
  ): Promise<InterceptedCall> {
    if (!this.config.enabled) {
      // Pass through if disabled
      return this.createPassthroughCall(sessionId, server, tool, args);
    }
    
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Session not found: ${sessionId}`);
    }
    
    // Create call record
    const call: InterceptedCall = {
      id: randomUUID(),
      timestamp: new Date(),
      sourceServer: server,
      sourceAgent: session.agentId,
      sessionId,
      tool,
      arguments: args,
      decision: 'pending_review',
      decisionAt: new Date(),
      status: 'pending',
    };
    
    // Update session
    session.totalCalls++;
    session.lastActivityAt = new Date();
    if (!session.activeServers.includes(server)) {
      session.activeServers.push(server);
    }
    
    // Analyze intent
    call.intent = analyzeIntent(tool, args, session.declaredIntents[session.declaredIntents.length - 1]);
    
    // Scan arguments if enabled
    if (this.config.scanEnabled && this.scanner) {
      const startTime = Date.now();
      call.scanResult = await this.scanner(JSON.stringify(args));
      call.scanResult.scanDurationMs = Date.now() - startTime;
    }
    
    // Check reputation if enabled
    if (this.config.reputationEnabled && this.reputationChecker) {
      call.reputationScore = await this.reputationChecker(server);
    }
    
    // Detect drift
    if (this.config.driftDetectionEnabled) {
      const previousCalls = this.getSessionCalls(sessionId).slice(-10);
      const drift = detectDrift(call, {
        declaredIntents: session.declaredIntents,
        previousCalls,
      });
      call.driftDetected = drift.detected;
      
      if (drift.detected) {
        this.emitEvent('drift_detected', drift);
      }
    }
    
    // Make decision
    const decision = this.makeDecision(call);
    call.decision = decision.decision;
    call.decisionReason = decision.reason;
    call.decisionAt = new Date();
    
    // Update status based on decision
    if (call.decision === 'auto_approved' || call.decision === 'manual_approved') {
      call.status = 'approved';
      session.approvedCalls++;
    } else if (call.decision === 'auto_blocked' || call.decision === 'manual_blocked') {
      call.status = 'blocked';
      session.blockedCalls++;
    } else {
      call.status = 'pending';
      session.pendingCalls++;
      this.pendingApprovals.set(call.id, call);
    }
    
    // Store call
    this.calls.set(call.id, call);
    
    // Emit event
    this.emitEvent(
      call.status === 'blocked' ? 'call_blocked' : 
      call.status === 'pending' ? 'manual_review_required' : 'call_intercepted',
      call
    );
    
    // Anchor to blockchain if high risk
    if (this.config.blockchainEnabled && this.blockchainAnchor) {
      if (!this.config.anchorHighRiskOnly || call.intent?.riskLevel === 'high' || call.intent?.riskLevel === 'critical') {
        try {
          await this.blockchainAnchor({
            callId: call.id,
            timestamp: call.timestamp,
            tool: call.tool,
            decision: call.decision,
            riskLevel: call.intent?.riskLevel,
          });
        } catch (err) {
          // Log but don't fail the call
          console.error('Blockchain anchor failed:', err);
        }
      }
    }
    
    return call;
  }
  
  private createPassthroughCall(
    sessionId: string,
    server: string,
    tool: string,
    args: Record<string, unknown>
  ): InterceptedCall {
    return {
      id: randomUUID(),
      timestamp: new Date(),
      sourceServer: server,
      sessionId,
      tool,
      arguments: args,
      decision: 'auto_approved',
      decisionReason: 'Inspector disabled',
      decisionAt: new Date(),
      status: 'approved',
    };
  }
  
  private makeDecision(call: InterceptedCall): { decision: CallDecision; reason: string } {
    // Check for blocking conditions
    
    // 1. Scan found critical issues
    if (call.scanResult && !call.scanResult.safe) {
      const critical = call.scanResult.issues.filter(i => i.severity === 'critical');
      if (critical.length > 0) {
        return {
          decision: 'auto_blocked',
          reason: `Critical security issue: ${critical[0].message}`,
        };
      }
    }
    
    // 2. Reputation too low
    if (call.reputationScore !== undefined && call.reputationScore < this.config.minReputationScore) {
      return {
        decision: 'auto_blocked',
        reason: `Server reputation (${call.reputationScore}) below minimum (${this.config.minReputationScore})`,
      };
    }
    
    // 3. Strict mode blocks high risk
    if (this.config.mode === 'strict' && 
        (call.intent?.riskLevel === 'high' || call.intent?.riskLevel === 'critical')) {
      return {
        decision: 'auto_blocked',
        reason: `Strict mode: ${call.intent.riskLevel} risk operation blocked`,
      };
    }
    
    // Check for manual approval required
    
    // 4. Category requires approval
    const needsApproval = call.intent?.categories.some(cat =>
      this.config.requireApprovalFor.includes(cat)
    );
    if (needsApproval && this.config.mode !== 'passive') {
      return {
        decision: 'pending_review',
        reason: `Category requires approval: ${call.intent?.categories.join(', ')}`,
      };
    }
    
    // 5. Drift detected with review recommendation
    if (call.driftDetected && this.config.mode === 'active') {
      return {
        decision: 'pending_review',
        reason: 'Drift detected from declared intent',
      };
    }
    
    // 6. High severity scan issues
    if (call.scanResult?.issues.some(i => i.severity === 'high')) {
      if (this.config.mode === 'strict') {
        return {
          decision: 'auto_blocked',
          reason: 'High severity security issue detected',
        };
      } else if (this.config.mode === 'active') {
        return {
          decision: 'pending_review',
          reason: 'High severity security issue needs review',
        };
      }
    }
    
    // Default: approve
    return {
      decision: 'auto_approved',
      reason: 'No blocking conditions',
    };
  }
  
  // ==========================================================================
  // Manual Approval
  // ==========================================================================
  
  approveCall(callId: string, approvedBy?: string): InterceptedCall | null {
    const call = this.pendingApprovals.get(callId);
    if (!call) return null;
    
    call.decision = 'manual_approved';
    call.decisionReason = `Manually approved${approvedBy ? ` by ${approvedBy}` : ''}`;
    call.decisionAt = new Date();
    call.status = 'approved';
    
    this.pendingApprovals.delete(callId);
    
    const session = this.sessions.get(call.sessionId);
    if (session) {
      session.pendingCalls--;
      session.approvedCalls++;
    }
    
    this.emitEvent('call_approved', call);
    return call;
  }
  
  blockCall(callId: string, blockedBy?: string, reason?: string): InterceptedCall | null {
    const call = this.pendingApprovals.get(callId);
    if (!call) return null;
    
    call.decision = 'manual_blocked';
    call.decisionReason = reason || `Manually blocked${blockedBy ? ` by ${blockedBy}` : ''}`;
    call.decisionAt = new Date();
    call.status = 'blocked';
    
    this.pendingApprovals.delete(callId);
    
    const session = this.sessions.get(call.sessionId);
    if (session) {
      session.pendingCalls--;
      session.blockedCalls++;
    }
    
    this.emitEvent('call_blocked', call);
    return call;
  }
  
  getPendingApprovals(): InterceptedCall[] {
    return Array.from(this.pendingApprovals.values());
  }
  
  // ==========================================================================
  // Call Completion
  // ==========================================================================
  
  recordResult(callId: string, result: unknown): void {
    const call = this.calls.get(callId);
    if (call && call.status === 'approved') {
      call.status = 'completed';
      call.result = result;
      call.executedAt = new Date();
      call.durationMs = call.executedAt.getTime() - call.timestamp.getTime();
      
      this.emitEvent('call_completed', call);
    }
  }
  
  recordError(callId: string, error: string): void {
    const call = this.calls.get(callId);
    if (call) {
      call.status = 'failed';
      call.error = error;
      call.executedAt = new Date();
      
      this.emitEvent('call_failed', call);
    }
  }
  
  // ==========================================================================
  // Query Methods
  // ==========================================================================
  
  getCall(callId: string): InterceptedCall | undefined {
    return this.calls.get(callId);
  }
  
  getSessionCalls(sessionId: string): InterceptedCall[] {
    return Array.from(this.calls.values())
      .filter(c => c.sessionId === sessionId)
      .sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  }
  
  getCallHistory(options: {
    sessionId?: string;
    server?: string;
    status?: CallStatus;
    since?: Date;
    limit?: number;
  } = {}): InterceptedCall[] {
    let calls = Array.from(this.calls.values());
    
    if (options.sessionId) {
      calls = calls.filter(c => c.sessionId === options.sessionId);
    }
    if (options.server) {
      calls = calls.filter(c => c.sourceServer === options.server);
    }
    if (options.status) {
      calls = calls.filter(c => c.status === options.status);
    }
    if (options.since) {
      calls = calls.filter(c => c.timestamp >= options.since!);
    }
    
    calls.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
    
    if (options.limit) {
      calls = calls.slice(0, options.limit);
    }
    
    return calls;
  }
  
  getStats(): {
    totalCalls: number;
    approvedCalls: number;
    blockedCalls: number;
    pendingCalls: number;
    activeSessions: number;
    avgDecisionTimeMs: number;
  } {
    const calls = Array.from(this.calls.values());
    const activeSessions = Array.from(this.sessions.values())
      .filter(s => s.status === 'active').length;
    
    const decisionTimes = calls
      .filter(c => c.decisionAt && c.timestamp)
      .map(c => c.decisionAt.getTime() - c.timestamp.getTime());
    
    return {
      totalCalls: calls.length,
      approvedCalls: calls.filter(c => c.status === 'approved' || c.status === 'completed').length,
      blockedCalls: calls.filter(c => c.status === 'blocked').length,
      pendingCalls: this.pendingApprovals.size,
      activeSessions,
      avgDecisionTimeMs: decisionTimes.length > 0
        ? Math.round(decisionTimes.reduce((a, b) => a + b, 0) / decisionTimes.length)
        : 0,
    };
  }
  
  // ==========================================================================
  // Event Emission
  // ==========================================================================
  
  private emitEvent(type: LiveFeedEventType, data: unknown): void {
    const event: LiveFeedEvent = {
      type,
      timestamp: new Date(),
      data: data as any,
    };
    
    this.emit('event', event);
    this.emit(type, data);
  }
}

export default Interceptor;
