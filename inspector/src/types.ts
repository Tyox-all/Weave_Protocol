/**
 * Inspector Types and Interfaces
 * @weave_protocol/inspector
 * 
 * Real-time MCP security proxy - intercepts, scans, and gates tool calls
 */

// ============================================================================
// Core Types
// ============================================================================

export interface InterceptedCall {
  id: string;
  timestamp: Date;
  
  // Source
  sourceServer: string;
  sourceAgent?: string;
  sessionId: string;
  
  // Call details
  tool: string;
  arguments: Record<string, unknown>;
  
  // Analysis
  intent?: IntentAnalysis;
  scanResult?: ScanResult;
  reputationScore?: number;
  driftDetected?: boolean;
  
  // Decision
  decision: CallDecision;
  decisionReason?: string;
  decisionAt: Date;
  
  // Execution
  status: CallStatus;
  result?: unknown;
  error?: string;
  executedAt?: Date;
  durationMs?: number;
}

export type CallStatus = 
  | 'pending'
  | 'approved'
  | 'blocked'
  | 'executing'
  | 'completed'
  | 'failed'
  | 'rolled_back';

export type CallDecision =
  | 'auto_approved'
  | 'auto_blocked'
  | 'manual_approved'
  | 'manual_blocked'
  | 'pending_review';

export interface IntentAnalysis {
  declaredIntent?: string;
  inferredIntent: string;
  confidence: number;
  categories: IntentCategory[];
  riskLevel: RiskLevel;
  flags: string[];
}

export type IntentCategory =
  | 'read_data'
  | 'write_data'
  | 'delete_data'
  | 'execute_code'
  | 'network_access'
  | 'file_system'
  | 'authentication'
  | 'external_api'
  | 'database'
  | 'messaging'
  | 'unknown';

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface ScanResult {
  safe: boolean;
  issues: ScanIssue[];
  scannedAt: Date;
  scanDurationMs: number;
}

export interface ScanIssue {
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  category: string;
  message: string;
  location?: string;
  remediation?: string;
}

// ============================================================================
// Policy Types
// ============================================================================

export interface InspectorPolicy {
  id: string;
  name: string;
  description?: string;
  enabled: boolean;
  priority: number;
  
  // Matching
  conditions: PolicyCondition[];
  
  // Action
  action: PolicyAction;
  
  // Metadata
  createdAt: Date;
  updatedAt: Date;
  createdBy?: string;
}

export interface PolicyCondition {
  field: PolicyField;
  operator: PolicyOperator;
  value: string | string[] | number | boolean;
}

export type PolicyField =
  | 'tool'
  | 'server'
  | 'argument'
  | 'intent_category'
  | 'risk_level'
  | 'reputation_score'
  | 'has_secrets'
  | 'has_pii'
  | 'has_injection'
  | 'drift_detected';

export type PolicyOperator =
  | 'equals'
  | 'not_equals'
  | 'contains'
  | 'not_contains'
  | 'matches'       // regex
  | 'in'
  | 'not_in'
  | 'greater_than'
  | 'less_than'
  | 'exists'
  | 'not_exists';

export type PolicyAction =
  | 'allow'
  | 'block'
  | 'require_approval'
  | 'log_only'
  | 'rate_limit';

// ============================================================================
// Reputation Types
// ============================================================================

export interface ServerReputation {
  serverId: string;
  serverName: string;
  
  // Scores (0-100)
  overallScore: number;
  trustScore: number;
  securityScore: number;
  communityScore: number;
  
  // Metrics
  totalCalls: number;
  blockedCalls: number;
  failedCalls: number;
  avgResponseTime: number;
  
  // Flags
  verified: boolean;
  knownMalicious: boolean;
  communityReports: number;
  lastIncident?: Date;
  
  // History
  firstSeen: Date;
  lastSeen: Date;
  scoreHistory: ScoreHistoryEntry[];
}

export interface ScoreHistoryEntry {
  timestamp: Date;
  score: number;
  reason?: string;
}

export interface ReputationReport {
  id: string;
  serverId: string;
  reportedBy: string;
  reportType: ReportType;
  description: string;
  evidence?: string;
  status: ReportStatus;
  createdAt: Date;
  resolvedAt?: Date;
  resolution?: string;
}

export type ReportType =
  | 'malicious_behavior'
  | 'data_exfiltration'
  | 'prompt_injection'
  | 'unexpected_actions'
  | 'false_positive'
  | 'other';

export type ReportStatus =
  | 'pending'
  | 'investigating'
  | 'confirmed'
  | 'dismissed'
  | 'resolved';

// ============================================================================
// Drift Detection Types
// ============================================================================

export interface DriftAnalysis {
  callId: string;
  detected: boolean;
  severity: RiskLevel;
  
  declared: {
    intent: string;
    expectedTools: string[];
    expectedActions: string[];
  };
  
  actual: {
    tool: string;
    action: string;
    scope: string;
  };
  
  deviations: DriftDeviation[];
  recommendation: 'proceed' | 'review' | 'block';
}

export interface DriftDeviation {
  type: 'tool_mismatch' | 'scope_expansion' | 'action_change' | 'data_access' | 'unexpected_target';
  expected: string;
  actual: string;
  severity: RiskLevel;
  description: string;
}

// ============================================================================
// Session Types
// ============================================================================

export interface InspectorSession {
  id: string;
  agentId?: string;
  startedAt: Date;
  lastActivityAt: Date;
  
  // Stats
  totalCalls: number;
  approvedCalls: number;
  blockedCalls: number;
  pendingCalls: number;
  
  // Context
  declaredIntents: string[];
  activeServers: string[];
  
  // State
  status: 'active' | 'idle' | 'terminated';
  terminatedAt?: Date;
  terminationReason?: string;
}

// ============================================================================
// Live Feed Types
// ============================================================================

export interface LiveFeedEvent {
  type: LiveFeedEventType;
  timestamp: Date;
  data: InterceptedCall | DriftAnalysis | PolicyMatch | ReputationAlert;
}

export type LiveFeedEventType =
  | 'call_intercepted'
  | 'call_approved'
  | 'call_blocked'
  | 'call_completed'
  | 'call_failed'
  | 'drift_detected'
  | 'policy_matched'
  | 'reputation_alert'
  | 'manual_review_required';

export interface PolicyMatch {
  callId: string;
  policyId: string;
  policyName: string;
  action: PolicyAction;
  conditions: PolicyCondition[];
}

export interface ReputationAlert {
  serverId: string;
  serverName: string;
  alertType: 'score_drop' | 'new_report' | 'confirmed_malicious' | 'unusual_activity';
  previousScore?: number;
  currentScore?: number;
  message: string;
}

// ============================================================================
// Rollback Types
// ============================================================================

export interface RollbackCapability {
  callId: string;
  canRollback: boolean;
  rollbackType?: 'full' | 'partial' | 'compensating';
  estimatedSuccess?: number;
  requirements?: string[];
  warnings?: string[];
}

export interface RollbackResult {
  callId: string;
  success: boolean;
  rollbackType: 'full' | 'partial' | 'compensating' | 'failed';
  actions: RollbackAction[];
  errors?: string[];
}

export interface RollbackAction {
  action: string;
  target: string;
  status: 'completed' | 'failed' | 'skipped';
  details?: string;
}

// ============================================================================
// Configuration Types
// ============================================================================

export interface InspectorConfig {
  // Core
  enabled: boolean;
  mode: 'passive' | 'active' | 'strict';
  
  // Scanning
  scanEnabled: boolean;
  scanSecrets: boolean;
  scanPii: boolean;
  scanInjection: boolean;
  
  // Drift detection
  driftDetectionEnabled: boolean;
  driftThreshold: number;  // 0-1, how much deviation triggers alert
  
  // Reputation
  reputationEnabled: boolean;
  minReputationScore: number;  // 0-100, block below this
  reputationApiUrl?: string;
  
  // Policies
  defaultAction: PolicyAction;
  requireApprovalFor: IntentCategory[];
  
  // Blockchain anchoring
  blockchainEnabled: boolean;
  blockchainNetwork: 'solana' | 'ethereum' | 'none';
  anchorHighRiskOnly: boolean;
  
  // Live feed
  liveFeedEnabled: boolean;
  liveFeedPort?: number;
  
  // Logging
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  logRetentionDays: number;
}

export const DEFAULT_CONFIG: InspectorConfig = {
  enabled: true,
  mode: 'active',
  
  scanEnabled: true,
  scanSecrets: true,
  scanPii: true,
  scanInjection: true,
  
  driftDetectionEnabled: true,
  driftThreshold: 0.3,
  
  reputationEnabled: true,
  minReputationScore: 30,
  
  defaultAction: 'allow',
  requireApprovalFor: ['delete_data', 'execute_code', 'authentication'],
  
  blockchainEnabled: false,
  blockchainNetwork: 'none',
  anchorHighRiskOnly: true,
  
  liveFeedEnabled: true,
  liveFeedPort: 8765,
  
  logLevel: 'info',
  logRetentionDays: 30,
};

// ============================================================================
// MCP Proxy Types
// ============================================================================

export interface ProxiedServer {
  id: string;
  name: string;
  originalCommand: string;
  originalArgs: string[];
  originalEnv?: Record<string, string>;
  
  // Status
  status: 'connected' | 'disconnected' | 'error';
  connectedAt?: Date;
  lastError?: string;
  
  // Stats
  reputation?: ServerReputation;
  callCount: number;
  errorCount: number;
}

export interface ProxyRoute {
  pattern: string;       // Tool name pattern (glob)
  targetServer: string;  // Server ID to route to
  priority: number;
  enabled: boolean;
}
