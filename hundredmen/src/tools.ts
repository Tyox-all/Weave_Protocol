/**
 * Inspector MCP Tools
 * @weave_protocol/inspector
 * 
 * MCP tool definitions for real-time security inspection
 */

import { Interceptor } from './interceptor.js';
import { ReputationManager } from './reputation.js';
import {
  CallStatus,
  RiskLevel,
  ReportType,
  InspectorConfig,
  IntentCategory,
  PolicyAction,
} from './types.js';

// ============================================================================
// Tool Definitions
// ============================================================================

export const inspectorTools = [
  // --------------------------------------------------------------------------
  // Session Management
  // --------------------------------------------------------------------------
  {
    name: 'hundredmen_create_session',
    description: `Create a new inspection session for tracking AI agent activity.
Sessions group tool calls and enable drift detection across the conversation.
Use when: starting a new task, beginning agent workflow, initializing inspection.`,
    inputSchema: {
      type: 'object',
      properties: {
        agent_id: {
          type: 'string',
          description: 'Optional identifier for the AI agent',
        },
      },
      required: [],
    },
  },
  {
    name: 'hundredmen_declare_intent',
    description: `Declare the intended actions for a session.
Enables drift detection by comparing actual tool calls against declared intent.
Use when: before performing a task, setting expectations, documenting purpose.`,
    inputSchema: {
      type: 'object',
      properties: {
        session_id: {
          type: 'string',
          description: 'Session ID from hundredmen_create_session',
        },
        intent: {
          type: 'string',
          description: 'Description of intended actions (e.g., "Read and summarize the README file")',
        },
      },
      required: ['session_id', 'intent'],
    },
  },
  {
    name: 'hundredmen_end_session',
    description: `End an inspection session and get summary statistics.
Use when: task completed, workflow finished, cleaning up.`,
    inputSchema: {
      type: 'object',
      properties: {
        session_id: {
          type: 'string',
          description: 'Session ID to terminate',
        },
        reason: {
          type: 'string',
          description: 'Reason for ending session',
        },
      },
      required: ['session_id'],
    },
  },
  
  // --------------------------------------------------------------------------
  // Live Feed & History
  // --------------------------------------------------------------------------
  {
    name: 'hundredmen_get_live_feed',
    description: `Get recent intercepted calls in real-time.
Shows what the AI agent is actually doing vs what it said it would do.
Use when: monitoring agent activity, reviewing actions, debugging behavior.`,
    inputSchema: {
      type: 'object',
      properties: {
        session_id: {
          type: 'string',
          description: 'Filter by session ID (optional)',
        },
        server: {
          type: 'string',
          description: 'Filter by server name (optional)',
        },
        status: {
          type: 'string',
          enum: ['pending', 'approved', 'blocked', 'completed', 'failed'],
          description: 'Filter by call status (optional)',
        },
        limit: {
          type: 'number',
          description: 'Maximum number of calls to return (default: 20)',
        },
      },
      required: [],
    },
  },
  {
    name: 'hundredmen_get_call_history',
    description: `Query historical call data with filters.
Use when: auditing past activity, investigating incidents, generating reports.`,
    inputSchema: {
      type: 'object',
      properties: {
        session_id: {
          type: 'string',
          description: 'Filter by session ID',
        },
        server: {
          type: 'string',
          description: 'Filter by server name',
        },
        status: {
          type: 'string',
          enum: ['pending', 'approved', 'blocked', 'completed', 'failed', 'rolled_back'],
          description: 'Filter by status',
        },
        since: {
          type: 'string',
          description: 'ISO date string - only calls after this time',
        },
        limit: {
          type: 'number',
          description: 'Maximum results (default: 100)',
        },
      },
      required: [],
    },
  },
  {
    name: 'hundredmen_diff_intent',
    description: `Compare declared intent vs actual actions ("Said X, doing Y" analysis).
Identifies drift between what the AI said it would do and what it's actually doing.
Use when: verifying agent behavior, catching unauthorized actions, security review.`,
    inputSchema: {
      type: 'object',
      properties: {
        session_id: {
          type: 'string',
          description: 'Session ID to analyze',
        },
        call_id: {
          type: 'string',
          description: 'Specific call ID to analyze (optional)',
        },
      },
      required: ['session_id'],
    },
  },
  
  // --------------------------------------------------------------------------
  // Manual Approval
  // --------------------------------------------------------------------------
  {
    name: 'hundredmen_get_pending',
    description: `Get all calls waiting for manual approval.
Use when: reviewing risky operations, approving/blocking queued actions.`,
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
  },
  {
    name: 'hundredmen_approve_call',
    description: `Manually approve a pending call.
Use when: allowing a blocked operation after review, unblocking legitimate actions.`,
    inputSchema: {
      type: 'object',
      properties: {
        call_id: {
          type: 'string',
          description: 'Call ID to approve',
        },
        approved_by: {
          type: 'string',
          description: 'Who is approving (optional)',
        },
      },
      required: ['call_id'],
    },
  },
  {
    name: 'hundredmen_block_call',
    description: `Manually block a pending call.
Use when: preventing suspicious actions, blocking after review.`,
    inputSchema: {
      type: 'object',
      properties: {
        call_id: {
          type: 'string',
          description: 'Call ID to block',
        },
        blocked_by: {
          type: 'string',
          description: 'Who is blocking (optional)',
        },
        reason: {
          type: 'string',
          description: 'Reason for blocking',
        },
      },
      required: ['call_id'],
    },
  },
  
  // --------------------------------------------------------------------------
  // Reputation
  // --------------------------------------------------------------------------
  {
    name: 'hundredmen_check_reputation',
    description: `Get reputation score and details for an MCP server.
Shows trust score, security score, community reports, and verification status.
Use when: evaluating server trustworthiness, before enabling new servers.`,
    inputSchema: {
      type: 'object',
      properties: {
        server_id: {
          type: 'string',
          description: 'Server ID to check',
        },
      },
      required: ['server_id'],
    },
  },
  {
    name: 'hundredmen_report_suspicious',
    description: `Report suspicious behavior from an MCP server.
Contributes to community reputation scoring.
Use when: server behaves unexpectedly, potential security issue, data concerns.`,
    inputSchema: {
      type: 'object',
      properties: {
        server_id: {
          type: 'string',
          description: 'Server ID to report',
        },
        report_type: {
          type: 'string',
          enum: ['malicious_behavior', 'data_exfiltration', 'prompt_injection', 'unexpected_actions', 'false_positive', 'other'],
          description: 'Type of suspicious behavior',
        },
        description: {
          type: 'string',
          description: 'Detailed description of the issue',
        },
        evidence: {
          type: 'string',
          description: 'Any evidence (logs, screenshots, etc.)',
        },
      },
      required: ['server_id', 'report_type', 'description'],
    },
  },
  {
    name: 'hundredmen_get_server_stats',
    description: `Get detailed statistics for an MCP server.
Shows call patterns, error rates, response times, and anomalies.
Use when: analyzing server behavior, investigating issues, capacity planning.`,
    inputSchema: {
      type: 'object',
      properties: {
        server_id: {
          type: 'string',
          description: 'Server ID to analyze',
        },
      },
      required: ['server_id'],
    },
  },
  {
    name: 'hundredmen_list_servers',
    description: `List all known servers with reputation scores.
Use when: reviewing server inventory, finding low-reputation servers.`,
    inputSchema: {
      type: 'object',
      properties: {
        filter: {
          type: 'string',
          enum: ['all', 'verified', 'malicious', 'low_reputation'],
          description: 'Filter servers (default: all)',
        },
        min_score: {
          type: 'number',
          description: 'Minimum reputation score (0-100)',
        },
      },
      required: [],
    },
  },
  
  // --------------------------------------------------------------------------
  // Configuration
  // --------------------------------------------------------------------------
  {
    name: 'hundredmen_set_policy',
    description: `Configure inspection policies.
Set which operations require approval, risk thresholds, etc.
Use when: customizing security rules, adjusting sensitivity.`,
    inputSchema: {
      type: 'object',
      properties: {
        mode: {
          type: 'string',
          enum: ['passive', 'active', 'strict'],
          description: 'Inspection mode: passive (log only), active (block risky), strict (block all risky)',
        },
        min_reputation_score: {
          type: 'number',
          description: 'Block servers below this score (0-100)',
        },
        require_approval_for: {
          type: 'array',
          items: {
            type: 'string',
            enum: ['read_data', 'write_data', 'delete_data', 'execute_code', 'network_access', 'file_system', 'authentication', 'external_api', 'database', 'messaging'],
          },
          description: 'Categories that require manual approval',
        },
        drift_threshold: {
          type: 'number',
          description: 'Drift sensitivity (0-1, lower = more sensitive)',
        },
      },
      required: [],
    },
  },
  {
    name: 'hundredmen_get_config',
    description: `Get current inspector configuration.
Use when: reviewing settings, debugging policy issues.`,
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
  },
  
  // --------------------------------------------------------------------------
  // Statistics
  // --------------------------------------------------------------------------
  {
    name: 'hundredmen_get_stats',
    description: `Get overall inspector statistics.
Shows total calls, approval rate, block rate, active sessions.
Use when: monitoring system health, generating reports.`,
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
  },
];

// ============================================================================
// Tool Handlers
// ============================================================================

export function createInspectorToolHandlers(
  interceptor: Interceptor,
  reputationManager: ReputationManager
) {
  return {
    // Session Management
    hundredmen_create_session: async (params: { agent_id?: string }) => {
      const session = interceptor.createSession(params.agent_id);
      return {
        success: true,
        session_id: session.id,
        started_at: session.startedAt,
        message: 'Inspection session created. Declare your intent with hundredmen_declare_intent.',
      };
    },
    
    hundredmen_declare_intent: async (params: { session_id: string; intent: string }) => {
      interceptor.declareIntent(params.session_id, params.intent);
      const session = interceptor.getSession(params.session_id);
      return {
        success: true,
        session_id: params.session_id,
        declared_intents: session?.declaredIntents || [],
        message: `Intent recorded: "${params.intent}"`,
      };
    },
    
    hundredmen_end_session: async (params: { session_id: string; reason?: string }) => {
      const session = interceptor.getSession(params.session_id);
      if (!session) {
        return { success: false, error: 'Session not found' };
      }
      
      interceptor.terminateSession(params.session_id, params.reason);
      
      return {
        success: true,
        session_id: params.session_id,
        summary: {
          duration_ms: Date.now() - session.startedAt.getTime(),
          total_calls: session.totalCalls,
          approved_calls: session.approvedCalls,
          blocked_calls: session.blockedCalls,
          pending_calls: session.pendingCalls,
          declared_intents: session.declaredIntents,
          active_servers: session.activeServers,
        },
      };
    },
    
    // Live Feed & History
    hundredmen_get_live_feed: async (params: {
      session_id?: string;
      server?: string;
      status?: CallStatus;
      limit?: number;
    }) => {
      const calls = interceptor.getCallHistory({
        sessionId: params.session_id,
        server: params.server,
        status: params.status,
        limit: params.limit || 20,
      });
      
      return {
        success: true,
        count: calls.length,
        calls: calls.map(c => ({
          id: c.id,
          timestamp: c.timestamp,
          server: c.sourceServer,
          tool: c.tool,
          status: c.status,
          decision: c.decision,
          risk_level: c.intent?.riskLevel,
          drift_detected: c.driftDetected,
          inferred_intent: c.intent?.inferredIntent,
        })),
      };
    },
    
    hundredmen_get_call_history: async (params: {
      session_id?: string;
      server?: string;
      status?: CallStatus;
      since?: string;
      limit?: number;
    }) => {
      const calls = interceptor.getCallHistory({
        sessionId: params.session_id,
        server: params.server,
        status: params.status,
        since: params.since ? new Date(params.since) : undefined,
        limit: params.limit || 100,
      });
      
      return {
        success: true,
        count: calls.length,
        calls: calls.map(c => ({
          id: c.id,
          timestamp: c.timestamp,
          session_id: c.sessionId,
          server: c.sourceServer,
          tool: c.tool,
          arguments: c.arguments,
          status: c.status,
          decision: c.decision,
          decision_reason: c.decisionReason,
          intent: c.intent,
          scan_result: c.scanResult,
          reputation_score: c.reputationScore,
          drift_detected: c.driftDetected,
          duration_ms: c.durationMs,
        })),
      };
    },
    
    hundredmen_diff_intent: async (params: { session_id: string; call_id?: string }) => {
      const session = interceptor.getSession(params.session_id);
      if (!session) {
        return { success: false, error: 'Session not found' };
      }
      
      const calls = interceptor.getCallHistory({ sessionId: params.session_id });
      
      if (params.call_id) {
        const call = calls.find(c => c.id === params.call_id);
        if (!call) {
          return { success: false, error: 'Call not found' };
        }
        
        return {
          success: true,
          declared_intents: session.declaredIntents,
          call: {
            id: call.id,
            tool: call.tool,
            inferred_intent: call.intent?.inferredIntent,
            drift_detected: call.driftDetected,
            risk_level: call.intent?.riskLevel,
          },
          drift_analysis: call.driftDetected ? {
            deviation: 'Tool call deviates from declared intent',
            declared: session.declaredIntents.join('; '),
            actual: call.intent?.inferredIntent,
          } : null,
        };
      }
      
      // Analyze all calls
      const driftCalls = calls.filter(c => c.driftDetected);
      
      return {
        success: true,
        declared_intents: session.declaredIntents,
        total_calls: calls.length,
        drift_detected_count: driftCalls.length,
        drift_rate: calls.length > 0 ? (driftCalls.length / calls.length * 100).toFixed(1) + '%' : '0%',
        drift_calls: driftCalls.map(c => ({
          id: c.id,
          tool: c.tool,
          inferred_intent: c.intent?.inferredIntent,
          risk_level: c.intent?.riskLevel,
        })),
      };
    },
    
    // Manual Approval
    hundredmen_get_pending: async () => {
      const pending = interceptor.getPendingApprovals();
      return {
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
        })),
      };
    },
    
    hundredmen_approve_call: async (params: { call_id: string; approved_by?: string }) => {
      const call = interceptor.approveCall(params.call_id, params.approved_by);
      if (!call) {
        return { success: false, error: 'Call not found or not pending' };
      }
      return {
        success: true,
        call_id: call.id,
        status: call.status,
        message: `Call approved: ${call.tool}`,
      };
    },
    
    hundredmen_block_call: async (params: { call_id: string; blocked_by?: string; reason?: string }) => {
      const call = interceptor.blockCall(params.call_id, params.blocked_by, params.reason);
      if (!call) {
        return { success: false, error: 'Call not found or not pending' };
      }
      return {
        success: true,
        call_id: call.id,
        status: call.status,
        message: `Call blocked: ${call.tool}`,
      };
    },
    
    // Reputation
    hundredmen_check_reputation: async (params: { server_id: string }) => {
      const reputation = reputationManager.getReputation(params.server_id);
      return {
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
      };
    },
    
    hundredmen_report_suspicious: async (params: {
      server_id: string;
      report_type: ReportType;
      description: string;
      evidence?: string;
    }) => {
      const report = reputationManager.submitReport(
        params.server_id,
        'user',
        params.report_type,
        params.description,
        params.evidence
      );
      
      const reputation = reputationManager.getReputation(params.server_id);
      
      return {
        success: true,
        report_id: report.id,
        server_id: params.server_id,
        new_score: reputation.overallScore,
        message: 'Report submitted. Server reputation has been updated.',
      };
    },
    
    hundredmen_get_server_stats: async (params: { server_id: string }) => {
      const reputation = reputationManager.getReputation(params.server_id);
      const reports = reputationManager.getReports(params.server_id);
      
      return {
        success: true,
        server_id: params.server_id,
        stats: {
          total_calls: reputation.totalCalls,
          blocked_calls: reputation.blockedCalls,
          failed_calls: reputation.failedCalls,
          success_rate: reputation.totalCalls > 0
            ? ((reputation.totalCalls - reputation.failedCalls - reputation.blockedCalls) / reputation.totalCalls * 100).toFixed(1) + '%'
            : 'N/A',
          avg_response_time_ms: Math.round(reputation.avgResponseTime),
          community_reports: reports.length,
          pending_reports: reports.filter(r => r.status === 'pending').length,
          confirmed_issues: reports.filter(r => r.status === 'confirmed').length,
        },
        score_history: reputation.scoreHistory.slice(-10),
      };
    },
    
    hundredmen_list_servers: async (params: { filter?: string; min_score?: number }) => {
      let servers = reputationManager.getAllReputations();
      
      if (params.filter === 'verified') {
        servers = reputationManager.getVerifiedServers();
      } else if (params.filter === 'malicious') {
        servers = reputationManager.getMaliciousServers();
      } else if (params.filter === 'low_reputation') {
        servers = reputationManager.getLowReputationServers(params.min_score || 30);
      }
      
      if (params.min_score !== undefined && params.filter !== 'low_reputation') {
        servers = servers.filter(s => s.overallScore >= params.min_score!);
      }
      
      return {
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
      };
    },
    
    // Configuration
    hundredmen_set_policy: async (params: {
      mode?: 'passive' | 'active' | 'strict';
      min_reputation_score?: number;
      require_approval_for?: IntentCategory[];
      drift_threshold?: number;
    }) => {
      const config: Partial<InspectorConfig> = {};
      
      if (params.mode) config.mode = params.mode;
      if (params.min_reputation_score !== undefined) config.minReputationScore = params.min_reputation_score;
      if (params.require_approval_for) config.requireApprovalFor = params.require_approval_for;
      if (params.drift_threshold !== undefined) config.driftThreshold = params.drift_threshold;
      
      interceptor.setConfig(config);
      
      return {
        success: true,
        message: 'Policy updated',
        current_config: interceptor.getConfig(),
      };
    },
    
    hundredmen_get_config: async () => {
      return {
        success: true,
        config: interceptor.getConfig(),
      };
    },
    
    // Statistics
    hundredmen_get_stats: async () => {
      const stats = interceptor.getStats();
      const maliciousCount = reputationManager.getMaliciousServers().length;
      const lowRepCount = reputationManager.getLowReputationServers().length;
      
      return {
        success: true,
        interceptor: stats,
        reputation: {
          total_servers: reputationManager.getAllReputations().length,
          verified_servers: reputationManager.getVerifiedServers().length,
          malicious_servers: maliciousCount,
          low_reputation_servers: lowRepCount,
        },
      };
    },
  };
}

export default inspectorTools;
