/**
 * CCPA/CPRA MCP Tools
 * @weave_protocol/domere
 * 
 * MCP tool definitions for CCPA compliance operations
 */

import { CCPAManager } from './ccpa-manager.js';
import {
  OptOutType,
  RequestSource,
  ConsumerRequestType,
  VerificationMethod,
  DenialReason,
  PersonalInfoCategory,
  CCPAReportType,
} from './ccpa-types.js';

// ============================================================================
// Tool Definitions
// ============================================================================

export const ccpaTools = [
  // Consumer Management
  {
    name: 'ccpa_register_consumer',
    description: 'Register a new consumer for CCPA compliance tracking',
    inputSchema: {
      type: 'object',
      properties: {
        email: { type: 'string', description: 'Consumer email address' },
        externalId: { type: 'string', description: 'External system ID' },
        californiaResident: { type: 'boolean', description: 'Whether consumer is a California resident', default: true },
        metadata: { type: 'object', description: 'Additional metadata' },
      },
    },
  },
  {
    name: 'ccpa_get_consumer',
    description: 'Get consumer details by ID or email',
    inputSchema: {
      type: 'object',
      properties: {
        consumerId: { type: 'string', description: 'Consumer ID' },
        email: { type: 'string', description: 'Consumer email (alternative lookup)' },
      },
    },
  },

  // Opt-Out Management
  {
    name: 'ccpa_record_opt_out',
    description: 'Record a consumer opt-out (Do Not Sell/Share)',
    inputSchema: {
      type: 'object',
      properties: {
        consumerId: { type: 'string', description: 'Consumer ID' },
        optOutType: {
          type: 'string',
          enum: ['sale', 'sharing', 'sensitive_use', 'automated_decision', 'profiling', 'cross_context'],
          description: 'Type of opt-out',
        },
        source: {
          type: 'string',
          enum: ['web_form', 'mobile_app', 'api', 'email', 'toll_free', 'in_person', 'agent', 'global_privacy_control'],
          description: 'Source of opt-out request',
        },
        globalPrivacyControl: { type: 'boolean', description: 'Whether triggered by GPC signal' },
      },
      required: ['consumerId', 'optOutType', 'source'],
    },
  },
  {
    name: 'ccpa_process_gpc',
    description: 'Process Global Privacy Control signal for a consumer (auto opts-out of sale and sharing)',
    inputSchema: {
      type: 'object',
      properties: {
        consumerId: { type: 'string', description: 'Consumer ID' },
      },
      required: ['consumerId'],
    },
  },
  {
    name: 'ccpa_withdraw_opt_out',
    description: 'Withdraw a consumer opt-out',
    inputSchema: {
      type: 'object',
      properties: {
        optOutId: { type: 'string', description: 'Opt-out record ID' },
      },
      required: ['optOutId'],
    },
  },
  {
    name: 'ccpa_get_opt_outs',
    description: 'Get all opt-outs for a consumer',
    inputSchema: {
      type: 'object',
      properties: {
        consumerId: { type: 'string', description: 'Consumer ID' },
      },
      required: ['consumerId'],
    },
  },
  {
    name: 'ccpa_check_opt_out',
    description: 'Check if consumer has active opt-out of specific type',
    inputSchema: {
      type: 'object',
      properties: {
        consumerId: { type: 'string', description: 'Consumer ID' },
        optOutType: {
          type: 'string',
          enum: ['sale', 'sharing', 'sensitive_use', 'automated_decision', 'profiling', 'cross_context'],
          description: 'Type of opt-out to check',
        },
      },
      required: ['consumerId', 'optOutType'],
    },
  },

  // Consumer Request Management
  {
    name: 'ccpa_submit_request',
    description: 'Submit a new consumer request (Right to Know, Delete, Correct, etc.)',
    inputSchema: {
      type: 'object',
      properties: {
        consumerId: { type: 'string', description: 'Consumer ID' },
        type: {
          type: 'string',
          enum: ['know_categories', 'know_specific', 'delete', 'correct', 'opt_out_sale', 'opt_out_sharing', 'limit_sensitive', 'portability'],
          description: 'Type of consumer request',
        },
        source: {
          type: 'string',
          enum: ['web_form', 'mobile_app', 'api', 'email', 'toll_free', 'in_person', 'agent', 'global_privacy_control'],
          description: 'Source of request',
        },
        metadata: { type: 'object', description: 'Additional request metadata' },
      },
      required: ['consumerId', 'type'],
    },
  },
  {
    name: 'ccpa_verify_request',
    description: 'Verify consumer identity for a request',
    inputSchema: {
      type: 'object',
      properties: {
        requestId: { type: 'string', description: 'Request ID' },
        method: {
          type: 'string',
          enum: ['email_verification', 'phone_verification', 'knowledge_based', 'government_id', 'signed_declaration', 'account_match', 'authorized_agent'],
          description: 'Verification method used',
        },
      },
      required: ['requestId', 'method'],
    },
  },
  {
    name: 'ccpa_extend_request',
    description: 'Extend request deadline by additional 45 days (allowed once per request)',
    inputSchema: {
      type: 'object',
      properties: {
        requestId: { type: 'string', description: 'Request ID' },
        reason: { type: 'string', description: 'Reason for extension' },
      },
      required: ['requestId', 'reason'],
    },
  },
  {
    name: 'ccpa_complete_request',
    description: 'Complete a consumer request with response',
    inputSchema: {
      type: 'object',
      properties: {
        requestId: { type: 'string', description: 'Request ID' },
        actions: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              type: { type: 'string', enum: ['disclosed', 'deleted', 'corrected', 'opted_out', 'limited', 'denied'] },
              dataCategory: { type: 'string' },
              recordCount: { type: 'number' },
              notes: { type: 'string' },
            },
            required: ['type', 'dataCategory', 'recordCount'],
          },
          description: 'Actions taken to fulfill request',
        },
        format: { type: 'string', enum: ['json', 'csv', 'pdf', 'mail'], default: 'json' },
        data: { type: 'object', description: 'Response data (for know requests)' },
      },
      required: ['requestId', 'actions'],
    },
  },
  {
    name: 'ccpa_deny_request',
    description: 'Deny a consumer request with reason',
    inputSchema: {
      type: 'object',
      properties: {
        requestId: { type: 'string', description: 'Request ID' },
        reason: {
          type: 'string',
          enum: ['unverifiable_identity', 'no_data_found', 'excessive_requests', 'legal_exception', 'service_provider_exception', 'fraud_prevention', 'legal_claims', 'public_interest'],
          description: 'Reason for denial',
        },
      },
      required: ['requestId', 'reason'],
    },
  },
  {
    name: 'ccpa_get_request',
    description: 'Get details of a specific request',
    inputSchema: {
      type: 'object',
      properties: {
        requestId: { type: 'string', description: 'Request ID' },
      },
      required: ['requestId'],
    },
  },
  {
    name: 'ccpa_get_pending_requests',
    description: 'Get all pending consumer requests',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'ccpa_get_overdue_requests',
    description: 'Get all overdue consumer requests (past deadline)',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },

  // Reporting
  {
    name: 'ccpa_generate_report',
    description: 'Generate a CCPA compliance report',
    inputSchema: {
      type: 'object',
      properties: {
        type: {
          type: 'string',
          enum: ['consumer_requests', 'opt_out_summary', 'sale_disclosure', 'service_providers', 'financial_incentives', 'full_compliance'],
          description: 'Type of report',
        },
        startDate: { type: 'string', format: 'date', description: 'Report period start (ISO date)' },
        endDate: { type: 'string', format: 'date', description: 'Report period end (ISO date)' },
      },
      required: ['type', 'startDate', 'endDate'],
    },
  },
  {
    name: 'ccpa_annual_metrics',
    description: 'Generate annual metrics disclosure (required by CCPA)',
    inputSchema: {
      type: 'object',
      properties: {
        year: { type: 'number', description: 'Year for metrics (e.g., 2025)' },
      },
      required: ['year'],
    },
  },

  // Checkpoints
  {
    name: 'ccpa_get_checkpoints',
    description: 'Get audit trail checkpoints for CCPA compliance',
    inputSchema: {
      type: 'object',
      properties: {
        consumerId: { type: 'string', description: 'Filter by consumer ID (optional)' },
      },
    },
  },
  {
    name: 'ccpa_verify_chain',
    description: 'Verify integrity of CCPA checkpoint chain',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
];

// ============================================================================
// Tool Handlers
// ============================================================================

export function createCCPAToolHandlers(manager: CCPAManager) {
  return {
    ccpa_register_consumer: (args: {
      email?: string;
      externalId?: string;
      californiaResident?: boolean;
      metadata?: Record<string, unknown>;
    }) => {
      const consumer = manager.registerConsumer(args);
      return { success: true, consumer };
    },

    ccpa_get_consumer: (args: { consumerId?: string; email?: string }) => {
      let consumer;
      if (args.consumerId) {
        consumer = manager.getConsumer(args.consumerId);
      } else if (args.email) {
        consumer = manager.findConsumerByEmail(args.email);
      }
      if (!consumer) {
        return { success: false, error: 'Consumer not found' };
      }
      return { success: true, consumer };
    },

    ccpa_record_opt_out: (args: {
      consumerId: string;
      optOutType: OptOutType;
      source: RequestSource;
      globalPrivacyControl?: boolean;
    }) => {
      const optOut = manager.recordOptOut(args);
      return { success: true, optOut };
    },

    ccpa_process_gpc: (args: { consumerId: string }) => {
      const optOuts = manager.processGPC(args.consumerId);
      return { success: true, optOuts, message: 'GPC signal processed - opted out of sale and sharing' };
    },

    ccpa_withdraw_opt_out: (args: { optOutId: string }) => {
      const optOut = manager.withdrawOptOut(args.optOutId);
      if (!optOut) {
        return { success: false, error: 'Opt-out not found' };
      }
      return { success: true, optOut };
    },

    ccpa_get_opt_outs: (args: { consumerId: string }) => {
      const optOuts = manager.getConsumerOptOuts(args.consumerId);
      return { success: true, optOuts };
    },

    ccpa_check_opt_out: (args: { consumerId: string; optOutType: OptOutType }) => {
      const hasOptOut = manager.hasActiveOptOut(args.consumerId, args.optOutType);
      return { success: true, hasOptOut, optOutType: args.optOutType };
    },

    ccpa_submit_request: (args: {
      consumerId: string;
      type: ConsumerRequestType;
      source?: RequestSource;
      metadata?: Record<string, unknown>;
    }) => {
      const request = manager.submitRequest(args);
      return { 
        success: true, 
        request,
        message: `Request submitted. Due date: ${request.dueDate.toISOString().split('T')[0]} (45 days)`,
      };
    },

    ccpa_verify_request: (args: { requestId: string; method: VerificationMethod }) => {
      const request = manager.verifyRequest(args.requestId, args.method);
      if (!request) {
        return { success: false, error: 'Request not found' };
      }
      return { success: true, request };
    },

    ccpa_extend_request: (args: { requestId: string; reason: string }) => {
      const request = manager.extendRequest(args.requestId, args.reason);
      if (!request) {
        return { success: false, error: 'Request not found or already extended' };
      }
      return { 
        success: true, 
        request,
        message: `Deadline extended to ${request.extendedDueDate?.toISOString().split('T')[0]}`,
      };
    },

    ccpa_complete_request: (args: {
      requestId: string;
      actions: Array<{
        type: 'disclosed' | 'deleted' | 'corrected' | 'opted_out' | 'limited' | 'denied';
        dataCategory: PersonalInfoCategory;
        recordCount: number;
        notes?: string;
      }>;
      format?: 'json' | 'csv' | 'pdf' | 'mail';
      data?: Record<string, unknown>;
    }) => {
      const request = manager.completeRequest(args.requestId, {
        actions: args.actions.map(a => ({
          ...a,
          completedAt: new Date(),
        })),
        format: args.format || 'json',
        data: args.data,
      });
      if (!request) {
        return { success: false, error: 'Request not found' };
      }
      return { success: true, request };
    },

    ccpa_deny_request: (args: { requestId: string; reason: DenialReason }) => {
      const request = manager.denyRequest(args.requestId, args.reason);
      if (!request) {
        return { success: false, error: 'Request not found' };
      }
      return { success: true, request };
    },

    ccpa_get_request: (args: { requestId: string }) => {
      const request = manager.getRequest(args.requestId);
      if (!request) {
        return { success: false, error: 'Request not found' };
      }
      return { success: true, request };
    },

    ccpa_get_pending_requests: () => {
      const requests = manager.getPendingRequests();
      return { success: true, requests, count: requests.length };
    },

    ccpa_get_overdue_requests: () => {
      const requests = manager.getOverdueRequests();
      return { 
        success: true, 
        requests, 
        count: requests.length,
        alert: requests.length > 0 ? 'WARNING: Overdue requests require immediate attention' : undefined,
      };
    },

    ccpa_generate_report: (args: { type: CCPAReportType; startDate: string; endDate: string }) => {
      const report = manager.generateReport(args.type, {
        start: new Date(args.startDate),
        end: new Date(args.endDate),
      });
      return { success: true, report };
    },

    ccpa_annual_metrics: (args: { year: number }) => {
      const metrics = manager.generateAnnualMetrics(args.year);
      return { 
        success: true, 
        metrics,
        note: 'These metrics are required for annual disclosure under CCPA Section 1798.185(a)(7)',
      };
    },

    ccpa_get_checkpoints: (args: { consumerId?: string }) => {
      const checkpoints = manager.getCheckpoints(args.consumerId);
      return { success: true, checkpoints, count: checkpoints.length };
    },

    ccpa_verify_chain: () => {
      const result = manager.verifyCheckpointChain();
      return { 
        success: true, 
        ...result,
        message: result.valid ? 'Checkpoint chain integrity verified' : 'Chain integrity broken',
      };
    },
  };
}
