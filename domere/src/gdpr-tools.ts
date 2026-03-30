/**
 * GDPR MCP Tools
 * @weave_protocol/domere
 * 
 * MCP tool definitions for GDPR compliance operations
 */

import { z } from 'zod';
import GDPRManager from './gdpr-manager.js';
import {
  ConsentPurpose,
  LegalBasis,
  ConsentSource,
  DSARType,
  VerificationMethod,
  DataCategory,
  BreachSeverity,
  BreachCause,
  DecisionSignificance,
  GDPRReportType,
  DeletionMethod,
} from './gdpr-types.js';

// ============================================================================
// Schema Definitions
// ============================================================================

const ConsentPurposeSchema = z.enum([
  'marketing',
  'analytics',
  'personalization',
  'third_party_sharing',
  'profiling',
  'automated_decision',
  'research',
  'service_delivery',
  'legal_obligation',
  'custom',
]);

const LegalBasisSchema = z.enum([
  'consent',
  'contract',
  'legal_obligation',
  'vital_interests',
  'public_task',
  'legitimate_interest',
]);

const ConsentSourceSchema = z.enum([
  'web_form',
  'mobile_app',
  'api',
  'email',
  'verbal',
  'written',
  'agent',
]);

const DSARTypeSchema = z.enum([
  'access',
  'rectification',
  'erasure',
  'restriction',
  'portability',
  'objection',
  'automated_decision',
]);

const VerificationMethodSchema = z.enum([
  'email',
  'sms',
  'id_document',
  'knowledge_based',
  'in_person',
  'trusted_source',
]);

const DataCategorySchema = z.enum([
  'identification',
  'contact',
  'financial',
  'location',
  'behavioral',
  'technical',
  'health',
  'biometric',
  'genetic',
  'political',
  'religious',
  'trade_union',
  'sexual_orientation',
  'criminal',
]);

const BreachSeveritySchema = z.enum(['low', 'medium', 'high', 'critical']);

const BreachCauseSchema = z.enum([
  'cyber_attack',
  'human_error',
  'system_failure',
  'unauthorized_access',
  'lost_device',
  'phishing',
  'insider_threat',
  'third_party',
  'unknown',
]);

const DecisionSignificanceSchema = z.enum([
  'legal_effects',
  'similarly_significant',
  'minor',
]);

const GDPRReportTypeSchema = z.enum([
  'consent_summary',
  'dsar_summary',
  'processing_records',
  'breach_report',
  'retention_report',
  'automated_decisions',
  'full_compliance',
]);

// ============================================================================
// Tool Definitions
// ============================================================================

export const gdprTools = [
  // --------------------------------------------------------------------------
  // Consent Management Tools
  // --------------------------------------------------------------------------
  {
    name: 'domere_gdpr_record_consent',
    description: `Record a data subject's consent for a specific processing purpose. 
Creates an auditable consent record with legal basis tracking per GDPR Article 6.
Use when: capturing user consent, updating consent preferences, documenting legal basis for processing.`,
    inputSchema: {
      type: 'object',
      properties: {
        subject_id: {
          type: 'string',
          description: 'Unique identifier for the data subject',
        },
        email: {
          type: 'string',
          description: 'Email address of the data subject (optional, for new subjects)',
        },
        purpose: {
          type: 'string',
          enum: ['marketing', 'analytics', 'personalization', 'third_party_sharing', 'profiling', 'automated_decision', 'research', 'service_delivery', 'legal_obligation', 'custom'],
          description: 'Purpose for which consent is being recorded',
        },
        legal_basis: {
          type: 'string',
          enum: ['consent', 'contract', 'legal_obligation', 'vital_interests', 'public_task', 'legitimate_interest'],
          description: 'Legal basis under GDPR Article 6',
        },
        granted: {
          type: 'boolean',
          description: 'Whether consent was granted (true) or denied (false)',
        },
        source: {
          type: 'string',
          enum: ['web_form', 'mobile_app', 'api', 'email', 'verbal', 'written', 'agent'],
          description: 'Source/channel through which consent was obtained',
        },
        version: {
          type: 'string',
          description: 'Version of the consent/privacy policy',
        },
        expires_days: {
          type: 'number',
          description: 'Number of days until consent expires (optional)',
        },
      },
      required: ['subject_id', 'purpose', 'legal_basis', 'granted', 'source', 'version'],
    },
  },
  {
    name: 'domere_gdpr_withdraw_consent',
    description: `Withdraw a previously granted consent. 
Creates an audit trail of the withdrawal per GDPR Article 7(3).
Use when: user requests to withdraw consent, updating consent status, handling opt-out requests.`,
    inputSchema: {
      type: 'object',
      properties: {
        consent_id: {
          type: 'string',
          description: 'ID of the consent record to withdraw',
        },
        reason: {
          type: 'string',
          description: 'Reason for withdrawal (optional)',
        },
      },
      required: ['consent_id'],
    },
  },
  {
    name: 'domere_gdpr_check_consent',
    description: `Check if a data subject has valid consent for a specific purpose.
Returns current consent status and details.
Use when: validating consent before processing, checking consent status, auditing consent records.`,
    inputSchema: {
      type: 'object',
      properties: {
        subject_id: {
          type: 'string',
          description: 'Unique identifier for the data subject',
        },
        purpose: {
          type: 'string',
          enum: ['marketing', 'analytics', 'personalization', 'third_party_sharing', 'profiling', 'automated_decision', 'research', 'service_delivery', 'legal_obligation', 'custom'],
          description: 'Purpose to check consent for',
        },
      },
      required: ['subject_id', 'purpose'],
    },
  },

  // --------------------------------------------------------------------------
  // DSAR Tools
  // --------------------------------------------------------------------------
  {
    name: 'domere_gdpr_handle_dsar',
    description: `Create and manage a Data Subject Access Request (DSAR).
Supports all GDPR rights: access (Art 15), rectification (Art 16), erasure (Art 17), 
restriction (Art 18), portability (Art 20), objection (Art 21), automated decisions (Art 22).
Use when: receiving subject rights requests, managing DSAR workflow, tracking request deadlines.`,
    inputSchema: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: ['create', 'verify', 'process', 'complete', 'extend', 'reject', 'status'],
          description: 'Action to perform on the DSAR',
        },
        subject_id: {
          type: 'string',
          description: 'Data subject ID (required for create)',
        },
        dsar_id: {
          type: 'string',
          description: 'DSAR ID (required for verify/process/complete/extend/reject/status)',
        },
        type: {
          type: 'string',
          enum: ['access', 'rectification', 'erasure', 'restriction', 'portability', 'objection', 'automated_decision'],
          description: 'Type of DSAR (required for create)',
        },
        verification_method: {
          type: 'string',
          enum: ['email', 'sms', 'id_document', 'knowledge_based', 'in_person', 'trusted_source'],
          description: 'Method used to verify identity',
        },
        assigned_to: {
          type: 'string',
          description: 'Person/team assigned to handle the request',
        },
        extension_days: {
          type: 'number',
          description: 'Days to extend deadline (max 60, for extend action)',
        },
        extension_reason: {
          type: 'string',
          description: 'Reason for extension (required for extend action)',
        },
        rejection_reason: {
          type: 'string',
          description: 'Reason for rejection (required for reject action)',
        },
        response_data_included: {
          type: 'boolean',
          description: 'Whether data is included in response (for complete action)',
        },
        response_format: {
          type: 'string',
          enum: ['json', 'csv', 'pdf', 'xml'],
          description: 'Format of exported data (for complete action)',
        },
      },
      required: ['action'],
    },
  },
  {
    name: 'domere_gdpr_right_to_erasure',
    description: `Execute the right to erasure ("right to be forgotten") per GDPR Article 17.
Permanently deletes all personal data for a subject while maintaining audit compliance.
Use when: processing erasure requests, handling deletion requests, clearing user data.`,
    inputSchema: {
      type: 'object',
      properties: {
        subject_id: {
          type: 'string',
          description: 'Data subject ID to erase',
        },
        reason: {
          type: 'string',
          description: 'Reason for erasure (consent withdrawn, data no longer necessary, etc.)',
        },
        verify_no_legal_hold: {
          type: 'boolean',
          description: 'Confirm there are no legal holds preventing erasure',
        },
      },
      required: ['subject_id', 'reason', 'verify_no_legal_hold'],
    },
  },
  {
    name: 'domere_gdpr_data_portability',
    description: `Export data subject's personal data in a portable format per GDPR Article 20.
Generates a machine-readable export of all personal data.
Use when: handling portability requests, exporting user data, transferring data to another controller.`,
    inputSchema: {
      type: 'object',
      properties: {
        subject_id: {
          type: 'string',
          description: 'Data subject ID to export',
        },
        format: {
          type: 'string',
          enum: ['json', 'csv'],
          description: 'Export format (default: json)',
        },
      },
      required: ['subject_id'],
    },
  },

  // --------------------------------------------------------------------------
  // Processing Records Tools
  // --------------------------------------------------------------------------
  {
    name: 'domere_gdpr_log_processing',
    description: `Create or update processing activity records per GDPR Article 30.
Maintains the required register of processing activities.
Use when: documenting new processing activities, updating existing records, audit preparation.`,
    inputSchema: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: ['create', 'update', 'list', 'get'],
          description: 'Action to perform',
        },
        record_id: {
          type: 'string',
          description: 'Processing record ID (for update/get)',
        },
        name: {
          type: 'string',
          description: 'Name of the processing activity',
        },
        description: {
          type: 'string',
          description: 'Description of the processing',
        },
        purposes: {
          type: 'array',
          items: { type: 'string' },
          description: 'Purposes of processing',
        },
        legal_basis: {
          type: 'string',
          enum: ['consent', 'contract', 'legal_obligation', 'vital_interests', 'public_task', 'legitimate_interest'],
          description: 'Legal basis for processing',
        },
        data_categories: {
          type: 'array',
          items: {
            type: 'string',
            enum: ['identification', 'contact', 'financial', 'location', 'behavioral', 'technical', 'health', 'biometric', 'genetic', 'political', 'religious', 'trade_union', 'sexual_orientation', 'criminal'],
          },
          description: 'Categories of personal data processed',
        },
        subject_categories: {
          type: 'array',
          items: { type: 'string' },
          description: 'Categories of data subjects (e.g., customers, employees)',
        },
        retention_days: {
          type: 'number',
          description: 'Retention period in days',
        },
        technical_measures: {
          type: 'array',
          items: { type: 'string' },
          description: 'Technical security measures in place',
        },
        organizational_measures: {
          type: 'array',
          items: { type: 'string' },
          description: 'Organizational security measures in place',
        },
      },
      required: ['action'],
    },
  },

  // --------------------------------------------------------------------------
  // Breach Notification Tools
  // --------------------------------------------------------------------------
  {
    name: 'domere_gdpr_breach_notify',
    description: `Report and manage data breaches per GDPR Articles 33-34.
Tracks 72-hour notification deadline and manages breach response workflow.
Use when: reporting data breaches, tracking breach response, notifying authorities/subjects.`,
    inputSchema: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: ['report', 'mitigate', 'notify_authority', 'notify_subjects', 'close', 'status', 'list_active'],
          description: 'Action to perform',
        },
        breach_id: {
          type: 'string',
          description: 'Breach ID (for actions other than report/list_active)',
        },
        description: {
          type: 'string',
          description: 'Description of the breach (for report)',
        },
        severity: {
          type: 'string',
          enum: ['low', 'medium', 'high', 'critical'],
          description: 'Severity level of the breach',
        },
        affected_subjects: {
          type: 'number',
          description: 'Number of affected data subjects',
        },
        affected_categories: {
          type: 'array',
          items: {
            type: 'string',
            enum: ['identification', 'contact', 'financial', 'location', 'behavioral', 'technical', 'health', 'biometric', 'genetic', 'political', 'religious', 'trade_union', 'sexual_orientation', 'criminal'],
          },
          description: 'Categories of data affected',
        },
        cause: {
          type: 'string',
          enum: ['cyber_attack', 'human_error', 'system_failure', 'unauthorized_access', 'lost_device', 'phishing', 'insider_threat', 'third_party', 'unknown'],
          description: 'Cause of the breach',
        },
        consequences: {
          type: 'array',
          items: { type: 'string' },
          description: 'Potential consequences of the breach',
        },
        mitigation_action: {
          type: 'string',
          description: 'Mitigation action taken (for mitigate)',
        },
        mitigation_by: {
          type: 'string',
          description: 'Person who performed mitigation',
        },
        mitigation_effective: {
          type: 'boolean',
          description: 'Whether mitigation was effective',
        },
        authority: {
          type: 'string',
          description: 'Supervisory authority name (for notify_authority)',
        },
        reference_number: {
          type: 'string',
          description: 'Authority reference number',
        },
        notification_method: {
          type: 'string',
          enum: ['email', 'letter', 'public_notice', 'direct_contact'],
          description: 'Method of subject notification',
        },
        subjects_notified: {
          type: 'number',
          description: 'Number of subjects notified',
        },
        root_cause_analysis: {
          type: 'string',
          description: 'Root cause analysis (for close)',
        },
        preventive_measures: {
          type: 'array',
          items: { type: 'string' },
          description: 'Preventive measures implemented',
        },
      },
      required: ['action'],
    },
  },

  // --------------------------------------------------------------------------
  // Retention Tools
  // --------------------------------------------------------------------------
  {
    name: 'domere_gdpr_retention_check',
    description: `Manage and execute data retention policies per GDPR Article 5(1)(e).
Enforces storage limitation principle and documents retention decisions.
Use when: creating retention policies, running retention checks, auditing data lifecycle.`,
    inputSchema: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: ['create_policy', 'execute_check', 'list_policies', 'get_policy'],
          description: 'Action to perform',
        },
        policy_id: {
          type: 'string',
          description: 'Policy ID (for execute_check/get_policy)',
        },
        name: {
          type: 'string',
          description: 'Policy name (for create_policy)',
        },
        description: {
          type: 'string',
          description: 'Policy description',
        },
        data_categories: {
          type: 'array',
          items: {
            type: 'string',
            enum: ['identification', 'contact', 'financial', 'location', 'behavioral', 'technical', 'health', 'biometric', 'genetic', 'political', 'religious', 'trade_union', 'sexual_orientation', 'criminal'],
          },
          description: 'Categories of data covered by policy',
        },
        retention_days: {
          type: 'number',
          description: 'Retention period in days',
        },
        legal_basis: {
          type: 'string',
          description: 'Legal basis for retention period',
        },
        deletion_method: {
          type: 'string',
          enum: ['hard_delete', 'soft_delete', 'anonymization', 'pseudonymization', 'encryption_key_destruction'],
          description: 'Method of data deletion',
        },
        review_cycle_days: {
          type: 'number',
          description: 'Days between policy reviews',
        },
      },
      required: ['action'],
    },
  },

  // --------------------------------------------------------------------------
  // Automated Decision Tools
  // --------------------------------------------------------------------------
  {
    name: 'domere_gdpr_automated_decision',
    description: `Track automated decisions and ensure Article 22 compliance.
Records automated decision-making, tracks human review requirements, manages appeals.
Use when: logging AI/ML decisions, ensuring human oversight, handling decision appeals.`,
    inputSchema: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: ['record', 'human_review', 'list_pending_reviews', 'get_decision'],
          description: 'Action to perform',
        },
        decision_id: {
          type: 'string',
          description: 'Decision ID (for human_review/get_decision)',
        },
        subject_id: {
          type: 'string',
          description: 'Data subject ID (for record)',
        },
        decision_type: {
          type: 'string',
          description: 'Type of decision (e.g., credit_scoring, fraud_detection)',
        },
        algorithm: {
          type: 'string',
          description: 'Name/version of algorithm used',
        },
        input_data: {
          type: 'array',
          items: { type: 'string' },
          description: 'Categories of input data used',
        },
        outcome: {
          type: 'string',
          description: 'Decision outcome',
        },
        significance: {
          type: 'string',
          enum: ['legal_effects', 'similarly_significant', 'minor'],
          description: 'Significance level of the decision',
        },
        legal_basis: {
          type: 'string',
          enum: ['consent', 'contract', 'legal_obligation', 'vital_interests', 'public_task', 'legitimate_interest'],
          description: 'Legal basis for automated processing',
        },
        explanation: {
          type: 'string',
          description: 'Human-readable explanation of decision logic',
        },
        reviewed_by: {
          type: 'string',
          description: 'Person conducting human review',
        },
        review_outcome: {
          type: 'string',
          description: 'Outcome of human review',
        },
      },
      required: ['action'],
    },
  },

  // --------------------------------------------------------------------------
  // Reporting Tools
  // --------------------------------------------------------------------------
  {
    name: 'domere_gdpr_report',
    description: `Generate GDPR compliance reports and dashboards.
Creates audit-ready reports for consent, DSARs, breaches, retention, and overall compliance.
Use when: preparing for audits, generating compliance dashboards, reviewing GDPR status.`,
    inputSchema: {
      type: 'object',
      properties: {
        report_type: {
          type: 'string',
          enum: ['consent_summary', 'dsar_summary', 'processing_records', 'breach_report', 'retention_report', 'automated_decisions', 'full_compliance'],
          description: 'Type of report to generate',
        },
        start_date: {
          type: 'string',
          description: 'Report period start date (ISO 8601)',
        },
        end_date: {
          type: 'string',
          description: 'Report period end date (ISO 8601)',
        },
        format: {
          type: 'string',
          enum: ['json', 'summary'],
          description: 'Output format',
        },
      },
      required: ['report_type', 'start_date', 'end_date'],
    },
  },
];

// ============================================================================
// Tool Handler Implementation
// ============================================================================

export function createGDPRToolHandlers(manager: GDPRManager) {
  return {
    domere_gdpr_record_consent: async (params: {
      subject_id: string;
      email?: string;
      purpose: ConsentPurpose;
      legal_basis: LegalBasis;
      granted: boolean;
      source: ConsentSource;
      version: string;
      expires_days?: number;
    }) => {
      // Register subject if new with email
      let subject = manager.getSubject(params.subject_id);
      if (!subject && params.email) {
        subject = manager.registerSubject({
          id: params.subject_id,
          email: params.email,
        });
      }

      const expiresAt = params.expires_days
        ? new Date(Date.now() + params.expires_days * 24 * 60 * 60 * 1000)
        : undefined;

      const consent = manager.recordConsent({
        subjectId: params.subject_id,
        purpose: params.purpose,
        legalBasis: params.legal_basis,
        granted: params.granted,
        source: params.source,
        version: params.version,
        expiresAt,
      });

      return {
        success: true,
        consent_id: consent.id,
        subject_id: consent.subjectId,
        purpose: consent.purpose,
        granted: consent.granted,
        granted_at: consent.grantedAt,
        expires_at: consent.expiresAt,
        message: `Consent ${consent.granted ? 'granted' : 'denied'} for ${consent.purpose}`,
      };
    },

    domere_gdpr_withdraw_consent: async (params: {
      consent_id: string;
      reason?: string;
    }) => {
      const consent = manager.withdrawConsent(params.consent_id, params.reason);
      if (!consent) {
        return { success: false, error: 'Consent record not found' };
      }

      return {
        success: true,
        consent_id: consent.id,
        purpose: consent.purpose,
        withdrawn_at: consent.withdrawnAt,
        message: `Consent withdrawn for ${consent.purpose}`,
      };
    },

    domere_gdpr_check_consent: async (params: {
      subject_id: string;
      purpose: ConsentPurpose;
    }) => {
      const hasConsent = manager.hasValidConsent(params.subject_id, params.purpose);
      const activeConsents = manager.getActiveConsents(params.subject_id);
      const relevantConsent = activeConsents.find(c => c.purpose === params.purpose);

      return {
        has_valid_consent: hasConsent,
        purpose: params.purpose,
        consent_details: relevantConsent || null,
        all_active_consents: activeConsents.map(c => ({
          id: c.id,
          purpose: c.purpose,
          legal_basis: c.legalBasis,
          granted_at: c.grantedAt,
          expires_at: c.expiresAt,
        })),
      };
    },

    domere_gdpr_handle_dsar: async (params: {
      action: 'create' | 'verify' | 'process' | 'complete' | 'extend' | 'reject' | 'status';
      subject_id?: string;
      dsar_id?: string;
      type?: DSARType;
      verification_method?: VerificationMethod;
      assigned_to?: string;
      extension_days?: number;
      extension_reason?: string;
      rejection_reason?: string;
      response_data_included?: boolean;
      response_format?: 'json' | 'csv' | 'pdf' | 'xml';
    }) => {
      switch (params.action) {
        case 'create': {
          if (!params.subject_id || !params.type) {
            return { success: false, error: 'subject_id and type required for create' };
          }
          const dsar = manager.createDSAR({
            subjectId: params.subject_id,
            type: params.type,
            verificationMethod: params.verification_method,
          });
          return {
            success: true,
            dsar_id: dsar.id,
            type: dsar.type,
            status: dsar.status,
            due_date: dsar.dueDate,
            message: `DSAR created: ${dsar.type} request, due ${dsar.dueDate.toISOString().split('T')[0]}`,
          };
        }

        case 'verify': {
          if (!params.dsar_id || !params.assigned_to) {
            return { success: false, error: 'dsar_id and assigned_to required for verify' };
          }
          const dsar = manager.verifyDSAR(params.dsar_id, params.assigned_to);
          if (!dsar) return { success: false, error: 'DSAR not found' };
          return {
            success: true,
            dsar_id: dsar.id,
            status: dsar.status,
            verified_at: dsar.verifiedAt,
            assigned_to: dsar.assignedTo,
          };
        }

        case 'process': {
          if (!params.dsar_id || !params.assigned_to) {
            return { success: false, error: 'dsar_id and assigned_to required for process' };
          }
          const dsar = manager.processDSAR(params.dsar_id, params.assigned_to);
          if (!dsar) return { success: false, error: 'DSAR not found' };
          return {
            success: true,
            dsar_id: dsar.id,
            status: dsar.status,
            assigned_to: dsar.assignedTo,
          };
        }

        case 'complete': {
          if (!params.dsar_id) {
            return { success: false, error: 'dsar_id required for complete' };
          }
          const dsar = manager.completeDSAR(params.dsar_id, {
            type: manager.getDSAR(params.dsar_id)?.type || 'access',
            completedAt: new Date(),
            dataIncluded: params.response_data_included,
            dataFormat: params.response_format,
          });
          if (!dsar) return { success: false, error: 'DSAR not found' };
          return {
            success: true,
            dsar_id: dsar.id,
            status: dsar.status,
            completed_at: dsar.completedAt,
            within_deadline: dsar.completedAt! <= dsar.dueDate,
          };
        }

        case 'extend': {
          if (!params.dsar_id || !params.extension_days || !params.extension_reason) {
            return { success: false, error: 'dsar_id, extension_days, and extension_reason required' };
          }
          try {
            const dsar = manager.extendDSAR(params.dsar_id, params.extension_days, params.extension_reason);
            if (!dsar) return { success: false, error: 'DSAR not found' };
            return {
              success: true,
              dsar_id: dsar.id,
              status: dsar.status,
              new_due_date: dsar.dueDate,
              extension_reason: params.extension_reason,
            };
          } catch (error: any) {
            return { success: false, error: error.message };
          }
        }

        case 'reject': {
          if (!params.dsar_id || !params.rejection_reason) {
            return { success: false, error: 'dsar_id and rejection_reason required' };
          }
          const dsar = manager.rejectDSAR(params.dsar_id, params.rejection_reason);
          if (!dsar) return { success: false, error: 'DSAR not found' };
          return {
            success: true,
            dsar_id: dsar.id,
            status: dsar.status,
            rejection_reason: params.rejection_reason,
          };
        }

        case 'status': {
          if (!params.dsar_id) {
            return { success: false, error: 'dsar_id required for status' };
          }
          const dsar = manager.getDSAR(params.dsar_id);
          if (!dsar) return { success: false, error: 'DSAR not found' };
          return {
            success: true,
            dsar: {
              id: dsar.id,
              type: dsar.type,
              status: dsar.status,
              requested_at: dsar.requestedAt,
              due_date: dsar.dueDate,
              verified_at: dsar.verifiedAt,
              completed_at: dsar.completedAt,
              assigned_to: dsar.assignedTo,
              response: dsar.response,
            },
          };
        }

        default:
          return { success: false, error: `Unknown action: ${params.action}` };
      }
    },

    domere_gdpr_right_to_erasure: async (params: {
      subject_id: string;
      reason: string;
      verify_no_legal_hold: boolean;
    }) => {
      if (!params.verify_no_legal_hold) {
        return {
          success: false,
          error: 'Must confirm no legal hold exists (verify_no_legal_hold: true)',
        };
      }

      const result = await manager.executeErasure(params.subject_id, params.reason);
      return {
        success: result.success,
        erased_records: result.erasedRecords,
        errors: result.errors,
        message: result.success
          ? `Successfully erased ${result.erasedRecords} records for subject`
          : `Erasure failed: ${result.errors.join(', ')}`,
      };
    },

    domere_gdpr_data_portability: async (params: {
      subject_id: string;
      format?: 'json' | 'csv';
    }) => {
      const exportData = manager.exportSubjectData(params.subject_id, params.format || 'json');

      if (!exportData.subject) {
        return { success: false, error: 'Subject not found' };
      }

      return {
        success: true,
        export: {
          subject: exportData.subject,
          consents_count: exportData.consents.length,
          dsar_requests_count: exportData.dsarRequests.length,
          automated_decisions_count: exportData.automatedDecisions.length,
          exported_at: exportData.exportedAt,
          format: exportData.format,
        },
        data: exportData,
      };
    },

    domere_gdpr_log_processing: async (params: {
      action: 'create' | 'update' | 'list' | 'get';
      record_id?: string;
      name?: string;
      description?: string;
      purposes?: string[];
      legal_basis?: LegalBasis;
      data_categories?: DataCategory[];
      subject_categories?: string[];
      retention_days?: number;
      technical_measures?: string[];
      organizational_measures?: string[];
    }) => {
      switch (params.action) {
        case 'create': {
          if (!params.name || !params.description || !params.purposes || !params.legal_basis) {
            return { success: false, error: 'name, description, purposes, and legal_basis required' };
          }
          const record = manager.createProcessingRecord({
            name: params.name,
            description: params.description,
            controller: { name: 'Controller', email: 'dpo@example.com' },
            purposes: params.purposes,
            legalBasis: params.legal_basis,
            categories: params.data_categories || [],
            subjectCategories: params.subject_categories || [],
            recipients: [],
            retentionPeriod: {
              duration: params.retention_days,
              unit: 'days',
            },
            technicalMeasures: params.technical_measures || [],
            organizationalMeasures: params.organizational_measures || [],
            reviewDate: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
            status: 'active',
          });
          return {
            success: true,
            record_id: record.id,
            name: record.name,
            message: `Processing record created: ${record.name}`,
          };
        }

        case 'list': {
          const records = manager.getProcessingRecords();
          return {
            success: true,
            count: records.length,
            records: records.map(r => ({
              id: r.id,
              name: r.name,
              legal_basis: r.legalBasis,
              status: r.status,
              review_date: r.reviewDate,
            })),
          };
        }

        case 'get': {
          if (!params.record_id) {
            return { success: false, error: 'record_id required' };
          }
          const record = manager.getProcessingRecord(params.record_id);
          if (!record) return { success: false, error: 'Record not found' };
          return { success: true, record };
        }

        default:
          return { success: false, error: `Unknown action: ${params.action}` };
      }
    },

    domere_gdpr_breach_notify: async (params: {
      action: 'report' | 'mitigate' | 'notify_authority' | 'notify_subjects' | 'close' | 'status' | 'list_active';
      breach_id?: string;
      description?: string;
      severity?: BreachSeverity;
      affected_subjects?: number;
      affected_categories?: DataCategory[];
      cause?: BreachCause;
      consequences?: string[];
      mitigation_action?: string;
      mitigation_by?: string;
      mitigation_effective?: boolean;
      authority?: string;
      reference_number?: string;
      notification_method?: 'email' | 'letter' | 'public_notice' | 'direct_contact';
      subjects_notified?: number;
      root_cause_analysis?: string;
      preventive_measures?: string[];
    }) => {
      switch (params.action) {
        case 'report': {
          if (!params.description || !params.severity || !params.affected_subjects || !params.cause) {
            return { success: false, error: 'description, severity, affected_subjects, and cause required' };
          }
          const breach = manager.reportBreach({
            description: params.description,
            severity: params.severity,
            affectedSubjects: params.affected_subjects,
            affectedCategories: params.affected_categories || [],
            cause: params.cause,
            consequences: params.consequences || [],
          });

          const deadlineDate = new Date(breach.detectedAt.getTime() + 72 * 60 * 60 * 1000);
          return {
            success: true,
            breach_id: breach.id,
            severity: breach.severity,
            status: breach.status,
            detected_at: breach.detectedAt,
            notification_deadline: deadlineDate,
            message: `⚠️ BREACH REPORTED: ${params.severity} severity. Supervisory authority must be notified by ${deadlineDate.toISOString()}`,
          };
        }

        case 'mitigate': {
          if (!params.breach_id || !params.mitigation_action || !params.mitigation_by) {
            return { success: false, error: 'breach_id, mitigation_action, and mitigation_by required' };
          }
          const breach = manager.addBreachMitigation(params.breach_id, {
            action: params.mitigation_action,
            performedBy: params.mitigation_by,
            effective: params.mitigation_effective ?? true,
          });
          if (!breach) return { success: false, error: 'Breach not found' };
          return {
            success: true,
            breach_id: breach.id,
            status: breach.status,
            mitigations_count: breach.mitigationActions.length,
          };
        }

        case 'notify_authority': {
          if (!params.breach_id || !params.authority) {
            return { success: false, error: 'breach_id and authority required' };
          }
          const breach = manager.notifySupervisoryAuthority(
            params.breach_id,
            params.authority,
            params.reference_number
          );
          if (!breach) return { success: false, error: 'Breach not found' };
          return {
            success: true,
            breach_id: breach.id,
            authority: breach.supervisoryNotification?.authority,
            within_72_hours: breach.supervisoryNotification?.withinDeadline,
            reference_number: breach.supervisoryNotification?.referenceNumber,
            message: breach.supervisoryNotification?.withinDeadline
              ? '✓ Authority notified within 72-hour deadline'
              : '⚠️ Authority notified AFTER 72-hour deadline',
          };
        }

        case 'notify_subjects': {
          if (!params.breach_id || !params.notification_method || !params.subjects_notified) {
            return { success: false, error: 'breach_id, notification_method, and subjects_notified required' };
          }
          const breach = manager.notifyAffectedSubjects(
            params.breach_id,
            params.notification_method,
            params.subjects_notified
          );
          if (!breach) return { success: false, error: 'Breach not found' };
          return {
            success: true,
            breach_id: breach.id,
            subjects_notified: params.subjects_notified,
            method: params.notification_method,
          };
        }

        case 'close': {
          if (!params.breach_id || !params.root_cause_analysis || !params.preventive_measures) {
            return { success: false, error: 'breach_id, root_cause_analysis, and preventive_measures required' };
          }
          const breach = manager.closeBreach(
            params.breach_id,
            params.root_cause_analysis,
            params.preventive_measures
          );
          if (!breach) return { success: false, error: 'Breach not found' };
          return {
            success: true,
            breach_id: breach.id,
            status: breach.status,
            closed_at: breach.closedAt,
            message: 'Breach closed with root cause analysis and preventive measures documented',
          };
        }

        case 'status': {
          if (!params.breach_id) {
            return { success: false, error: 'breach_id required' };
          }
          const breach = manager.getBreach(params.breach_id);
          if (!breach) return { success: false, error: 'Breach not found' };
          return { success: true, breach };
        }

        case 'list_active': {
          const breaches = manager.getActiveBreaches();
          return {
            success: true,
            count: breaches.length,
            breaches: breaches.map(b => ({
              id: b.id,
              severity: b.severity,
              status: b.status,
              detected_at: b.detectedAt,
              affected_subjects: b.affectedSubjects,
            })),
          };
        }

        default:
          return { success: false, error: `Unknown action: ${params.action}` };
      }
    },

    domere_gdpr_retention_check: async (params: {
      action: 'create_policy' | 'execute_check' | 'list_policies' | 'get_policy';
      policy_id?: string;
      name?: string;
      description?: string;
      data_categories?: DataCategory[];
      retention_days?: number;
      legal_basis?: string;
      deletion_method?: DeletionMethod;
      review_cycle_days?: number;
    }) => {
      switch (params.action) {
        case 'create_policy': {
          if (!params.name || !params.retention_days || !params.deletion_method) {
            return { success: false, error: 'name, retention_days, and deletion_method required' };
          }
          const policy = manager.createRetentionPolicy({
            name: params.name,
            description: params.description || '',
            dataCategories: params.data_categories || [],
            retentionPeriod: {
              duration: params.retention_days,
              unit: 'days',
              reviewCycle: params.review_cycle_days,
            },
            legalBasis: params.legal_basis || 'Business requirement',
            deletionMethod: params.deletion_method,
            status: 'active',
            nextReviewDate: new Date(Date.now() + (params.review_cycle_days || 365) * 24 * 60 * 60 * 1000),
          });
          return {
            success: true,
            policy_id: policy.id,
            name: policy.name,
            retention_days: params.retention_days,
            deletion_method: policy.deletionMethod,
          };
        }

        case 'execute_check': {
          if (!params.policy_id) {
            return { success: false, error: 'policy_id required' };
          }
          try {
            const check = manager.executeRetentionCheck(params.policy_id);
            return {
              success: true,
              check_id: check.id,
              records_checked: check.recordsChecked,
              records_expired: check.recordsExpired,
              records_deleted: check.recordsDeleted,
              status: check.status,
            };
          } catch (error: any) {
            return { success: false, error: error.message };
          }
        }

        case 'list_policies': {
          const policies = manager.getRetentionPolicies();
          return {
            success: true,
            count: policies.length,
            policies: policies.map(p => ({
              id: p.id,
              name: p.name,
              retention_days: p.retentionPeriod.duration,
              deletion_method: p.deletionMethod,
              status: p.status,
            })),
          };
        }

        default:
          return { success: false, error: `Unknown action: ${params.action}` };
      }
    },

    domere_gdpr_automated_decision: async (params: {
      action: 'record' | 'human_review' | 'list_pending_reviews' | 'get_decision';
      decision_id?: string;
      subject_id?: string;
      decision_type?: string;
      algorithm?: string;
      input_data?: string[];
      outcome?: string;
      significance?: DecisionSignificance;
      legal_basis?: LegalBasis;
      explanation?: string;
      reviewed_by?: string;
      review_outcome?: string;
    }) => {
      switch (params.action) {
        case 'record': {
          if (!params.subject_id || !params.decision_type || !params.algorithm || !params.outcome || !params.significance || !params.legal_basis) {
            return { success: false, error: 'subject_id, decision_type, algorithm, outcome, significance, and legal_basis required' };
          }
          const decision = manager.recordAutomatedDecision({
            subjectId: params.subject_id,
            decisionType: params.decision_type,
            algorithm: params.algorithm,
            inputData: params.input_data || [],
            outcome: params.outcome,
            significance: params.significance,
            legalBasis: params.legal_basis,
            explanation: params.explanation,
          });
          return {
            success: true,
            decision_id: decision.id,
            human_review_required: decision.humanReviewRequired,
            appealable: decision.appealable,
            appeal_deadline: decision.appealDeadline,
            message: decision.humanReviewRequired
              ? '⚠️ Human review REQUIRED for this decision (Article 22)'
              : 'Decision recorded',
          };
        }

        case 'human_review': {
          if (!params.decision_id || !params.reviewed_by || !params.review_outcome) {
            return { success: false, error: 'decision_id, reviewed_by, and review_outcome required' };
          }
          const decision = manager.completeHumanReview(
            params.decision_id,
            params.reviewed_by,
            params.review_outcome
          );
          if (!decision) return { success: false, error: 'Decision not found' };
          return {
            success: true,
            decision_id: decision.id,
            reviewed_by: decision.reviewedBy,
            reviewed_at: decision.reviewedAt,
            original_outcome: decision.outcome,
            review_outcome: decision.reviewOutcome,
          };
        }

        case 'list_pending_reviews': {
          const pending = manager.getPendingHumanReviews();
          return {
            success: true,
            count: pending.length,
            decisions: pending.map(d => ({
              id: d.id,
              subject_id: d.subjectId,
              type: d.decisionType,
              outcome: d.outcome,
              significance: d.significance,
              appeal_deadline: d.appealDeadline,
            })),
          };
        }

        case 'get_decision': {
          if (!params.decision_id) {
            return { success: false, error: 'decision_id required' };
          }
          // Would need to add a getDecision method to manager
          return { success: false, error: 'Not implemented' };
        }

        default:
          return { success: false, error: `Unknown action: ${params.action}` };
      }
    },

    domere_gdpr_report: async (params: {
      report_type: GDPRReportType;
      start_date: string;
      end_date: string;
      format?: 'json' | 'summary';
    }) => {
      const report = manager.generateReport(params.report_type, {
        start: new Date(params.start_date),
        end: new Date(params.end_date),
      });

      if (params.format === 'summary') {
        return {
          success: true,
          report_id: report.id,
          type: report.type,
          period: report.period,
          summary: report.summary,
          generated_at: report.generatedAt,
        };
      }

      return {
        success: true,
        report,
      };
    },
  };
}

export default gdprTools;
