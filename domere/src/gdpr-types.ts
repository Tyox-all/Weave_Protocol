/**
 * GDPR Compliance Types and Interfaces
 * @weave_protocol/domere
 */

// ============================================================================
// Data Subject Types
// ============================================================================

export interface DataSubject {
  id: string;
  externalId?: string;
  email?: string;
  createdAt: Date;
  updatedAt: Date;
  metadata?: Record<string, unknown>;
}

export interface ConsentRecord {
  id: string;
  subjectId: string;
  purpose: ConsentPurpose;
  legalBasis: LegalBasis;
  granted: boolean;
  grantedAt?: Date;
  withdrawnAt?: Date;
  expiresAt?: Date;
  source: ConsentSource;
  version: string;
  metadata?: Record<string, unknown>;
}

export type ConsentPurpose =
  | 'marketing'
  | 'analytics'
  | 'personalization'
  | 'third_party_sharing'
  | 'profiling'
  | 'automated_decision'
  | 'research'
  | 'service_delivery'
  | 'legal_obligation'
  | 'custom';

export type LegalBasis =
  | 'consent'           // Article 6(1)(a)
  | 'contract'          // Article 6(1)(b)
  | 'legal_obligation'  // Article 6(1)(c)
  | 'vital_interests'   // Article 6(1)(d)
  | 'public_task'       // Article 6(1)(e)
  | 'legitimate_interest'; // Article 6(1)(f)

export type ConsentSource =
  | 'web_form'
  | 'mobile_app'
  | 'api'
  | 'email'
  | 'verbal'
  | 'written'
  | 'agent';

// ============================================================================
// Data Subject Access Request (DSAR) Types
// ============================================================================

export interface DSARRequest {
  id: string;
  subjectId: string;
  type: DSARType;
  status: DSARStatus;
  requestedAt: Date;
  acknowledgedAt?: Date;
  completedAt?: Date;
  dueDate: Date;
  assignedTo?: string;
  verificationMethod?: VerificationMethod;
  verifiedAt?: Date;
  response?: DSARResponse;
  metadata?: Record<string, unknown>;
}

export type DSARType =
  | 'access'           // Article 15 - Right of access
  | 'rectification'    // Article 16 - Right to rectification
  | 'erasure'          // Article 17 - Right to erasure
  | 'restriction'      // Article 18 - Right to restriction
  | 'portability'      // Article 20 - Right to data portability
  | 'objection'        // Article 21 - Right to object
  | 'automated_decision'; // Article 22 - Automated decision-making

export type DSARStatus =
  | 'pending_verification'
  | 'verified'
  | 'in_progress'
  | 'pending_review'
  | 'completed'
  | 'rejected'
  | 'extended';

export type VerificationMethod =
  | 'email'
  | 'sms'
  | 'id_document'
  | 'knowledge_based'
  | 'in_person'
  | 'trusted_source';

export interface DSARResponse {
  type: DSARType;
  completedAt: Date;
  dataIncluded?: boolean;
  dataFormat?: 'json' | 'csv' | 'pdf' | 'xml';
  dataLocation?: string;
  rejectionReason?: string;
  extensionReason?: string;
  actions?: DSARAction[];
}

export interface DSARAction {
  action: string;
  performedAt: Date;
  performedBy: string;
  details?: Record<string, unknown>;
}

// ============================================================================
// Processing Records (Article 30)
// ============================================================================

export interface ProcessingRecord {
  id: string;
  name: string;
  description: string;
  controller: DataController;
  processor?: DataProcessor;
  purposes: string[];
  legalBasis: LegalBasis;
  categories: DataCategory[];
  subjectCategories: string[];
  recipients: DataRecipient[];
  thirdCountryTransfers?: ThirdCountryTransfer[];
  retentionPeriod: RetentionPeriod;
  technicalMeasures: string[];
  organizationalMeasures: string[];
  createdAt: Date;
  updatedAt: Date;
  reviewDate: Date;
  status: 'active' | 'inactive' | 'pending_review';
}

export interface DataController {
  name: string;
  address?: string;
  email: string;
  phone?: string;
  dpoContact?: string;
}

export interface DataProcessor {
  name: string;
  address?: string;
  email: string;
  contractDate?: Date;
  subProcessors?: string[];
}

export type DataCategory =
  | 'identification'
  | 'contact'
  | 'financial'
  | 'location'
  | 'behavioral'
  | 'technical'
  | 'health'
  | 'biometric'
  | 'genetic'
  | 'political'
  | 'religious'
  | 'trade_union'
  | 'sexual_orientation'
  | 'criminal';

export interface DataRecipient {
  name: string;
  category: 'internal' | 'external' | 'public_authority';
  purpose: string;
  legalBasis?: string;
}

export interface ThirdCountryTransfer {
  country: string;
  safeguard: TransferSafeguard;
  details?: string;
}

export type TransferSafeguard =
  | 'adequacy_decision'
  | 'standard_clauses'
  | 'binding_corporate_rules'
  | 'certification'
  | 'code_of_conduct'
  | 'explicit_consent'
  | 'derogation';

export interface RetentionPeriod {
  duration?: number;
  unit?: 'days' | 'months' | 'years';
  criteria?: string;
  reviewCycle?: number;
}

// ============================================================================
// Data Breach Types
// ============================================================================

export interface DataBreach {
  id: string;
  detectedAt: Date;
  reportedAt?: Date;
  description: string;
  severity: BreachSeverity;
  status: BreachStatus;
  affectedSubjects: number;
  affectedCategories: DataCategory[];
  cause: BreachCause;
  consequences: string[];
  mitigationActions: MitigationAction[];
  supervisoryNotification?: SupervisoryNotification;
  subjectNotification?: SubjectNotification;
  rootCauseAnalysis?: string;
  preventiveMeasures?: string[];
  closedAt?: Date;
}

export type BreachSeverity = 'low' | 'medium' | 'high' | 'critical';

export type BreachStatus =
  | 'detected'
  | 'investigating'
  | 'contained'
  | 'notifying'
  | 'remediated'
  | 'closed';

export type BreachCause =
  | 'cyber_attack'
  | 'human_error'
  | 'system_failure'
  | 'unauthorized_access'
  | 'lost_device'
  | 'phishing'
  | 'insider_threat'
  | 'third_party'
  | 'unknown';

export interface MitigationAction {
  action: string;
  performedAt: Date;
  performedBy: string;
  effective: boolean;
}

export interface SupervisoryNotification {
  authority: string;
  notifiedAt: Date;
  referenceNumber?: string;
  withinDeadline: boolean;
  delayReason?: string;
}

export interface SubjectNotification {
  notifiedAt: Date;
  method: 'email' | 'letter' | 'public_notice' | 'direct_contact';
  subjectsNotified: number;
  template?: string;
}

// ============================================================================
// Retention Policy Types
// ============================================================================

export interface RetentionPolicy {
  id: string;
  name: string;
  description: string;
  dataCategories: DataCategory[];
  retentionPeriod: RetentionPeriod;
  legalBasis: string;
  deletionMethod: DeletionMethod;
  exceptions?: RetentionException[];
  status: 'active' | 'inactive';
  createdAt: Date;
  updatedAt: Date;
  nextReviewDate: Date;
}

export type DeletionMethod =
  | 'hard_delete'
  | 'soft_delete'
  | 'anonymization'
  | 'pseudonymization'
  | 'encryption_key_destruction';

export interface RetentionException {
  reason: string;
  legalBasis: string;
  expiresAt?: Date;
}

export interface RetentionCheck {
  id: string;
  policyId: string;
  executedAt: Date;
  recordsChecked: number;
  recordsExpired: number;
  recordsDeleted: number;
  recordsExcepted: number;
  errors: string[];
  status: 'completed' | 'partial' | 'failed';
}

// ============================================================================
// Automated Decision Types (Article 22)
// ============================================================================

export interface AutomatedDecision {
  id: string;
  subjectId: string;
  decisionType: string;
  algorithm: string;
  inputData: string[];
  outcome: string;
  significance: DecisionSignificance;
  legalBasis: LegalBasis;
  humanReviewRequired: boolean;
  humanReviewCompleted?: boolean;
  reviewedBy?: string;
  reviewedAt?: Date;
  reviewOutcome?: string;
  explanation?: string;
  appealable: boolean;
  appealDeadline?: Date;
  createdAt: Date;
}

export type DecisionSignificance =
  | 'legal_effects'
  | 'similarly_significant'
  | 'minor';

// ============================================================================
// GDPR Report Types
// ============================================================================

export interface GDPRReport {
  id: string;
  type: GDPRReportType;
  generatedAt: Date;
  period: {
    start: Date;
    end: Date;
  };
  summary: GDPRReportSummary;
  details: Record<string, unknown>;
  format: 'json' | 'pdf' | 'html';
}

export type GDPRReportType =
  | 'consent_summary'
  | 'dsar_summary'
  | 'processing_records'
  | 'breach_report'
  | 'retention_report'
  | 'automated_decisions'
  | 'full_compliance';

export interface GDPRReportSummary {
  totalSubjects: number;
  activeConsents: number;
  dsarRequests: number;
  dsarCompleted: number;
  dsarPending: number;
  avgResponseTime: number;
  breaches: number;
  retentionViolations: number;
  automatedDecisions: number;
  humanReviews: number;
  complianceScore: number;
}

// ============================================================================
// GDPR Checkpoint Integration
// ============================================================================

export interface GDPRCheckpoint {
  id: string;
  type: GDPRCheckpointType;
  timestamp: Date;
  actor: string;
  action: string;
  subjectId?: string;
  details: Record<string, unknown>;
  hash: string;
  previousHash?: string;
  blockchainAnchor?: {
    chain: 'solana' | 'ethereum';
    transactionId: string;
    anchoredAt: Date;
  };
}

export type GDPRCheckpointType =
  | 'consent_granted'
  | 'consent_withdrawn'
  | 'dsar_received'
  | 'dsar_completed'
  | 'data_accessed'
  | 'data_modified'
  | 'data_deleted'
  | 'data_exported'
  | 'breach_detected'
  | 'breach_notified'
  | 'retention_executed'
  | 'automated_decision'
  | 'human_review';
