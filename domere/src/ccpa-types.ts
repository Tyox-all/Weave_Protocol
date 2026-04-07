/**
 * CCPA/CPRA Compliance Types and Interfaces
 * @weave_protocol/domere
 * 
 * California Consumer Privacy Act (CCPA) + California Privacy Rights Act (CPRA)
 */

// ============================================================================
// Consumer Types (CCPA equivalent of GDPR Data Subject)
// ============================================================================

export interface Consumer {
  id: string;
  externalId?: string;
  email?: string;
  californiaResident: boolean;
  createdAt: Date;
  updatedAt: Date;
  metadata?: Record<string, unknown>;
}

export interface OptOutRecord {
  id: string;
  consumerId: string;
  optOutType: OptOutType;
  status: 'active' | 'withdrawn';
  requestedAt: Date;
  effectiveAt: Date;
  withdrawnAt?: Date;
  source: RequestSource;
  globalPrivacyControl?: boolean;
  metadata?: Record<string, unknown>;
}

export type OptOutType =
  | 'sale'                    // Do Not Sell My Personal Information
  | 'sharing'                 // Do Not Share (CPRA)
  | 'sensitive_use'           // Limit Use of Sensitive Personal Info (CPRA)
  | 'automated_decision'      // Opt out of automated decision-making (CPRA)
  | 'profiling'               // Opt out of profiling (CPRA)
  | 'cross_context';          // Cross-context behavioral advertising

export type RequestSource =
  | 'web_form'
  | 'mobile_app'
  | 'api'
  | 'email'
  | 'toll_free'
  | 'in_person'
  | 'agent'
  | 'global_privacy_control';

// ============================================================================
// Consumer Request Types (CCPA equivalent of GDPR DSAR)
// ============================================================================

export interface ConsumerRequest {
  id: string;
  consumerId: string;
  type: ConsumerRequestType;
  status: ConsumerRequestStatus;
  requestedAt: Date;
  acknowledgedAt?: Date;
  completedAt?: Date;
  dueDate: Date;
  extendedDueDate?: Date;
  extensionReason?: string;
  assignedTo?: string;
  verificationMethod?: VerificationMethod;
  verifiedAt?: Date;
  response?: ConsumerRequestResponse;
  metadata?: Record<string, unknown>;
}

export type ConsumerRequestType =
  | 'know_categories'         // Right to Know - Categories
  | 'know_specific'           // Right to Know - Specific Pieces
  | 'delete'                  // Right to Delete
  | 'correct'                 // Right to Correct (CPRA)
  | 'opt_out_sale'            // Right to Opt-Out of Sale
  | 'opt_out_sharing'         // Right to Opt-Out of Sharing (CPRA)
  | 'limit_sensitive'         // Right to Limit Sensitive PI Use (CPRA)
  | 'portability';            // Right to Portability (CPRA)

export type ConsumerRequestStatus =
  | 'pending_verification'
  | 'verified'
  | 'in_progress'
  | 'pending_review'
  | 'completed'
  | 'denied'
  | 'extended';

export type VerificationMethod =
  | 'email_verification'
  | 'phone_verification'
  | 'knowledge_based'
  | 'government_id'
  | 'signed_declaration'
  | 'account_match'
  | 'authorized_agent';

export interface ConsumerRequestResponse {
  id: string;
  requestId: string;
  respondedAt: Date;
  actions: ConsumerRequestAction[];
  denialReason?: DenialReason;
  data?: Record<string, unknown>;
  format: 'json' | 'csv' | 'pdf' | 'mail';
}

export interface ConsumerRequestAction {
  type: 'disclosed' | 'deleted' | 'corrected' | 'opted_out' | 'limited' | 'denied';
  dataCategory: PersonalInfoCategory;
  recordCount: number;
  completedAt: Date;
  notes?: string;
}

export type DenialReason =
  | 'unverifiable_identity'
  | 'no_data_found'
  | 'excessive_requests'
  | 'legal_exception'
  | 'service_provider_exception'
  | 'fraud_prevention'
  | 'legal_claims'
  | 'public_interest';

// ============================================================================
// Personal Information Categories (CCPA Section 1798.140)
// ============================================================================

export type PersonalInfoCategory =
  | 'identifiers'                    // Name, alias, SSN, DL, passport, etc.
  | 'customer_records'               // Paper/electronic customer records
  | 'protected_classifications'      // Age, race, religion, sexual orientation
  | 'commercial_info'                // Products purchased, history, tendencies
  | 'biometric'                      // Physiological, behavioral characteristics
  | 'internet_activity'              // Browsing, search history, interactions
  | 'geolocation'                    // Precise physical location
  | 'sensory_data'                   // Audio, electronic, visual, thermal, olfactory
  | 'professional_info'              // Employment-related information
  | 'education_info'                 // Non-public education records (FERPA)
  | 'inferences'                     // Profiles reflecting preferences, behavior
  | 'sensitive_personal_info';       // CPRA sensitive categories

export type SensitivePersonalInfo =
  | 'ssn_drivers_license'            // Government IDs
  | 'financial_account'              // Account + credentials
  | 'precise_geolocation'            // Within 1,850 feet
  | 'racial_ethnic_origin'
  | 'religious_beliefs'
  | 'union_membership'
  | 'mail_email_text_contents'       // Unless business is intended recipient
  | 'genetic_data'
  | 'biometric_identification'
  | 'health_info'
  | 'sex_life_orientation';

// ============================================================================
// Business & Service Provider Types
// ============================================================================

export interface Business {
  id: string;
  name: string;
  address: string;
  privacyPolicyUrl: string;
  doNotSellUrl: string;
  tollFreeNumber?: string;
  contactEmail: string;
  annualRevenue?: 'under_25m' | 'over_25m';
  meetsThreshold: boolean;
  registeredDataBroker?: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface ServiceProvider {
  id: string;
  name: string;
  businessId: string;
  contractDate: Date;
  purposes: ServiceProviderPurpose[];
  certifications: string[];
  status: 'active' | 'terminated';
  lastAuditDate?: Date;
  nextAuditDate?: Date;
}

export type ServiceProviderPurpose =
  | 'data_processing'
  | 'analytics'
  | 'marketing'
  | 'customer_service'
  | 'security'
  | 'compliance'
  | 'infrastructure';

// ============================================================================
// Sale/Sharing Disclosure Types
// ============================================================================

export interface SaleDisclosure {
  id: string;
  businessId: string;
  period: {
    start: Date;
    end: Date;
  };
  categoriesSold: PersonalInfoCategory[];
  categoriesShared: PersonalInfoCategory[];
  thirdPartyCategories: ThirdPartyCategory[];
  businessPurposes: BusinessPurpose[];
  createdAt: Date;
}

export type ThirdPartyCategory =
  | 'advertising_networks'
  | 'data_analytics'
  | 'social_networks'
  | 'data_brokers'
  | 'service_providers'
  | 'business_partners'
  | 'government_entities';

export type BusinessPurpose =
  | 'auditing'
  | 'security'
  | 'debugging'
  | 'short_term_use'
  | 'service_provision'
  | 'internal_research'
  | 'quality_assurance';

// ============================================================================
// Financial Incentive Types
// ============================================================================

export interface FinancialIncentive {
  id: string;
  businessId: string;
  name: string;
  description: string;
  type: IncentiveType;
  value: number;
  dataCategories: PersonalInfoCategory[];
  terms: string;
  optInRequired: boolean;
  withdrawalAllowed: boolean;
  status: 'active' | 'inactive';
  createdAt: Date;
  updatedAt: Date;
}

export type IncentiveType =
  | 'loyalty_program'
  | 'discount'
  | 'premium_service'
  | 'sweepstakes'
  | 'rewards';

export interface IncentiveEnrollment {
  id: string;
  consumerId: string;
  incentiveId: string;
  enrolledAt: Date;
  withdrawnAt?: Date;
  status: 'active' | 'withdrawn';
}

// ============================================================================
// CCPA Report Types
// ============================================================================

export interface CCPAReport {
  id: string;
  type: CCPAReportType;
  generatedAt: Date;
  period: {
    start: Date;
    end: Date;
  };
  summary: CCPAReportSummary;
  details: Record<string, unknown>;
  format: 'json' | 'pdf' | 'html';
}

export type CCPAReportType =
  | 'consumer_requests'
  | 'opt_out_summary'
  | 'sale_disclosure'
  | 'service_providers'
  | 'financial_incentives'
  | 'full_compliance';

export interface CCPAReportSummary {
  totalConsumers: number;
  requestsReceived: number;
  requestsCompleted: number;
  requestsDenied: number;
  avgResponseTime: number;
  medianResponseTime: number;
  optOutsActive: number;
  salesDisclosed: number;
  complianceScore: number;
}

// ============================================================================
// Annual Metrics (Required Disclosure)
// ============================================================================

export interface AnnualMetrics {
  year: number;
  requestsToKnow: {
    received: number;
    complied: number;
    denied: number;
    avgDaysToRespond: number;
  };
  requestsToDelete: {
    received: number;
    complied: number;
    denied: number;
    avgDaysToRespond: number;
  };
  requestsToOptOut: {
    received: number;
    complied: number;
    denied: number;
    avgDaysToRespond: number;
  };
  requestsToCorrect?: {  // CPRA
    received: number;
    complied: number;
    denied: number;
    avgDaysToRespond: number;
  };
}

// ============================================================================
// CCPA Checkpoint Integration
// ============================================================================

export interface CCPACheckpoint {
  id: string;
  type: CCPACheckpointType;
  timestamp: Date;
  actor: string;
  action: string;
  consumerId?: string;
  details: Record<string, unknown>;
  hash: string;
  previousHash?: string;
  blockchainAnchor?: {
    chain: 'solana' | 'ethereum';
    transactionId: string;
    anchoredAt: Date;
  };
}

export type CCPACheckpointType =
  | 'request_received'
  | 'request_verified'
  | 'request_completed'
  | 'request_denied'
  | 'opt_out_recorded'
  | 'opt_out_withdrawn'
  | 'data_disclosed'
  | 'data_deleted'
  | 'data_corrected'
  | 'sale_recorded'
  | 'incentive_enrolled'
  | 'incentive_withdrawn';
