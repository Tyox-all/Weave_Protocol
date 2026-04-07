/**
 * CCPA/CPRA Compliance Module
 * @weave_protocol/domere
 */

// Re-export types with CCPA prefix to avoid conflicts with GDPR
export {
  Consumer,
  OptOutRecord,
  OptOutType,
  RequestSource,
  ConsumerRequest,
  ConsumerRequestType,
  ConsumerRequestStatus,
  ConsumerRequestResponse,
  ConsumerRequestAction,
  VerificationMethod as CCPAVerificationMethod,
  DenialReason,
  PersonalInfoCategory,
  SensitivePersonalInfo,
  Business,
  ServiceProvider,
  ServiceProviderPurpose,
  SaleDisclosure,
  ThirdPartyCategory,
  BusinessPurpose,
  FinancialIncentive,
  IncentiveType,
  IncentiveEnrollment,
  CCPAReport,
  CCPAReportType,
  CCPAReportSummary,
  AnnualMetrics,
  CCPACheckpoint,
  CCPACheckpointType,
} from './ccpa-types.js';

export { CCPAManager, createCCPAManager } from './ccpa-manager.js';
export { ccpaTools, createCCPAToolHandlers } from './ccpa-tools.js';
