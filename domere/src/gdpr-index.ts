/**
 * GDPR Module Exports
 * @weave_protocol/domere
 * 
 * Note: RetentionPolicy is renamed to GDPRRetentionPolicy to avoid
 * conflict with existing RetentionPolicy in compliance/index.js
 */

// Types - explicit exports to avoid naming conflicts
export {
  DataSubject,
  ConsentRecord,
  ConsentPurpose,
  LegalBasis,
  ConsentSource,
  DSARRequest,
  DSARType,
  DSARStatus,
  DSARResponse,
  DSARAction,
  VerificationMethod,
  ProcessingRecord,
  DataController,
  DataProcessor,
  DataCategory,
  DataRecipient,
  ThirdCountryTransfer,
  TransferSafeguard,
  RetentionPeriod,
  DataBreach,
  BreachSeverity,
  BreachStatus,
  BreachCause,
  MitigationAction,
  SupervisoryNotification,
  SubjectNotification,
  RetentionPolicy as GDPRRetentionPolicy,
  DeletionMethod,
  RetentionException,
  RetentionCheck,
  AutomatedDecision,
  DecisionSignificance,
  GDPRReport,
  GDPRReportType,
  GDPRReportSummary,
  GDPRCheckpoint,
  GDPRCheckpointType,
} from './gdpr-types.js';

// Manager
export { GDPRManager, default as GDPRManagerDefault } from './gdpr-manager.js';

// MCP Tools
export { gdprTools, createGDPRToolHandlers } from './gdpr-tools.js';
