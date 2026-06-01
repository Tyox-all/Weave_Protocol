/**
 * @weave_protocol/browser — public API
 *
 * Primary export: WardBrowserGuard class.
 * Plus: IPI scanner, provenance utilities, types, errors.
 */

export { WardBrowserGuard } from './guard.js';
export { scanForIpi, getPatternCatalog } from './ipi.js';
export type { ScanOptions } from './ipi.js';
export {
  resolveWardForCwd,
  loadWardFromSource,
  loadWardFromPath,
  evaluateNavigation,
  evaluateDownload,
  evaluateTaintedAction,
} from './policy.js';
export type { ResolvedWard } from './policy.js';
export {
  getOrCreateSession,
  recordIngestion,
  isTainted,
  getSession,
  clearSession,
  clearAllSessions,
  classifyTrust,
} from './provenance.js';
export {
  WardBrowserDeniedError,
  IpiDetectedError,
} from './types.js';
export type {
  Decision,
  DecisionResult,
  IpiThreat,
  IpiThreatType,
  IpiScanResult,
  NavigationCheck,
  DownloadCheck,
  SessionProvenance,
  GuardOptions,
} from './types.js';
