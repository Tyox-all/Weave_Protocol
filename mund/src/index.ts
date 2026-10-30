/**
 * @weave_protocol/mund: library entry point.
 * The MCP server lives in server.ts (bin).
 */

export { ThreatIntelManager, threatIntel } from './threat-intel-manager.js';
export { threatIntelTools, createThreatIntelToolHandlers } from './threat-intel-tools.js';
export * from './threat-intel-types.js';

// Scanning
export { scan, SCAN_TYPES } from './scan.js';
export type { ScanType, ScanOptions, ScanResult } from './scan.js';
export {
  AnalyzerEngine, getAnalyzers,
  SecretScanner, PIIDetector, CodeAnalyzer, InjectionDetector, ExfiltrationDetector, McpServerAnalyzer,
} from './analyzers/index.js';
export { DEFAULT_RULES } from './constants.js';
export { computeRiskScore, labelForScore } from './scoring.js';
export type { RiskScore } from './scoring.js';
export type { Severity, SecurityIssue, DetectionRule, IAnalyzer } from './types.js';

// Importing this module has no side effects. Run directly (`node dist/index.js`,
// as older MCP configs do), it still starts the server; the bin points at server.js.
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const invokedDirectly = (() => {
  try {
    return !!process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
})();
if (invokedDirectly) void import('./server.js');
