/**
 * Weave Protocol LangChain Integration
 * Security callbacks, tool wrappers, and retriever guards for LangChain.js
 * 
 * @packageDocumentation
 * @module @weave_protocol/langchain
 */

// ============================================================================
// Types
// ============================================================================

export type {
  SecurityAction,
  ScanTarget,
  SecurityConfig,
  SecurityEventType,
  ThreatMatch,
  SecurityEvent,
  ScanResult,
  SecureToolConfig,
  SecureRetrieverConfig,
  CallbackStats,
  WeaveIntegrationOptions,
} from './types.js';

export { DEFAULT_CONFIG } from './types.js';

// ============================================================================
// Scanner
// ============================================================================

export type { Scanner } from './scanner.js';

export {
  LocalScanner,
  RemoteScanner,
  createScanner,
} from './scanner.js';

// ============================================================================
// Callback Handler
// ============================================================================

export { WeaveSecurityCallback } from './callback.js';

// ============================================================================
// Secure Tools
// ============================================================================

export type { SecureToolOptions } from './secure-tool.js';

export {
  createSecureTool,
  createSecureStructuredTool,
  createHighRiskTool,
} from './secure-tool.js';

// ============================================================================
// Secure Retrievers
// ============================================================================

export type { SecureRetrieverOptions } from './secure-retriever.js';

export {
  SecureRetriever,
  createSecureRetriever,
  filterSecureDocuments,
} from './secure-retriever.js';

// ============================================================================
// Convenience Presets
// ============================================================================

import { WeaveSecurityCallback } from './callback.js';
import type { SecurityConfig, WeaveIntegrationOptions } from './types.js';

/**
 * Creates a security callback with strict blocking settings
 * Blocks on any threat with medium or higher severity
 */
export function createStrictSecurityCallback(
  options?: WeaveIntegrationOptions
): WeaveSecurityCallback {
  return new WeaveSecurityCallback(
    {
      action: 'block',
      scanTarget: 'both',
      minSeverity: 'medium',
      scanTools: true,
      scanRetrievers: true,
      includeMitre: true,
    },
    options
  );
}

/**
 * Creates a security callback with warning-only settings
 * Logs threats but doesn't block execution
 */
export function createWarningSecurityCallback(
  options?: WeaveIntegrationOptions
): WeaveSecurityCallback {
  return new WeaveSecurityCallback(
    {
      action: 'warn',
      scanTarget: 'both',
      minSeverity: 'low',
      scanTools: true,
      scanRetrievers: true,
      includeMitre: true,
    },
    { ...options, verbose: true }
  );
}

/**
 * Creates a security callback optimized for production
 * Blocks critical threats, warns on high severity
 */
export function createProductionSecurityCallback(
  config?: Partial<SecurityConfig>,
  options?: WeaveIntegrationOptions
): WeaveSecurityCallback {
  return new WeaveSecurityCallback(
    {
      action: 'block',
      scanTarget: 'both',
      minSeverity: 'high',
      scanTools: true,
      scanRetrievers: true,
      includeMitre: true,
      ...config,
    },
    options
  );
}

// ============================================================================
// Version
// ============================================================================

export const VERSION = '1.0.0';
