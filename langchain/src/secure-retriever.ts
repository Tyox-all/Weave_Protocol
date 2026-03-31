/**
 * Secure Retriever Wrapper
 * Wraps LangChain retrievers with security scanning
 * @weave_protocol/langchain
 */

import { BaseRetriever } from '@langchain/core/retrievers';
import type { Document } from '@langchain/core/documents';
import type { CallbackManagerForRetrieverRun } from '@langchain/core/callbacks/manager';

import type { SecureRetrieverConfig, SecurityConfig, ThreatMatch } from './types.js';
import { DEFAULT_CONFIG } from './types.js';
import { createScanner, type Scanner } from './scanner.js';

// ============================================================================
// PII Patterns for Redaction
// ============================================================================

const PII_PATTERNS: Array<{ name: string; pattern: RegExp; replacement: string }> = [
  { name: 'ssn', pattern: /\b\d{3}-\d{2}-\d{4}\b/g, replacement: '[SSN REDACTED]' },
  { name: 'email', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, replacement: '[EMAIL REDACTED]' },
  { name: 'phone', pattern: /\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, replacement: '[PHONE REDACTED]' },
  { name: 'credit_card', pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/g, replacement: '[CC REDACTED]' },
  { name: 'ip_address', pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, replacement: '[IP REDACTED]' },
];

// ============================================================================
// Secure Retriever
// ============================================================================

export interface SecureRetrieverOptions extends SecureRetrieverConfig {
  /** Scanner instance */
  scanner?: Scanner;
  
  /** Callback when threat is detected */
  onThreat?: (threats: ThreatMatch[], document: Document) => void | Promise<void>;
  
  /** Custom redaction function */
  redactor?: (content: string) => string;
}

export class SecureRetriever extends BaseRetriever {
  lc_namespace = ['weave_protocol', 'langchain'];
  
  private wrappedRetriever: BaseRetriever;
  private scanner: Scanner;
  private config: SecurityConfig;
  private options: SecureRetrieverOptions;

  constructor(
    retriever: BaseRetriever,
    options: SecureRetrieverOptions
  ) {
    super();
    
    this.wrappedRetriever = retriever;
    this.options = options;
    this.scanner = options.scanner || createScanner();
    this.config = { ...DEFAULT_CONFIG, ...options.security };
  }

  async _getRelevantDocuments(
    query: string,
    runManager?: CallbackManagerForRetrieverRun
  ): Promise<Document[]> {
    // Scan the query first
    const queryScan = await this.scanner.scan(query, {
      categories: this.config.categories,
      minSeverity: this.config.minSeverity,
    });

    if (queryScan.threats.length > 0 && this.config.action === 'block') {
      throw new Error(
        `[SecureRetriever:${this.options.name}] Blocked: Threat detected in query. ` +
        `Threats: ${queryScan.threats.map(t => t.patternName).join(', ')}`
      );
    }

    // Get documents from wrapped retriever
    const documents = await this.wrappedRetriever._getRelevantDocuments(query, runManager);

    if (!this.options.scanDocuments) {
      return documents;
    }

    // Scan and optionally redact documents
    const securedDocuments: Document[] = [];
    const maxDocs = this.options.maxDocumentsToScan ?? documents.length;

    for (let i = 0; i < Math.min(documents.length, maxDocs); i++) {
      const doc = documents[i];
      let content = doc.pageContent;

      // Scan document content
      const docScan = await this.scanner.scan(content, {
        categories: this.config.categories,
        minSeverity: this.config.minSeverity,
      });

      if (docScan.threats.length > 0) {
        // Emit threat callback
        if (this.options.onThreat) {
          await this.options.onThreat(docScan.threats, doc);
        }

        // Block if configured
        if (this.config.action === 'block') {
          throw new Error(
            `[SecureRetriever:${this.options.name}] Blocked: Threat in document ${i}. ` +
            `Source: ${doc.metadata?.source || 'unknown'}`
          );
        }
      }

      // Redact sensitive content if enabled
      if (this.options.redactSensitive) {
        content = this.redactContent(content);
      }

      securedDocuments.push({
        pageContent: content,
        metadata: {
          ...doc.metadata,
          _weave_scanned: true,
          _weave_threats_found: docScan.threatCount,
          _weave_redacted: this.options.redactSensitive || false,
        },
      });
    }

    // Add remaining documents without scanning (if maxDocumentsToScan was exceeded)
    for (let i = maxDocs; i < documents.length; i++) {
      let content = documents[i].pageContent;
      
      if (this.options.redactSensitive) {
        content = this.redactContent(content);
      }

      securedDocuments.push({
        pageContent: content,
        metadata: {
          ...documents[i].metadata,
          _weave_scanned: false,
          _weave_redacted: this.options.redactSensitive || false,
        },
      });
    }

    return securedDocuments;
  }

  private redactContent(content: string): string {
    if (this.options.redactor) {
      return this.options.redactor(content);
    }

    let redacted = content;
    for (const { pattern, replacement } of PII_PATTERNS) {
      redacted = redacted.replace(pattern, replacement);
    }
    return redacted;
  }
}

/**
 * Factory function to wrap an existing retriever
 */
export function createSecureRetriever(
  retriever: BaseRetriever,
  options: SecureRetrieverOptions
): SecureRetriever {
  return new SecureRetriever(retriever, options);
}

// ============================================================================
// Document Filter
// ============================================================================

/**
 * Filters documents based on security scan results
 * Useful as a post-processing step
 */
export async function filterSecureDocuments(
  documents: Document[],
  options?: {
    scanner?: Scanner;
    minSeverity?: 'low' | 'medium' | 'high' | 'critical';
    categories?: string[];
    removeThreats?: boolean;
    redactSensitive?: boolean;
  }
): Promise<Document[]> {
  const scanner = options?.scanner || createScanner();
  const filtered: Document[] = [];

  for (const doc of documents) {
    let content = doc.pageContent;

    const scanResult = await scanner.scan(content, {
      minSeverity: options?.minSeverity,
      categories: options?.categories,
    });

    // Skip documents with threats if removeThreats is true
    if (options?.removeThreats && scanResult.threats.length > 0) {
      continue;
    }

    // Redact sensitive content
    if (options?.redactSensitive) {
      for (const { pattern, replacement } of PII_PATTERNS) {
        content = content.replace(pattern, replacement);
      }
    }

    filtered.push({
      pageContent: content,
      metadata: {
        ...doc.metadata,
        _weave_filtered: true,
        _weave_threats: scanResult.threatCount,
      },
    });
  }

  return filtered;
}
