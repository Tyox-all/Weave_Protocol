/**
 * Weave Security Callback for LangChain
 * @weave_protocol/langchain
 */

import { BaseCallbackHandler } from '@langchain/core/callbacks/base';
import type { Serialized } from '@langchain/core/load/serializable';
import type { LLMResult } from '@langchain/core/outputs';
import type { AgentAction, AgentFinish } from '@langchain/core/agents';
import type { ChainValues } from '@langchain/core/utils/types';
import type { Document } from '@langchain/core/documents';

import type {
  SecurityConfig,
  SecurityEvent,
  CallbackStats,
  ThreatMatch,
  WeaveIntegrationOptions,
} from './types.js';
import { DEFAULT_CONFIG } from './types.js';
import { createScanner, type Scanner } from './scanner.js';

// ============================================================================
// Weave Security Callback Handler
// ============================================================================

export class WeaveSecurityCallback extends BaseCallbackHandler {
  name = 'WeaveSecurityCallback';
  
  private config: SecurityConfig;
  private scanner: Scanner;
  private stats: CallbackStats;
  private verbose: boolean;

  constructor(
    config?: Partial<SecurityConfig>,
    options?: WeaveIntegrationOptions
  ) {
    super();
    
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.verbose = options?.verbose ?? false;
    
    // Initialize scanner
    this.scanner = createScanner({
      endpoint: options?.mundEndpoint,
      apiKey: options?.mundApiKey,
    });

    // Initialize stats
    this.stats = {
      totalScans: 0,
      threatsDetected: 0,
      actionsBlocked: 0,
      scansBySource: {},
      threatsByCategory: {},
      threatsBySeverity: {},
      averageScanTimeMs: 0,
      startTime: new Date(),
    };
  }

  // ==========================================================================
  // Stats & Utilities
  // ==========================================================================

  getStats(): CallbackStats {
    return { ...this.stats };
  }

  resetStats(): void {
    this.stats = {
      totalScans: 0,
      threatsDetected: 0,
      actionsBlocked: 0,
      scansBySource: {},
      threatsByCategory: {},
      threatsBySeverity: {},
      averageScanTimeMs: 0,
      startTime: new Date(),
    };
  }

  private updateStats(source: string, threats: ThreatMatch[], scanTimeMs: number, blocked: boolean): void {
    this.stats.totalScans++;
    this.stats.scansBySource[source] = (this.stats.scansBySource[source] || 0) + 1;
    
    if (threats.length > 0) {
      this.stats.threatsDetected += threats.length;
      for (const t of threats) {
        this.stats.threatsByCategory[t.category] = (this.stats.threatsByCategory[t.category] || 0) + 1;
        this.stats.threatsBySeverity[t.severity] = (this.stats.threatsBySeverity[t.severity] || 0) + 1;
      }
    }
    
    if (blocked) {
      this.stats.actionsBlocked++;
    }
    
    // Update average scan time
    this.stats.averageScanTimeMs = 
      (this.stats.averageScanTimeMs * (this.stats.totalScans - 1) + scanTimeMs) / this.stats.totalScans;
  }

  private log(message: string, data?: any): void {
    if (this.verbose) {
      console.log(`[WeaveSecurityCallback] ${message}`, data || '');
    }
  }

  private async emitEvent(event: SecurityEvent): Promise<void> {
    if (this.config.onSecurityEvent) {
      await this.config.onSecurityEvent(event);
    }
  }

  private shouldBlock(threats: ThreatMatch[]): boolean {
    if (this.config.action !== 'block') return false;
    if (threats.length === 0) return false;

    const severityOrder = ['low', 'medium', 'high', 'critical'];
    const minIndex = severityOrder.indexOf(this.config.minSeverity);
    
    return threats.some(t => severityOrder.indexOf(t.severity) >= minIndex);
  }

  private async scanContent(
    content: string,
    source: 'llm' | 'chain' | 'tool' | 'retriever' | 'agent',
    direction: 'input' | 'output',
    sourceName?: string
  ): Promise<{ threats: ThreatMatch[]; blocked: boolean }> {
    // Check if we should scan this direction
    if (this.config.scanTarget === 'input' && direction === 'output') {
      return { threats: [], blocked: false };
    }
    if (this.config.scanTarget === 'output' && direction === 'input') {
      return { threats: [], blocked: false };
    }

    const result = await this.scanner.scan(content, {
      categories: this.config.categories,
      minSeverity: this.config.minSeverity,
    });

    const blocked = this.shouldBlock(result.threats);
    
    // Update stats
    this.updateStats(source, result.threats, result.scanDurationMs, blocked);

    // Emit event
    const event: SecurityEvent = {
      type: result.threats.length > 0 ? 'threat_detected' : 'scan_completed',
      timestamp: new Date(),
      source,
      sourceName,
      direction,
      content: content.substring(0, 200),
      contentLength: content.length,
      threats: result.threats,
      actionTaken: blocked ? 'block' : this.config.action,
      blocked,
      scanDurationMs: result.scanDurationMs,
    };

    await this.emitEvent(event);

    // Log if verbose or threats found
    if (result.threats.length > 0) {
      this.log(`Threats detected in ${source} ${direction}:`, {
        count: result.threats.length,
        highest: result.highestSeverity,
        blocked,
      });
    }

    return { threats: result.threats, blocked };
  }

  // ==========================================================================
  // LLM Callbacks
  // ==========================================================================

  async handleLLMStart(
    llm: Serialized,
    prompts: string[],
    runId: string,
    parentRunId?: string,
    extraParams?: Record<string, unknown>,
    tags?: string[],
    metadata?: Record<string, unknown>,
    name?: string
  ): Promise<void> {
    this.log('LLM Start', { name: llm.id, promptCount: prompts.length });

    for (const prompt of prompts) {
      const { blocked } = await this.scanContent(prompt, 'llm', 'input', name);
      
      if (blocked) {
        throw new Error(
          `[WeaveSecurityCallback] Blocked: Threat detected in LLM input. ` +
          `Run ID: ${runId}`
        );
      }
    }
  }

  async handleLLMEnd(
    output: LLMResult,
    runId: string,
    parentRunId?: string,
    tags?: string[]
  ): Promise<void> {
    this.log('LLM End', { runId });

    for (const generation of output.generations) {
      for (const gen of generation) {
        const { blocked } = await this.scanContent(gen.text, 'llm', 'output');
        
        if (blocked) {
          throw new Error(
            `[WeaveSecurityCallback] Blocked: Threat detected in LLM output. ` +
            `Run ID: ${runId}`
          );
        }
      }
    }
  }

  async handleLLMError(
    err: Error,
    runId: string,
    parentRunId?: string,
    tags?: string[]
  ): Promise<void> {
    this.log('LLM Error', { runId, error: err.message });
  }

  // ==========================================================================
  // Chain Callbacks
  // ==========================================================================

  async handleChainStart(
    chain: Serialized,
    inputs: ChainValues,
    runId: string,
    parentRunId?: string,
    tags?: string[],
    metadata?: Record<string, unknown>,
    runType?: string,
    name?: string
  ): Promise<void> {
    this.log('Chain Start', { name: chain.id });

    // Scan all string inputs
    for (const [key, value] of Object.entries(inputs)) {
      if (typeof value === 'string') {
        const { blocked } = await this.scanContent(value, 'chain', 'input', name);
        
        if (blocked) {
          throw new Error(
            `[WeaveSecurityCallback] Blocked: Threat detected in chain input "${key}". ` +
            `Run ID: ${runId}`
          );
        }
      }
    }
  }

  async handleChainEnd(
    outputs: ChainValues,
    runId: string,
    parentRunId?: string,
    tags?: string[]
  ): Promise<void> {
    this.log('Chain End', { runId });

    // Scan all string outputs
    for (const [key, value] of Object.entries(outputs)) {
      if (typeof value === 'string') {
        const { blocked } = await this.scanContent(value, 'chain', 'output');
        
        if (blocked) {
          throw new Error(
            `[WeaveSecurityCallback] Blocked: Threat detected in chain output "${key}". ` +
            `Run ID: ${runId}`
          );
        }
      }
    }
  }

  async handleChainError(
    err: Error,
    runId: string,
    parentRunId?: string,
    tags?: string[]
  ): Promise<void> {
    this.log('Chain Error', { runId, error: err.message });
  }

  // ==========================================================================
  // Tool Callbacks
  // ==========================================================================

  async handleToolStart(
    tool: Serialized,
    input: string,
    runId: string,
    parentRunId?: string,
    tags?: string[],
    metadata?: Record<string, unknown>,
    name?: string
  ): Promise<void> {
    if (!this.config.scanTools) return;

    this.log('Tool Start', { name: tool.id, inputLength: input.length });

    const { blocked } = await this.scanContent(input, 'tool', 'input', name);
    
    if (blocked) {
      throw new Error(
        `[WeaveSecurityCallback] Blocked: Threat detected in tool input. ` +
        `Tool: ${name || tool.id}. Run ID: ${runId}`
      );
    }
  }

  async handleToolEnd(
    output: string,
    runId: string,
    parentRunId?: string,
    tags?: string[]
  ): Promise<void> {
    if (!this.config.scanTools) return;

    this.log('Tool End', { runId, outputLength: output.length });

    const { blocked } = await this.scanContent(output, 'tool', 'output');
    
    if (blocked) {
      throw new Error(
        `[WeaveSecurityCallback] Blocked: Threat detected in tool output. ` +
        `Run ID: ${runId}`
      );
    }
  }

  async handleToolError(
    err: Error,
    runId: string,
    parentRunId?: string,
    tags?: string[]
  ): Promise<void> {
    this.log('Tool Error', { runId, error: err.message });
  }

  // ==========================================================================
  // Agent Callbacks
  // ==========================================================================

  async handleAgentAction(
    action: AgentAction,
    runId: string,
    parentRunId?: string,
    tags?: string[]
  ): Promise<void> {
    this.log('Agent Action', { tool: action.tool });

    const input = typeof action.toolInput === 'string' 
      ? action.toolInput 
      : JSON.stringify(action.toolInput);

    const { blocked } = await this.scanContent(input, 'agent', 'input', action.tool);
    
    if (blocked) {
      throw new Error(
        `[WeaveSecurityCallback] Blocked: Threat detected in agent action. ` +
        `Tool: ${action.tool}. Run ID: ${runId}`
      );
    }
  }

  async handleAgentEnd(
    action: AgentFinish,
    runId: string,
    parentRunId?: string,
    tags?: string[]
  ): Promise<void> {
    this.log('Agent End', { runId });

    const output = typeof action.returnValues === 'string'
      ? action.returnValues
      : JSON.stringify(action.returnValues);

    const { blocked } = await this.scanContent(output, 'agent', 'output');
    
    if (blocked) {
      throw new Error(
        `[WeaveSecurityCallback] Blocked: Threat detected in agent output. ` +
        `Run ID: ${runId}`
      );
    }
  }

  // ==========================================================================
  // Retriever Callbacks
  // ==========================================================================

  async handleRetrieverStart(
    retriever: Serialized,
    query: string,
    runId: string,
    parentRunId?: string,
    tags?: string[],
    metadata?: Record<string, unknown>,
    name?: string
  ): Promise<void> {
    if (!this.config.scanRetrievers) return;

    this.log('Retriever Start', { name: retriever.id, queryLength: query.length });

    const { blocked } = await this.scanContent(query, 'retriever', 'input', name);
    
    if (blocked) {
      throw new Error(
        `[WeaveSecurityCallback] Blocked: Threat detected in retriever query. ` +
        `Run ID: ${runId}`
      );
    }
  }

  async handleRetrieverEnd(
    documents: Document[],
    runId: string,
    parentRunId?: string,
    tags?: string[]
  ): Promise<void> {
    if (!this.config.scanRetrievers) return;

    this.log('Retriever End', { runId, docCount: documents.length });

    for (const doc of documents) {
      const { blocked } = await this.scanContent(doc.pageContent, 'retriever', 'output');
      
      if (blocked) {
        throw new Error(
          `[WeaveSecurityCallback] Blocked: Threat detected in retrieved document. ` +
          `Run ID: ${runId}`
        );
      }
    }
  }

  async handleRetrieverError(
    err: Error,
    runId: string,
    parentRunId?: string,
    tags?: string[]
  ): Promise<void> {
    this.log('Retriever Error', { runId, error: err.message });
  }
}
