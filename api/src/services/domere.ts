/**
 * Dōmere Service - backed by @weave_protocol/domere
 *
 * Threads, hops, verification, language/injection analysis, drift and anchor
 * preparation run through DomereToolHandler — the same code as the Dōmere MCP
 * tools. Intent analysis and compliance use Dōmere's IntentAnalyzer and one
 * shared ComplianceManager, so reports include earlier checkpoints.
 *
 * Compliance records are signed with WEAVE_SIGNING_KEY; without it, a random
 * key is used for this process.
 *
 * Submitting, verifying and polling on-chain anchors isn't implemented in
 * Dōmere yet, so those endpoints say so (501) instead of faking a chain.
 */

import { randomBytes } from 'node:crypto';
import { createStorage, DomereToolHandler, IntentAnalyzer, ComplianceManager } from '@weave_protocol/domere';

export class NotSupportedError extends Error {}

const ANCHORING_NOT_IMPLEMENTED =
  'On-chain anchor submission, verification and status are not implemented in Dōmere yet. ' +
  'Use /anchor/prepare to get the data to anchor and submit it with your own signer.';

export class DomereService {
  private tools = new DomereToolHandler(createStorage('memory'));
  private intents = new IntentAnalyzer();
  private compliance = new ComplianceManager(process.env.WEAVE_SIGNING_KEY || randomBytes(32).toString('hex'));

  private tool(name: string, args: Record<string, unknown>): Promise<any> {
    return this.tools.handleTool(name, args);
  }

  // ==========================================================================
  // Thread Management
  // ==========================================================================

  async createThread(config: {
    origin_type: string;
    origin_identity: string;
    intent: string;
    constraints?: string[];
    metadata?: any;
  }) {
    return this.tool('domere_create_thread', {
      origin_type: config.origin_type,
      origin_identity: config.origin_identity,
      intent: config.intent,
      constraints: config.constraints,
    });
  }

  async addHop(params: { thread_id: string; agent_id: string; agent_type: string; received_intent: string; actions: unknown[] }) {
    return this.tool('domere_add_hop', params);
  }

  async listThreads(filters?: { status?: string; origin_identity?: string; limit?: number }) {
    return this.tool('domere_list_threads', { status: filters?.status, limit: filters?.limit });
  }

  async getThread(id: string) {
    const thread = await this.tool('domere_get_thread', { thread_id: id });
    if (thread?.error) throw new Error(`Thread ${thread.error.toLowerCase()}: ${id}`);
    return thread;
  }

  async closeThread(id: string, outcome: string) {
    return this.tool('domere_close_thread', { thread_id: id, outcome });
  }

  async verifyThread(id: string) {
    return this.tool('domere_verify_thread', { thread_id: id });
  }

  // ==========================================================================
  // Intent & Drift
  // ==========================================================================

  async analyzeIntent(content: string) {
    return this.intents.analyze(content);
  }

  async checkDrift(originalIntent: string, currentIntent: string, constraints?: string[]) {
    return this.tool('domere_check_drift', { original_intent: originalIntent, current_intent: currentIntent, constraints });
  }

  async compareIntents(intent1: string, intent2: string) {
    return {
      similarity: this.intents.compareIntents(intent1, intent2),
      within_scope: this.intents.isWithinScope(intent1, intent2),
    };
  }

  // ==========================================================================
  // Language Analysis
  // ==========================================================================

  async detectLanguage(content: string) {
    return this.tool('domere_detect_language', { content });
  }

  async analyzeContent(content: string) {
    return this.tool('domere_analyze_content', { content });
  }

  async checkInjection(content: string) {
    return this.tool('domere_check_injection', { content });
  }

  // ==========================================================================
  // Anchoring
  // ==========================================================================

  async estimateAnchorCost(network: string) {
    return this.tool('domere_estimate_anchor_cost', { network });
  }

  async prepareAnchor(threadId: string, network: string) {
    return this.tool('domere_prepare_anchor', { thread_id: threadId, network });
  }

  async submitAnchor(_network: string, _signedTransaction: any): Promise<never> {
    throw new NotSupportedError(ANCHORING_NOT_IMPLEMENTED);
  }

  async verifyAnchor(_network: string, _threadId: string, _merkleRoot: string): Promise<never> {
    throw new NotSupportedError(ANCHORING_NOT_IMPLEMENTED);
  }

  async getAnchorStatus(_threadId: string): Promise<never> {
    throw new NotSupportedError(ANCHORING_NOT_IMPLEMENTED);
  }

  // ==========================================================================
  // Compliance
  // ==========================================================================

  async createCheckpoint(params: {
    thread_id: string; framework: string; control: string; event_type: string;
    event_description?: string; data_classification?: string; agent_id: string;
    user_id?: string; risk_level?: string; sign?: boolean;
  }): Promise<object> {
    return this.compliance.checkpoint({
      thread_id: params.thread_id, framework: params.framework as any,
      control: params.control, event_type: params.event_type as any,
      event_description: params.event_description || '',
      data_classification: (params.data_classification as any) || 'internal',
      agent_id: params.agent_id, user_id: params.user_id,
      risk_level: (params.risk_level as any) || 'low', sign: params.sign ?? true,
    });
  }

  async logCardholderDataAccess(params: {
    thread_id: string; agent_id: string; data_type: string; action: string;
    masked: boolean; encrypted: boolean; business_justification: string;
  }): Promise<object> {
    return this.compliance.logCardholderDataAccess({
      thread_id: params.thread_id, agent_id: params.agent_id,
      data_type: params.data_type as any, action: params.action as any,
      masked: params.masked, encrypted: params.encrypted,
      business_justification: params.business_justification,
    });
  }

  async logSecurityIncident(params: {
    thread_id: string; agent_id: string; incident_id: string; incident_type: string;
    severity: string; status: string; affected_assets: string[]; description?: string;
  }): Promise<object> {
    return this.compliance.logSecurityIncident({
      thread_id: params.thread_id, agent_id: params.agent_id,
      incident_id: params.incident_id, incident_type: params.incident_type as any,
      severity: params.severity as any, status: params.status as any,
      affected_assets: params.affected_assets, description: params.description || '',
    });
  }

  async logAssetEvent(params: {
    thread_id: string; agent_id: string; asset_id: string;
    asset_type: string; action: string; classification: string;
  }): Promise<object> {
    return this.compliance.logAssetEvent({
      thread_id: params.thread_id, agent_id: params.agent_id,
      asset_id: params.asset_id, asset_type: params.asset_type as any,
      action: params.action as any, classification: params.classification as any,
    });
  }

  async generateComplianceReport(params: { framework: string; period_start: Date; period_end: Date }): Promise<object> {
    return this.compliance.generateReport({
      framework: params.framework as any,
      period_start: params.period_start,
      period_end: params.period_end,
    });
  }

  // ==========================================================================
  // Function calling
  // ==========================================================================

  async call(fn: string, args: any) {
    switch (fn) {
      case 'domere_create_thread':
        return this.createThread(args);
      case 'domere_check_drift':
        return this.checkDrift(args.original_intent, args.current_intent, args.constraints);
      case 'domere_check_injection':
        return this.checkInjection(args.content);
      case 'domere_detect_language':
        return this.detectLanguage(args.content);
      case 'domere_analyze_intent':
        return this.analyzeIntent(args.content);
      default:
        throw new Error(`Unknown function: ${fn}`);
    }
  }
}
