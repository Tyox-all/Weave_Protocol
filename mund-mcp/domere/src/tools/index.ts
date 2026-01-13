/**
 * Dōmere - The Judge Protocol
 * MCP Tools
 */

import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import type { BlockchainNetwork, IDomereStorage } from '../types.js';
import { ThreadManager, IntentAnalyzer, DriftDetector } from '../thread/index.js';
import { LanguageAnalyzerService } from '../language/index.js';
import { AnchoringService } from '../anchoring/index.js';
import { createStorage } from '../storage/index.js';

// Tool definitions
export const DOMERE_TOOLS: Tool[] = [
  { name: 'domere_create_thread', description: 'Create thread from human intent', inputSchema: { type: 'object', properties: { origin_type: { type: 'string', enum: ['human', 'system', 'scheduled', 'delegated'] }, origin_identity: { type: 'string' }, intent: { type: 'string' }, constraints: { type: 'array', items: { type: 'string' } } }, required: ['origin_type', 'origin_identity', 'intent'] } },
  { name: 'domere_add_hop', description: 'Add hop to thread', inputSchema: { type: 'object', properties: { thread_id: { type: 'string' }, agent_id: { type: 'string' }, agent_type: { type: 'string' }, received_intent: { type: 'string' }, actions: { type: 'array', items: { type: 'object' } } }, required: ['thread_id', 'agent_id', 'agent_type', 'received_intent', 'actions'] } },
  { name: 'domere_get_thread', description: 'Get thread details', inputSchema: { type: 'object', properties: { thread_id: { type: 'string' } }, required: ['thread_id'] } },
  { name: 'domere_close_thread', description: 'Close thread', inputSchema: { type: 'object', properties: { thread_id: { type: 'string' }, outcome: { type: 'string', enum: ['success', 'failure', 'abandoned'] } }, required: ['thread_id', 'outcome'] } },
  { name: 'domere_verify_thread', description: 'Verify thread integrity', inputSchema: { type: 'object', properties: { thread_id: { type: 'string' } }, required: ['thread_id'] } },
  { name: 'domere_list_threads', description: 'List threads', inputSchema: { type: 'object', properties: { status: { type: 'string' }, limit: { type: 'number' } } } },
  { name: 'domere_detect_language', description: 'Detect language in content', inputSchema: { type: 'object', properties: { content: { type: 'string' } }, required: ['content'] } },
  { name: 'domere_analyze_content', description: 'Full semantic analysis', inputSchema: { type: 'object', properties: { content: { type: 'string' } }, required: ['content'] } },
  { name: 'domere_check_injection', description: 'Check for prompt injection', inputSchema: { type: 'object', properties: { content: { type: 'string' } }, required: ['content'] } },
  { name: 'domere_check_drift', description: 'Check intent drift', inputSchema: { type: 'object', properties: { original_intent: { type: 'string' }, current_intent: { type: 'string' }, constraints: { type: 'array', items: { type: 'string' } } }, required: ['original_intent', 'current_intent'] } },
  { name: 'domere_estimate_anchor_cost', description: 'Estimate blockchain cost', inputSchema: { type: 'object', properties: { network: { type: 'string', enum: ['solana', 'ethereum', 'solana-devnet', 'ethereum-sepolia'] } }, required: ['network'] } },
  { name: 'domere_prepare_anchor', description: 'Prepare anchor transaction', inputSchema: { type: 'object', properties: { thread_id: { type: 'string' }, network: { type: 'string' } }, required: ['thread_id', 'network'] } },
];

// Tool Handler
export class DomereToolHandler {
  private storage: IDomereStorage;
  private threadManager: ThreadManager;
  private languageAnalyzer: LanguageAnalyzerService;
  private anchoringService: AnchoringService;
  private intentAnalyzer: IntentAnalyzer;
  private driftDetector: DriftDetector;
  
  constructor(storage?: IDomereStorage) {
    this.storage = storage || createStorage('memory');
    this.threadManager = new ThreadManager(this.storage);
    this.languageAnalyzer = new LanguageAnalyzerService();
    this.anchoringService = new AnchoringService();
    this.intentAnalyzer = new IntentAnalyzer();
    this.driftDetector = new DriftDetector();
  }
  
  async handleTool(name: string, args: Record<string, unknown>): Promise<unknown> {
    switch (name) {
      case 'domere_create_thread': {
        const thread = await this.threadManager.createThread({
          origin: { type: args.origin_type as any, identity: args.origin_identity as string },
          intent: args.intent as string,
          constraints: args.constraints as string[],
        });
        return { thread_id: thread.id, intent_hash: thread.intent.hash, weave_signature: thread.weave_signature };
      }
      case 'domere_add_hop': {
        const hop = await this.threadManager.addHop({
          thread_id: args.thread_id as string,
          agent: { id: args.agent_id as string, type: args.agent_type as string },
          received_intent: args.received_intent as string,
          actions: (args.actions as any[]).map(a => ({ ...a, timestamp: new Date() })),
        });
        return { hop_id: hop.hop_id, intent_preserved: hop.intent_preserved, drift: hop.intent_drift?.verdict };
      }
      case 'domere_get_thread': {
        const thread = await this.threadManager.getThread(args.thread_id as string);
        return thread ? { id: thread.id, status: thread.status, hop_count: thread.hops.length, merkle_root: thread.merkle_root } : { error: 'Not found' };
      }
      case 'domere_close_thread': {
        const thread = await this.threadManager.closeThread(args.thread_id as string, args.outcome as any);
        return { thread_id: thread.id, status: thread.status, merkle_root: thread.merkle_root };
      }
      case 'domere_verify_thread':
        return this.threadManager.verifyThread(args.thread_id as string);
      case 'domere_list_threads': {
        const threads = await this.threadManager.listThreads({ status: args.status as any, limit: args.limit as number });
        return threads.map(t => ({ id: t.id, status: t.status, hops: t.hops.length }));
      }
      case 'domere_detect_language':
        return this.languageAnalyzer.detectLanguage(args.content as string);
      case 'domere_analyze_content':
        return this.languageAnalyzer.analyze(args.content as string);
      case 'domere_check_injection':
        return this.languageAnalyzer.checkInjection(args.content as string);
      case 'domere_check_drift':
        return this.driftDetector.analyze({
          original_intent: args.original_intent as string,
          previous_intent: args.original_intent as string,
          current_intent: args.current_intent as string,
          constraints: (args.constraints as string[]) || [],
          hop_number: 1,
        });
      case 'domere_estimate_anchor_cost':
        return this.anchoringService.estimateCost(args.network as BlockchainNetwork);
      case 'domere_prepare_anchor': {
        const thread = await this.threadManager.getThread(args.thread_id as string);
        if (!thread) return { error: 'Thread not found' };
        const request = this.anchoringService.prepareThreadAnchor(thread);
        request.network = args.network as BlockchainNetwork;
        return this.anchoringService.createAnchorTransaction(request);
      }
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  }
}
