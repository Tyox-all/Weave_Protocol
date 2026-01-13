/**
 * Dōmere - The Judge Protocol
 * Thread Manager
 */

import * as crypto from 'crypto';
import type {
  Thread,
  ThreadOrigin,
  ThreadIntent,
  ThreadHop,
  ThreadStatus,
  IDomereStorage,
  AgentInfo,
  HopAction,
  DriftAnalysis,
  LanguageAnalysis,
  SecurityScanResult,
} from '../types.js';
import { ThreadError } from '../types.js';
import { LanguageAnalyzerService } from '../language/index.js';
import { IntentAnalyzer } from './intent.js';
import { DriftDetector } from './drift.js';
import { WeaveSignature } from './weave.js';

// ============================================================================
// Thread Manager
// ============================================================================

export class ThreadManager {
  private storage: IDomereStorage;
  private languageAnalyzer: LanguageAnalyzerService;
  private intentAnalyzer: IntentAnalyzer;
  private driftDetector: DriftDetector;
  private weaveSignature: WeaveSignature;
  
  constructor(storage: IDomereStorage) {
    this.storage = storage;
    this.languageAnalyzer = new LanguageAnalyzerService();
    this.intentAnalyzer = new IntentAnalyzer();
    this.driftDetector = new DriftDetector();
    this.weaveSignature = new WeaveSignature();
  }
  
  /**
   * Create a new thread
   */
  async createThread(config: {
    origin: Omit<ThreadOrigin, 'timestamp'>;
    intent: string;
    constraints?: string[];
    metadata?: Record<string, unknown>;
  }): Promise<Thread> {
    const now = new Date();
    const threadId = this.generateThreadId();
    
    // Analyze the intent
    const intentAnalysis = this.intentAnalyzer.analyze(config.intent);
    const languageAnalysis = this.languageAnalyzer.analyze(config.intent);
    
    const intent: ThreadIntent = {
      raw: config.intent,
      hash: this.hashContent(config.intent),
      normalized: intentAnalysis.normalized,
      classification: languageAnalysis.semantic?.intent_classification || 'unknown',
      constraints: config.constraints || [],
      entities: languageAnalysis.semantic?.entities || [],
      actions_implied: languageAnalysis.semantic?.actions_implied || [],
      language_analysis: languageAnalysis,
    };
    
    const origin: ThreadOrigin = {
      ...config.origin,
      timestamp: now,
    };
    
    // Create initial weave signature
    const initialSignature = this.weaveSignature.createInitial({
      threadId,
      origin,
      intent,
    });
    
    const thread: Thread = {
      id: threadId,
      origin,
      intent,
      hops: [],
      weave_signature: initialSignature,
      status: 'active',
      created_at: now,
      updated_at: now,
      metadata: config.metadata || {},
    };
    
    await this.storage.saveThread(thread);
    
    return thread;
  }
  
  /**
   * Add a hop to a thread
   */
  async addHop(config: {
    thread_id: string;
    agent: AgentInfo;
    received_intent: string;
    actions: HopAction[];
    security_scan?: SecurityScanResult;
    sandbox_result?: { sandbox_id: string; result_id: string; status: string; summary: string };
  }): Promise<ThreadHop> {
    const thread = await this.storage.getThread(config.thread_id);
    if (!thread) {
      throw new ThreadError('Thread not found', { thread_id: config.thread_id });
    }
    
    if (thread.status !== 'active') {
      throw new ThreadError('Thread is not active', { 
        thread_id: config.thread_id, 
        status: thread.status 
      });
    }
    
    const now = new Date();
    const sequence = thread.hops.length + 1;
    const hopId = this.generateHopId(config.thread_id, sequence);
    
    // Analyze received intent
    const languageAnalysis = this.languageAnalyzer.analyze(config.received_intent);
    
    // Calculate previous intent for drift detection
    const previousIntent = sequence === 1 
      ? thread.intent.raw 
      : thread.hops[thread.hops.length - 1].received_intent;
    
    // Detect drift
    const driftAnalysis = this.driftDetector.analyze({
      original_intent: thread.intent.raw,
      previous_intent: previousIntent,
      current_intent: config.received_intent,
      constraints: thread.intent.constraints,
      hop_number: sequence,
    });
    
    // Calculate cumulative hash
    const previousHash = sequence === 1 
      ? thread.weave_signature 
      : thread.hops[thread.hops.length - 1].cumulative_hash;
    
    const hopData = {
      hopId,
      agent: config.agent,
      received_intent: config.received_intent,
      actions: config.actions,
      timestamp: now,
    };
    
    const hopSignature = this.weaveSignature.signHop(hopData, previousHash);
    const cumulativeHash = this.weaveSignature.computeCumulativeHash(previousHash, hopSignature);
    
    const hop: ThreadHop = {
      sequence,
      hop_id: hopId,
      agent: config.agent,
      received_intent: config.received_intent,
      received_intent_hash: this.hashContent(config.received_intent),
      intent_preserved: driftAnalysis.verdict === 'aligned' || driftAnalysis.verdict === 'minor_drift',
      intent_drift: driftAnalysis,
      actions: config.actions,
      language_analysis: languageAnalysis,
      security_scan: config.security_scan,
      sandbox_result: config.sandbox_result ? {
        sandbox_id: config.sandbox_result.sandbox_id,
        result_id: config.sandbox_result.result_id,
        status: config.sandbox_result.status as 'safe' | 'review' | 'blocked',
        summary: config.sandbox_result.summary,
      } : undefined,
      hop_signature: hopSignature,
      cumulative_hash: cumulativeHash,
      started_at: now,
      completed_at: now,
      duration_ms: 0,
      status: 'success',
    };
    
    // Update thread
    thread.hops.push(hop);
    thread.weave_signature = cumulativeHash;
    thread.updated_at = now;
    
    // Check for violations
    if (driftAnalysis.verdict === 'violated') {
      thread.status = 'violated';
    }
    
    // Update merkle root
    thread.merkle_root = this.computeMerkleRoot(thread.hops);
    
    await this.storage.updateThread(thread);
    await this.storage.addHop(config.thread_id, hop);
    
    return hop;
  }
  
  /**
   * Close a thread
   */
  async closeThread(threadId: string, outcome: 'success' | 'failure' | 'abandoned'): Promise<Thread> {
    const thread = await this.storage.getThread(threadId);
    if (!thread) {
      throw new ThreadError('Thread not found', { thread_id: threadId });
    }
    
    const now = new Date();
    
    thread.status = outcome === 'success' ? 'complete' : 
                    outcome === 'failure' ? 'violated' : 'abandoned';
    thread.closed_at = now;
    thread.updated_at = now;
    
    // Final merkle root
    thread.merkle_root = this.computeMerkleRoot(thread.hops);
    
    await this.storage.updateThread(thread);
    
    return thread;
  }
  
  /**
   * Get a thread
   */
  async getThread(threadId: string): Promise<Thread | null> {
    return this.storage.getThread(threadId);
  }
  
  /**
   * List threads
   */
  async listThreads(filters?: {
    status?: ThreadStatus;
    origin_type?: ThreadOrigin['type'];
    origin_identity?: string;
    since?: Date;
    until?: Date;
    limit?: number;
  }): Promise<Thread[]> {
    return this.storage.listThreads(filters);
  }
  
  /**
   * Verify thread integrity
   */
  async verifyThread(threadId: string): Promise<{
    valid: boolean;
    errors: string[];
    verified_hops: number;
    total_hops: number;
  }> {
    const thread = await this.storage.getThread(threadId);
    if (!thread) {
      return { valid: false, errors: ['Thread not found'], verified_hops: 0, total_hops: 0 };
    }
    
    const errors: string[] = [];
    let verifiedHops = 0;
    
    // Verify initial signature
    const expectedInitial = this.weaveSignature.createInitial({
      threadId: thread.id,
      origin: thread.origin,
      intent: thread.intent,
    });
    
    let previousHash = expectedInitial;
    
    // Verify each hop
    for (let i = 0; i < thread.hops.length; i++) {
      const hop = thread.hops[i];
      
      // Verify sequence
      if (hop.sequence !== i + 1) {
        errors.push(`Hop ${i + 1} has incorrect sequence: ${hop.sequence}`);
      }
      
      // Verify hop signature
      const hopData = {
        hopId: hop.hop_id,
        agent: hop.agent,
        received_intent: hop.received_intent,
        actions: hop.actions,
        timestamp: hop.started_at,
      };
      
      const expectedSignature = this.weaveSignature.signHop(hopData, previousHash);
      if (hop.hop_signature !== expectedSignature) {
        errors.push(`Hop ${i + 1} has invalid signature`);
      } else {
        verifiedHops++;
      }
      
      // Verify cumulative hash
      const expectedCumulative = this.weaveSignature.computeCumulativeHash(previousHash, hop.hop_signature);
      if (hop.cumulative_hash !== expectedCumulative) {
        errors.push(`Hop ${i + 1} has invalid cumulative hash`);
      }
      
      previousHash = hop.cumulative_hash;
    }
    
    // Verify final weave signature
    if (thread.hops.length > 0) {
      const lastHop = thread.hops[thread.hops.length - 1];
      if (thread.weave_signature !== lastHop.cumulative_hash) {
        errors.push('Thread weave signature does not match last hop');
      }
    }
    
    // Verify merkle root
    const expectedMerkle = this.computeMerkleRoot(thread.hops);
    if (thread.merkle_root && thread.merkle_root !== expectedMerkle) {
      errors.push('Thread merkle root is invalid');
    }
    
    return {
      valid: errors.length === 0,
      errors,
      verified_hops: verifiedHops,
      total_hops: thread.hops.length,
    };
  }
  
  /**
   * Get thread summary
   */
  async getThreadSummary(threadId: string): Promise<{
    id: string;
    status: ThreadStatus;
    origin: string;
    intent_summary: string;
    hop_count: number;
    total_drift: number;
    has_violations: boolean;
    duration_ms: number;
    merkle_root?: string;
  } | null> {
    const thread = await this.storage.getThread(threadId);
    if (!thread) return null;
    
    const totalDrift = thread.hops.reduce(
      (sum, hop) => sum + (hop.intent_drift?.hop_drift || 0), 
      0
    );
    
    const hasViolations = thread.hops.some(
      hop => hop.intent_drift?.verdict === 'violated' || hop.status !== 'success'
    );
    
    const durationMs = thread.closed_at 
      ? thread.closed_at.getTime() - thread.created_at.getTime()
      : Date.now() - thread.created_at.getTime();
    
    return {
      id: thread.id,
      status: thread.status,
      origin: `${thread.origin.type}:${thread.origin.identity}`,
      intent_summary: thread.intent.raw.slice(0, 100),
      hop_count: thread.hops.length,
      total_drift: totalDrift,
      has_violations: hasViolations,
      duration_ms: durationMs,
      merkle_root: thread.merkle_root,
    };
  }
  
  // ============================================================================
  // Private Methods
  // ============================================================================
  
  private generateThreadId(): string {
    return `thr_${crypto.randomBytes(12).toString('hex')}`;
  }
  
  private generateHopId(threadId: string, sequence: number): string {
    return `hop_${crypto.randomBytes(8).toString('hex')}_${sequence}`;
  }
  
  private hashContent(content: string): string {
    return crypto.createHash('sha256').update(content).digest('hex');
  }
  
  private computeMerkleRoot(hops: ThreadHop[]): string {
    if (hops.length === 0) {
      return this.hashContent('empty');
    }
    
    // Get leaf hashes
    let hashes = hops.map(hop => hop.hop_signature);
    
    // Build tree
    while (hashes.length > 1) {
      const newLevel: string[] = [];
      for (let i = 0; i < hashes.length; i += 2) {
        if (i + 1 < hashes.length) {
          newLevel.push(this.hashContent(hashes[i] + hashes[i + 1]));
        } else {
          newLevel.push(hashes[i]);  // Odd one out
        }
      }
      hashes = newLevel;
    }
    
    return hashes[0];
  }
}
