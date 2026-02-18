/**
 * Dōmere Service - Wraps @weave_protocol/domere
 */

import crypto from 'crypto';

export class DomereService {
  private threads: Map<string, any> = new Map();
  private signingKey: string = process.env.WEAVE_SIGNING_KEY || "weave-default-signing-key";
  private anchors: Map<string, any> = new Map();
  
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
    const id = `thr_${crypto.randomUUID()}`;
    const intentHash = crypto.createHash('sha256').update(config.intent).digest('hex');
    const weaveSignature = crypto.createHash('sha256')
      .update(`${config.origin_type}:${config.origin_identity}:${intentHash}`)
      .digest('hex');
    
    const thread = {
      id,
      status: 'active',
      origin: {
        type: config.origin_type,
        identity: config.origin_identity
      },
      intent: {
        raw: config.intent,
        hash: intentHash,
        classification: this.classifyIntent(config.intent),
        constraints: config.constraints || []
      },
      hops: [],
      weave_signature: weaveSignature,
      merkle_root: null,
      metadata: config.metadata,
      created_at: new Date().toISOString(),
      closed_at: null
    };
    
    this.threads.set(id, thread);
    
    return {
      thread_id: id,
      intent_hash: intentHash,
      intent_classification: thread.intent.classification,
      weave_signature: weaveSignature,
      created_at: thread.created_at
    };
  }
  
  async listThreads(filters?: { status?: string; origin_identity?: string; limit?: number }) {
    let threads = Array.from(this.threads.values());
    
    if (filters?.status) {
      threads = threads.filter(t => t.status === filters.status);
    }
    if (filters?.origin_identity) {
      threads = threads.filter(t => t.origin.identity === filters.origin_identity);
    }
    if (filters?.limit) {
      threads = threads.slice(0, filters.limit);
    }
    
    return threads.map(t => ({
      id: t.id,
      status: t.status,
      origin: `${t.origin.type}:${t.origin.identity}`,
      intent_summary: t.intent.raw.substring(0, 50),
      hop_count: t.hops.length,
      created_at: t.created_at
    }));
  }
  
  async getThread(id: string) {
    const thread = this.threads.get(id);
    if (!thread) throw new Error(`Thread not found: ${id}`);
    return thread;
  }
  
  async addHop(config: {
    thread_id: string;
    agent_id: string;
    agent_type: string;
    received_intent: string;
    actions: any[];
  }) {
    const thread = this.threads.get(config.thread_id);
    if (!thread) throw new Error(`Thread not found: ${config.thread_id}`);
    
    const hopNumber = thread.hops.length + 1;
    const previousHash = thread.hops.length > 0 
      ? thread.hops[thread.hops.length - 1].cumulative_hash 
      : thread.weave_signature;
    
    // Calculate drift
    const drift = this.calculateDrift(thread.intent.raw, config.received_intent, thread.intent.constraints);
    
    // Cumulative hash
    const cumulativeHash = crypto.createHash('sha256')
      .update(`${previousHash}:${config.agent_id}:${config.received_intent}`)
      .digest('hex');
    
    const hop = {
      hop_id: `hop_${crypto.randomUUID()}`,
      sequence: hopNumber,
      agent: {
        id: config.agent_id,
        type: config.agent_type
      },
      received_intent: config.received_intent,
      actions: config.actions.map(a => ({ ...a, timestamp: new Date().toISOString() })),
      intent_preserved: drift.verdict === 'aligned' || drift.verdict === 'minor_drift',
      intent_drift: drift,
      cumulative_hash: cumulativeHash,
      timestamp: new Date().toISOString()
    };
    
    thread.hops.push(hop);
    
    // Update thread status if drift is severe
    if (drift.verdict === 'violated') {
      thread.status = 'violated';
    }
    
    // Update merkle root
    thread.merkle_root = this.computeMerkleRoot(thread.hops);
    
    return hop;
  }
  
  async closeThread(id: string, outcome: string) {
    const thread = this.threads.get(id);
    if (!thread) throw new Error(`Thread not found: ${id}`);
    
    thread.status = outcome === 'success' ? 'complete' : outcome;
    thread.closed_at = new Date().toISOString();
    thread.merkle_root = this.computeMerkleRoot(thread.hops);
    
    return {
      thread_id: id,
      status: thread.status,
      closed_at: thread.closed_at,
      merkle_root: thread.merkle_root
    };
  }
  
  async verifyThread(id: string) {
    const thread = this.threads.get(id);
    if (!thread) throw new Error(`Thread not found: ${id}`);
    
    // Verify chain integrity
    let previousHash = thread.weave_signature;
    let valid = true;
    const issues: string[] = [];
    
    for (const hop of thread.hops) {
      const expectedHash = crypto.createHash('sha256')
        .update(`${previousHash}:${hop.agent.id}:${hop.received_intent}`)
        .digest('hex');
      
      if (expectedHash !== hop.cumulative_hash) {
        valid = false;
        issues.push(`Hop ${hop.sequence}: hash mismatch`);
      }
      
      previousHash = hop.cumulative_hash;
    }
    
    return {
      thread_id: id,
      valid,
      issues,
      hop_count: thread.hops.length,
      merkle_root: thread.merkle_root
    };
  }
  
  // ==========================================================================
  // Intent & Drift
  // ==========================================================================
  
  async analyzeIntent(content: string) {
    return {
      raw: content,
      classification: this.classifyIntent(content),
      entities: this.extractEntities(content),
      complexity: this.assessComplexity(content),
      scope: this.assessScope(content)
    };
  }
  
  async checkDrift(originalIntent: string, currentIntent: string, constraints?: string[]) {
    return this.calculateDrift(originalIntent, currentIntent, constraints || []);
  }
  
  async compareIntents(intent1: string, intent2: string) {
    const similarity = this.calculateSimilarity(intent1, intent2);
    const withinScope = similarity > 0.7;
    return { similarity, within_scope: withinScope };
  }
  
  // ==========================================================================
  // Language Analysis
  // ==========================================================================
  
  async detectLanguage(content: string) {
    // Simple detection based on patterns
    const languages: { lang: string; confidence: number }[] = [];
    
    // Check for code
    if (/function\s+\w+\s*\(|const\s+\w+\s*=|let\s+\w+\s*=/.test(content)) {
      languages.push({ lang: 'javascript', confidence: 0.8 });
    }
    if (/def\s+\w+\s*\(|import\s+\w+|from\s+\w+\s+import/.test(content)) {
      languages.push({ lang: 'python', confidence: 0.8 });
    }
    if (/SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+.+\s+SET/i.test(content)) {
      languages.push({ lang: 'sql', confidence: 0.9 });
    }
    
    // Default to natural language
    if (languages.length === 0) {
      languages.push({ lang: 'english', confidence: 0.7 });
    }
    
    return {
      primary: languages[0],
      detected: languages,
      contains_code: languages.some(l => ['javascript', 'python', 'sql'].includes(l.lang))
    };
  }
  
  async analyzeContent(content: string) {
    return {
      language: await this.detectLanguage(content),
      intent: await this.analyzeIntent(content),
      entities: this.extractEntities(content),
      sentiment: this.analyzeSentiment(content)
    };
  }
  
  async checkInjection(content: string) {
    const patterns = [
      { name: 'instruction_override', pattern: /ignore (previous|all|above) instructions/gi, severity: 'high' },
      { name: 'role_manipulation', pattern: /you are (now|actually) /gi, severity: 'high' },
      { name: 'jailbreak', pattern: /(DAN|jailbreak|bypass safety)/gi, severity: 'critical' },
      { name: 'hidden_base64', pattern: /[A-Za-z0-9+/]{50,}={0,2}/g, severity: 'medium' }
    ];
    
    const detections: any[] = [];
    let riskScore = 0;
    
    for (const { name, pattern, severity } of patterns) {
      const matches = content.match(pattern);
      if (matches) {
        detections.push({ name, severity, matches: matches.length });
        riskScore += severity === 'critical' ? 0.4 : severity === 'high' ? 0.2 : 0.1;
      }
    }
    
    return {
      is_injection: detections.length > 0,
      risk_score: Math.min(1, riskScore),
      verdict: riskScore > 0.5 ? 'high' : riskScore > 0.2 ? 'medium' : riskScore > 0 ? 'low' : 'none',
      detections
    };
  }
  
  // ==========================================================================
  // Blockchain Anchoring
  // ==========================================================================
  
  async estimateAnchorCost(network: string) {
    const costs: Record<string, any> = {
      solana: {
        network_fee_lamports: 5000,
        protocol_fee_lamports: 100000,
        total_lamports: 105000,
        estimated_usd: 0.02
      },
      ethereum: {
        gas_limit: 80000,
        protocol_fee_bps: 500,
        estimated_usd_range: { min: 2, max: 10 }
      }
    };
    
    return costs[network] || { error: 'Unknown network' };
  }
  
  async prepareAnchor(threadId: string, network: string) {
    const thread = this.threads.get(threadId);
    if (!thread) throw new Error(`Thread not found: ${threadId}`);
    
    const merkleRoot = thread.merkle_root || this.computeMerkleRoot(thread.hops);
    
    // In production, this would create actual unsigned transactions
    return {
      thread_id: threadId,
      network,
      merkle_root: merkleRoot,
      unsigned_transaction: {
        type: network === 'solana' ? 'solana_transaction' : 'ethereum_transaction',
        data: {
          thread_id: threadId,
          merkle_root: merkleRoot,
          timestamp: Date.now()
        }
      },
      instructions: `Sign this transaction with your ${network} wallet`
    };
  }
  
  async submitAnchor(network: string, signedTransaction: any) {
    // In production, this would submit to actual blockchain
    const txId = `tx_${crypto.randomUUID()}`;
    
    this.anchors.set(txId, {
      network,
      transaction: signedTransaction,
      submitted_at: new Date().toISOString(),
      status: 'confirmed'
    });
    
    return {
      success: true,
      transaction_id: txId,
      network,
      status: 'confirmed',
      explorer_url: network === 'solana' 
        ? `https://solscan.io/tx/${txId}`
        : `https://etherscan.io/tx/${txId}`
    };
  }
  
  async verifyAnchor(network: string, threadId: string, merkleRoot: string) {
    // In production, this would verify on actual blockchain
    return {
      verified: true,
      network,
      thread_id: threadId,
      merkle_root: merkleRoot,
      verified_at: new Date().toISOString()
    };
  }
  
  async getAnchorStatus(threadId: string) {
    const anchor = Array.from(this.anchors.values()).find(
      a => a.transaction?.data?.thread_id === threadId
    );
    
    if (!anchor) return { anchored: false };
    
    return {
      anchored: true,
      network: anchor.network,
      status: anchor.status,
      submitted_at: anchor.submitted_at
    };
  }
  
  // ==========================================================================
  // Function Call Interface
  // ==========================================================================
  
  async call(fn: string, args: any) {
    switch (fn) {
      case 'domere_create_thread':
        return this.createThread(args);
      case 'domere_add_hop':
        return this.addHop(args);
      case 'domere_check_drift':
        return this.checkDrift(args.original_intent, args.current_intent, args.constraints);
      case 'domere_anchor':
        return this.prepareAnchor(args.thread_id, args.network);
      default:
        throw new Error(`Unknown function: ${fn}`);
    }
  }
  
  // ==========================================================================
  // Helpers
  // ==========================================================================
  
  private classifyIntent(intent: string): string {
    const lower = intent.toLowerCase();
    if (/get|fetch|retrieve|find|search|look up|show/.test(lower)) return 'query';
    if (/create|add|insert|make|generate|write/.test(lower)) return 'mutation';
    if (/delete|remove|drop|clear/.test(lower)) return 'deletion';
    if (/run|execute|perform|do/.test(lower)) return 'execution';
    if (/send|email|notify|message/.test(lower)) return 'communication';
    if (/analyze|review|check|examine/.test(lower)) return 'analysis';
    return 'general';
  }
  
  private extractEntities(content: string): any[] {
    const entities: any[] = [];
    
    // Extract quoted strings
    const quotes = content.match(/"[^"]+"|'[^']+'/g);
    if (quotes) entities.push(...quotes.map(q => ({ type: 'quoted', value: q })));
    
    // Extract numbers
    const numbers = content.match(/\b\d+(\.\d+)?\b/g);
    if (numbers) entities.push(...numbers.map(n => ({ type: 'number', value: n })));
    
    return entities;
  }
  
  private assessComplexity(content: string): string {
    const words = content.split(/\s+/).length;
    if (words > 50) return 'complex';
    if (words > 20) return 'moderate';
    return 'simple';
  }
  
  private assessScope(content: string): string {
    const lower = content.toLowerCase();
    if (/all|every|entire|complete|full/.test(lower)) return 'broad';
    if (/only|just|specific|single/.test(lower)) return 'narrow';
    return 'medium';
  }
  
  private calculateSimilarity(text1: string, text2: string): number {
    const words1 = new Set(text1.toLowerCase().split(/\s+/));
    const words2 = new Set(text2.toLowerCase().split(/\s+/));
    
    const intersection = new Set([...words1].filter(x => words2.has(x)));
    const union = new Set([...words1, ...words2]);
    
    return intersection.size / union.size;
  }
  
  private calculateDrift(original: string, current: string, constraints: string[]) {
    const similarity = this.calculateSimilarity(original, current);
    const driftScore = 1 - similarity;
    
    // Check constraints
    const constraintViolations: string[] = [];
    for (const constraint of constraints) {
      if (current.toLowerCase().includes(constraint.replace(/^not?\s+/i, '').toLowerCase())) {
        if (constraint.toLowerCase().startsWith('no ') || constraint.toLowerCase().startsWith('not ')) {
          constraintViolations.push(constraint);
        }
      }
    }
    
    let verdict: string;
    if (constraintViolations.length > 0) verdict = 'violated';
    else if (driftScore > 0.5) verdict = 'significant_drift';
    else if (driftScore > 0.3) verdict = 'minor_drift';
    else verdict = 'aligned';
    
    return {
      verdict,
      semantic_similarity: similarity,
      drift_score: driftScore,
      constraint_violations: constraintViolations,
      cumulative_drift: driftScore,
      hop_drift: driftScore
    };
  }
  
  private analyzeSentiment(content: string): { score: number; label: string } {
    const positive = /good|great|excellent|happy|love|wonderful|fantastic/gi;
    const negative = /bad|terrible|awful|hate|horrible|disgusting|worst/gi;
    
    const posMatches = (content.match(positive) || []).length;
    const negMatches = (content.match(negative) || []).length;
    
    const score = (posMatches - negMatches) / Math.max(1, posMatches + negMatches);
    
    return {
      score,
      label: score > 0.2 ? 'positive' : score < -0.2 ? 'negative' : 'neutral'
    };
  }
  
  private computeMerkleRoot(hops: any[]): string {
    if (hops.length === 0) return '';
    
    const hashes = hops.map(h => h.cumulative_hash);
    
    while (hashes.length > 1) {
      const newHashes: string[] = [];
      for (let i = 0; i < hashes.length; i += 2) {
        const left = hashes[i];
        const right = hashes[i + 1] || left;
        newHashes.push(crypto.createHash('sha256').update(left + right).digest('hex'));
      }
      hashes.length = 0;
      hashes.push(...newHashes);
    }
    
    return hashes[0];
  }

  // =============================================================================
  // Compliance
  // =============================================================================

  async createCheckpoint(params: {
    thread_id: string; framework: string; control: string; event_type: string;
    event_description?: string; data_classification?: string; agent_id: string;
    user_id?: string; risk_level?: string; sign?: boolean;
  }): Promise<object> {
    const { ComplianceManager } = await import("@weave_protocol/domere");
    const compliance = new ComplianceManager(this.signingKey);
    return compliance.checkpoint({
      thread_id: params.thread_id, framework: params.framework as any,
      control: params.control, event_type: params.event_type as any,
      event_description: params.event_description || "",
      data_classification: params.data_classification as any || "internal",
      agent_id: params.agent_id, user_id: params.user_id,
      risk_level: params.risk_level as any || "low", sign: params.sign ?? true
    });
  }

  async logCardholderDataAccess(params: {
    thread_id: string; agent_id: string; data_type: string; action: string;
    masked: boolean; encrypted: boolean; business_justification: string;
  }): Promise<object> {
    const { ComplianceManager } = await import("@weave_protocol/domere");
    const compliance = new ComplianceManager(this.signingKey);
    return compliance.logCardholderDataAccess({
      thread_id: params.thread_id, agent_id: params.agent_id,
      data_type: params.data_type as any, action: params.action as any,
      masked: params.masked, encrypted: params.encrypted,
      business_justification: params.business_justification
    });
  }

  async logSecurityIncident(params: {
    thread_id: string; agent_id: string; incident_id: string; incident_type: string;
    severity: string; status: string; affected_assets: string[]; description?: string;
  }): Promise<object> {
    const { ComplianceManager } = await import("@weave_protocol/domere");
    const compliance = new ComplianceManager(this.signingKey);
    return compliance.logSecurityIncident({
      thread_id: params.thread_id, agent_id: params.agent_id,
      incident_id: params.incident_id, incident_type: params.incident_type as any,
      severity: params.severity as any, status: params.status as any,
      affected_assets: params.affected_assets, description: params.description || ""
    });
  }

  async logAssetEvent(params: {
    thread_id: string; agent_id: string; asset_id: string;
    asset_type: string; action: string; classification: string;
  }): Promise<object> {
    const { ComplianceManager } = await import("@weave_protocol/domere");
    const compliance = new ComplianceManager(this.signingKey);
    return compliance.logAssetEvent({
      thread_id: params.thread_id, agent_id: params.agent_id,
      asset_id: params.asset_id, asset_type: params.asset_type as any,
      action: params.action as any, classification: params.classification as any
    });
  }

  async generateComplianceReport(params: {
    framework: string; period_start: Date; period_end: Date;
  }): Promise<object> {
    const { ComplianceManager } = await import("@weave_protocol/domere");
    const compliance = new ComplianceManager(this.signingKey);
    return compliance.generateReport({
      framework: params.framework as any,
      period_start: params.period_start, period_end: params.period_end
    });
  }

}
