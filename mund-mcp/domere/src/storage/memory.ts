/**
 * Dōmere - The Judge Protocol
 * Memory Storage Implementation
 */

import type {
  IDomereStorage,
  Thread,
  ThreadHop,
  ThreadFilters,
  ComplianceResult,
  CompliancePolicy,
  AnchorReference,
  ArbitrationCase,
  ArbitrationEvidence,
  CaseFilters,
} from '../types.js';

// ============================================================================
// Memory Storage
// ============================================================================

export class MemoryStorage implements IDomereStorage {
  private threads: Map<string, Thread> = new Map();
  private hops: Map<string, ThreadHop[]> = new Map();
  private complianceResults: Map<string, ComplianceResult[]> = new Map();
  private policies: Map<string, CompliancePolicy> = new Map();
  private anchors: Map<string, AnchorReference[]> = new Map();
  private cases: Map<string, ArbitrationCase> = new Map();
  private evidence: Map<string, ArbitrationEvidence[]> = new Map();
  
  // ============================================================================
  // Thread Operations
  // ============================================================================
  
  async saveThread(thread: Thread): Promise<void> {
    this.threads.set(thread.id, { ...thread });
    this.hops.set(thread.id, [...thread.hops]);
  }
  
  async getThread(id: string): Promise<Thread | null> {
    const thread = this.threads.get(id);
    if (!thread) return null;
    
    return {
      ...thread,
      hops: this.hops.get(id) || [],
    };
  }
  
  async updateThread(thread: Thread): Promise<void> {
    this.threads.set(thread.id, { ...thread });
    this.hops.set(thread.id, [...thread.hops]);
  }
  
  async listThreads(filters?: ThreadFilters): Promise<Thread[]> {
    let threads = Array.from(this.threads.values());
    
    if (filters) {
      if (filters.status) {
        threads = threads.filter(t => t.status === filters.status);
      }
      if (filters.origin_type) {
        threads = threads.filter(t => t.origin.type === filters.origin_type);
      }
      if (filters.origin_identity) {
        threads = threads.filter(t => t.origin.identity === filters.origin_identity);
      }
      if (filters.since) {
        threads = threads.filter(t => t.created_at >= filters.since!);
      }
      if (filters.until) {
        threads = threads.filter(t => t.created_at <= filters.until!);
      }
    }
    
    // Sort by creation date (newest first)
    threads.sort((a, b) => b.created_at.getTime() - a.created_at.getTime());
    
    // Apply pagination
    const offset = filters?.offset ?? 0;
    const limit = filters?.limit ?? 100;
    
    return threads.slice(offset, offset + limit).map(t => ({
      ...t,
      hops: this.hops.get(t.id) || [],
    }));
  }
  
  // ============================================================================
  // Hop Operations
  // ============================================================================
  
  async addHop(threadId: string, hop: ThreadHop): Promise<void> {
    const hops = this.hops.get(threadId) || [];
    hops.push({ ...hop });
    this.hops.set(threadId, hops);
  }
  
  async getHops(threadId: string): Promise<ThreadHop[]> {
    return [...(this.hops.get(threadId) || [])];
  }
  
  // ============================================================================
  // Compliance Operations
  // ============================================================================
  
  async saveComplianceResult(result: ComplianceResult): Promise<void> {
    const results = this.complianceResults.get(result.thread_id) || [];
    results.push({ ...result });
    this.complianceResults.set(result.thread_id, results);
  }
  
  async getComplianceResults(threadId: string): Promise<ComplianceResult[]> {
    return [...(this.complianceResults.get(threadId) || [])];
  }
  
  // ============================================================================
  // Policy Operations
  // ============================================================================
  
  async savePolicy(policy: CompliancePolicy): Promise<void> {
    this.policies.set(policy.id, { ...policy });
  }
  
  async getPolicy(id: string): Promise<CompliancePolicy | null> {
    const policy = this.policies.get(id);
    return policy ? { ...policy } : null;
  }
  
  async listPolicies(): Promise<CompliancePolicy[]> {
    return Array.from(this.policies.values()).map(p => ({ ...p }));
  }
  
  // ============================================================================
  // Anchor Operations
  // ============================================================================
  
  async saveAnchor(threadId: string, anchor: AnchorReference): Promise<void> {
    const anchors = this.anchors.get(threadId) || [];
    anchors.push({ ...anchor });
    this.anchors.set(threadId, anchors);
  }
  
  async getAnchors(threadId: string): Promise<AnchorReference[]> {
    return [...(this.anchors.get(threadId) || [])];
  }
  
  // ============================================================================
  // Arbitration Operations
  // ============================================================================
  
  async saveCase(case_: ArbitrationCase): Promise<void> {
    this.cases.set(case_.id, { ...case_ });
  }
  
  async getCase(id: string): Promise<ArbitrationCase | null> {
    const case_ = this.cases.get(id);
    if (!case_) return null;
    
    return {
      ...case_,
      evidence: this.evidence.get(id) || [],
    };
  }
  
  async listCases(filters?: CaseFilters): Promise<ArbitrationCase[]> {
    let cases = Array.from(this.cases.values());
    
    if (filters) {
      if (filters.status) {
        cases = cases.filter(c => c.status === filters.status);
      }
      if (filters.dispute_type) {
        cases = cases.filter(c => c.dispute.type === filters.dispute_type);
      }
      if (filters.thread_id) {
        cases = cases.filter(c => c.thread_id === filters.thread_id);
      }
    }
    
    // Sort by creation date (newest first)
    cases.sort((a, b) => b.created_at.getTime() - a.created_at.getTime());
    
    // Apply pagination
    const offset = filters?.offset ?? 0;
    const limit = filters?.limit ?? 100;
    
    return cases.slice(offset, offset + limit).map(c => ({
      ...c,
      evidence: this.evidence.get(c.id) || [],
    }));
  }
  
  // ============================================================================
  // Evidence Operations
  // ============================================================================
  
  async saveEvidence(evidence: ArbitrationEvidence): Promise<void> {
    const evidenceList = this.evidence.get(evidence.case_id) || [];
    evidenceList.push({ ...evidence });
    this.evidence.set(evidence.case_id, evidenceList);
  }
  
  async getEvidence(caseId: string): Promise<ArbitrationEvidence[]> {
    return [...(this.evidence.get(caseId) || [])];
  }
  
  // ============================================================================
  // Utility Operations
  // ============================================================================
  
  /**
   * Clear all data
   */
  clear(): void {
    this.threads.clear();
    this.hops.clear();
    this.complianceResults.clear();
    this.policies.clear();
    this.anchors.clear();
    this.cases.clear();
    this.evidence.clear();
  }
  
  /**
   * Get statistics
   */
  getStats(): {
    threads: number;
    hops: number;
    policies: number;
    anchors: number;
    cases: number;
  } {
    let totalHops = 0;
    for (const hops of this.hops.values()) {
      totalHops += hops.length;
    }
    
    let totalAnchors = 0;
    for (const anchors of this.anchors.values()) {
      totalAnchors += anchors.length;
    }
    
    return {
      threads: this.threads.size,
      hops: totalHops,
      policies: this.policies.size,
      anchors: totalAnchors,
      cases: this.cases.size,
    };
  }
}

// ============================================================================
// Storage Factory
// ============================================================================

export function createStorage(type: 'memory' | 'sqlite' = 'memory'): IDomereStorage {
  switch (type) {
    case 'memory':
      return new MemoryStorage();
    case 'sqlite':
      // TODO: Implement SQLite storage
      console.warn('SQLite storage not implemented, falling back to memory');
      return new MemoryStorage();
    default:
      return new MemoryStorage();
  }
}
