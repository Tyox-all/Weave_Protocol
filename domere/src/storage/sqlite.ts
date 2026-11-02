/**
 * Dōmere - The Judge Protocol
 * SQLite Storage (Node's built-in node:sqlite)
 *
 * Same behavior as MemoryStorage, persisted to one file. Records are JSON
 * documents in a single table; hops and evidence are their own collections
 * so they can be appended without rewriting the thread or case.
 *
 * node:sqlite is loaded only when this storage is created (it prints an
 * experimental-feature warning on load), so importing Dōmere stays silent.
 */

import { createRequire } from 'node:module';
import { randomUUID } from 'node:crypto';
import { chmodSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
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

interface Statement {
  run(...params: unknown[]): unknown;
  get(...params: unknown[]): Record<string, unknown> | undefined;
  all(...params: unknown[]): Record<string, unknown>[];
}
interface Database {
  exec(sql: string): void;
  prepare(sql: string): Statement;
  close(): void;
}

const ISO_DATE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
/** JSON.parse reviver that restores Dates (records compare and sort on them). */
const reviveDates = (_key: string, value: unknown) =>
  typeof value === 'string' && ISO_DATE.test(value) ? new Date(value) : value;

export class SqliteStorage implements IDomereStorage {
  private db: Database;

  constructor(path: string) {
    const require = createRequire(import.meta.url);
    const { DatabaseSync } = require('node:sqlite') as { DatabaseSync: new (path: string) => Database };
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(path);
    if (path !== ':memory:') chmodSync(path, 0o600);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS docs (
        collection TEXT NOT NULL,
        id         TEXT NOT NULL,
        parent     TEXT,
        seq        INTEGER NOT NULL DEFAULT 0,
        data       TEXT NOT NULL,
        PRIMARY KEY (collection, id)
      );
      CREATE INDEX IF NOT EXISTS docs_parent ON docs (collection, parent, seq);
    `);
  }

  close(): void {
    this.db.close();
  }

  // ─── document helpers ───────────────────────────────────────

  private put(collection: string, id: string, data: unknown, parent: string | null = null, seq = 0): void {
    this.db
      .prepare('INSERT OR REPLACE INTO docs (collection, id, parent, seq, data) VALUES (?, ?, ?, ?, ?)')
      .run(collection, id, parent, seq, JSON.stringify(data));
  }

  private get<T>(collection: string, id: string): T | null {
    const row = this.db.prepare('SELECT data FROM docs WHERE collection = ? AND id = ?').get(collection, id);
    return row ? (JSON.parse(row.data as string, reviveDates) as T) : null;
  }

  private all<T>(collection: string): T[] {
    return this.db
      .prepare('SELECT data FROM docs WHERE collection = ? ORDER BY rowid')
      .all(collection)
      .map((r) => JSON.parse(r.data as string, reviveDates) as T);
  }

  private children<T>(collection: string, parent: string): T[] {
    return this.db
      .prepare('SELECT data FROM docs WHERE collection = ? AND parent = ? ORDER BY seq, rowid')
      .all(collection, parent)
      .map((r) => JSON.parse(r.data as string, reviveDates) as T);
  }

  private childCount(collection: string, parent: string): number {
    const row = this.db.prepare('SELECT COUNT(*) AS n FROM docs WHERE collection = ? AND parent = ?').get(collection, parent);
    return Number(row?.n ?? 0);
  }

  /** Replace a thread's hops with exactly `hops`, in order. */
  private setHops(threadId: string, hops: ThreadHop[]): void {
    this.db.prepare("DELETE FROM docs WHERE collection = 'hop' AND parent = ?").run(threadId);
    hops.forEach((hop, i) => this.put('hop', hop.hop_id, hop, threadId, i));
  }

  private withHops(thread: Thread): Thread {
    return { ...thread, hops: this.children<ThreadHop>('hop', thread.id) };
  }

  private withEvidence(case_: ArbitrationCase): ArbitrationCase {
    return { ...case_, evidence: this.children<ArbitrationEvidence>('evidence', case_.id) };
  }

  // ============================================================================
  // Thread Operations
  // ============================================================================

  async saveThread(thread: Thread): Promise<void> {
    this.put('thread', thread.id, { ...thread, hops: [] });
    this.setHops(thread.id, thread.hops);
  }

  async getThread(id: string): Promise<Thread | null> {
    const thread = this.get<Thread>('thread', id);
    return thread ? this.withHops(thread) : null;
  }

  async updateThread(thread: Thread): Promise<void> {
    await this.saveThread(thread);
  }

  async listThreads(filters?: ThreadFilters): Promise<Thread[]> {
    let threads = this.all<Thread>('thread');

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

    const offset = filters?.offset ?? 0;
    const limit = filters?.limit ?? 100;

    return threads.slice(offset, offset + limit).map(t => this.withHops(t));
  }

  // ============================================================================
  // Hop Operations
  // ============================================================================

  async addHop(threadId: string, hop: ThreadHop): Promise<void> {
    // Idempotent by hop_id, like MemoryStorage.
    if (this.get<ThreadHop>('hop', hop.hop_id)) return;
    this.put('hop', hop.hop_id, hop, threadId, this.childCount('hop', threadId));
  }

  async getHops(threadId: string): Promise<ThreadHop[]> {
    return this.children<ThreadHop>('hop', threadId);
  }

  // ============================================================================
  // Compliance Operations
  // ============================================================================

  async saveComplianceResult(result: ComplianceResult): Promise<void> {
    this.put('compliance_result', randomUUID(), result, result.thread_id, this.childCount('compliance_result', result.thread_id));
  }

  async getComplianceResults(threadId: string): Promise<ComplianceResult[]> {
    return this.children<ComplianceResult>('compliance_result', threadId);
  }

  // ============================================================================
  // Policy Operations
  // ============================================================================

  async savePolicy(policy: CompliancePolicy): Promise<void> {
    this.put('policy', policy.id, policy);
  }

  async getPolicy(id: string): Promise<CompliancePolicy | null> {
    return this.get<CompliancePolicy>('policy', id);
  }

  async listPolicies(): Promise<CompliancePolicy[]> {
    return this.all<CompliancePolicy>('policy');
  }

  // ============================================================================
  // Anchor Operations
  // ============================================================================

  async saveAnchor(threadId: string, anchor: AnchorReference): Promise<void> {
    this.put('anchor', randomUUID(), anchor, threadId, this.childCount('anchor', threadId));
  }

  async getAnchors(threadId: string): Promise<AnchorReference[]> {
    return this.children<AnchorReference>('anchor', threadId);
  }

  // ============================================================================
  // Arbitration Operations
  // ============================================================================

  async saveCase(case_: ArbitrationCase): Promise<void> {
    this.put('case', case_.id, case_);
  }

  async getCase(id: string): Promise<ArbitrationCase | null> {
    const case_ = this.get<ArbitrationCase>('case', id);
    return case_ ? this.withEvidence(case_) : null;
  }

  async listCases(filters?: CaseFilters): Promise<ArbitrationCase[]> {
    let cases = this.all<ArbitrationCase>('case');

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

    const offset = filters?.offset ?? 0;
    const limit = filters?.limit ?? 100;

    return cases.slice(offset, offset + limit).map(c => this.withEvidence(c));
  }

  // ============================================================================
  // Evidence Operations
  // ============================================================================

  async saveEvidence(evidence: ArbitrationEvidence): Promise<void> {
    this.put('evidence', randomUUID(), evidence, evidence.case_id, this.childCount('evidence', evidence.case_id));
  }

  async getEvidence(caseId: string): Promise<ArbitrationEvidence[]> {
    return this.children<ArbitrationEvidence>('evidence', caseId);
  }
}
