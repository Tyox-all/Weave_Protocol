/**
 * Hord - The Vault Protocol
 * SQLite Storage (Node's built-in node:sqlite)
 *
 * Same behavior as MemoryStorage, persisted to one file. Records are JSON
 * documents in a single table. Vault keys are persisted too, wrapped with
 * the master key, so a vault survives a restart only when the same master
 * key is configured.
 *
 * node:sqlite is loaded only when this storage is created (it prints an
 * experimental-feature warning on load), so importing Hord stays silent.
 */

import { createRequire } from 'node:module';
import { chmodSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import type {
  IHordStorage,
  Vault,
  CapabilityToken,
  Sandbox,
  SandboxResult,
  RedactionPolicy,
  TokenizationMap,
  Attestation,
  AccessLogEntry,
  AccessLogFilters,
} from '../types.js';
import { keyStore, type EncryptedData } from '../vault/encryption.js';

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

const ACCESS_LOG_LIMIT = 10000;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
/** JSON.parse reviver that restores Dates (records compare and sort on them). */
const reviveDates = (_key: string, value: unknown) =>
  typeof value === 'string' && ISO_DATE.test(value) ? new Date(value) : value;

export class SqliteStorage implements IHordStorage {
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
        owner      TEXT,
        parent     TEXT,
        ts         INTEGER NOT NULL DEFAULT 0,
        data       TEXT NOT NULL,
        PRIMARY KEY (collection, id)
      );
      CREATE INDEX IF NOT EXISTS docs_owner ON docs (collection, owner);
      CREATE INDEX IF NOT EXISTS docs_parent ON docs (collection, parent);
      CREATE INDEX IF NOT EXISTS docs_ts ON docs (collection, ts);
    `);
  }

  close(): void {
    this.db.close();
  }

  // ─── document helpers ───────────────────────────────────────

  private put(collection: string, id: string, data: unknown, meta: { owner?: string; parent?: string; ts?: number } = {}): void {
    this.db
      .prepare('INSERT OR REPLACE INTO docs (collection, id, owner, parent, ts, data) VALUES (?, ?, ?, ?, ?, ?)')
      .run(collection, id, meta.owner ?? null, meta.parent ?? null, meta.ts ?? 0, JSON.stringify(data));
  }

  private get<T>(collection: string, id: string, revive = true): T | null {
    const row = this.db.prepare('SELECT data FROM docs WHERE collection = ? AND id = ?').get(collection, id);
    return row ? (JSON.parse(row.data as string, revive ? reviveDates : undefined) as T) : null;
  }

  private list<T>(collection: string, where = '', ...params: unknown[]): T[] {
    return this.db
      .prepare(`SELECT data FROM docs WHERE collection = ?${where ? ` AND ${where}` : ''} ORDER BY rowid`)
      .all(collection, ...params)
      .map((r) => JSON.parse(r.data as string, reviveDates) as T);
  }

  private remove(collection: string, id: string): void {
    this.db.prepare('DELETE FROM docs WHERE collection = ? AND id = ?').run(collection, id);
  }

  private exists(collection: string, id: string): boolean {
    return !!this.db.prepare('SELECT 1 FROM docs WHERE collection = ? AND id = ?').get(collection, id);
  }

  // ─── vault keys (wrapped with the master key) ──────────────

  private persistKey(keyId: string): void {
    const wrapped = keyStore.exportKeys().find((k) => k.id === keyId);
    if (wrapped) this.put('key', keyId, wrapped.encrypted);
  }

  private loadKey(keyId: string): void {
    if (keyStore.getKey(keyId)) return;
    const wrapped = this.get<EncryptedData>('key', keyId, false);
    if (wrapped) keyStore.importKey(keyId, wrapped, 'encryption');
  }

  // ============================================================================
  // Vaults
  // ============================================================================

  async saveVault(vault: Vault): Promise<void> {
    this.put('vault', vault.id, vault, { owner: vault.agent_id });
    this.persistKey(vault.encryption.key_id);
  }

  async getVault(id: string): Promise<Vault | null> {
    const vault = this.get<Vault>('vault', id);
    if (vault) this.loadKey(vault.encryption.key_id);
    return vault;
  }

  async getVaultsByAgent(agentId: string): Promise<Vault[]> {
    return this.list<Vault>('vault', 'owner = ?', agentId);
  }

  async updateVault(vault: Vault): Promise<void> {
    if (!this.exists('vault', vault.id)) {
      throw new Error('Vault not found');
    }
    this.put('vault', vault.id, vault, { owner: vault.agent_id });
  }

  async deleteVault(id: string): Promise<void> {
    const vault = this.get<Vault>('vault', id);
    this.remove('vault', id);
    this.remove('vault_contents', id);
    if (vault) this.remove('key', vault.encryption.key_id);
  }

  async saveVaultContents(vaultId: string, contents: string): Promise<void> {
    this.put('vault_contents', vaultId, contents);
  }

  async getVaultContents(vaultId: string): Promise<string | null> {
    return this.get<string>('vault_contents', vaultId, false);
  }

  // ============================================================================
  // Capability Tokens
  // ============================================================================

  async saveCapabilityToken(token: CapabilityToken): Promise<void> {
    this.put('capability', token.id, token, { owner: token.agent_id });
  }

  async getCapabilityToken(id: string): Promise<CapabilityToken | null> {
    return this.get<CapabilityToken>('capability', id);
  }

  async getCapabilityTokensByAgent(agentId: string): Promise<CapabilityToken[]> {
    return this.list<CapabilityToken>('capability', 'owner = ?', agentId);
  }

  async revokeCapabilityToken(id: string): Promise<void> {
    const token = this.get<CapabilityToken>('capability', id);
    if (token) {
      token.revoked = true;
      this.put('capability', id, token, { owner: token.agent_id });
    }
  }

  async incrementTokenUse(id: string): Promise<void> {
    const token = this.get<CapabilityToken>('capability', id);
    if (token) {
      token.uses++;
      this.put('capability', id, token, { owner: token.agent_id });
    }
  }

  // ============================================================================
  // Sandboxes
  // ============================================================================

  async saveSandbox(sandbox: Sandbox): Promise<void> {
    this.put('sandbox', sandbox.id, sandbox);
  }

  async getSandbox(id: string): Promise<Sandbox | null> {
    return this.get<Sandbox>('sandbox', id);
  }

  async updateSandboxStatus(id: string, status: Sandbox['status']): Promise<void> {
    const sandbox = this.get<Sandbox>('sandbox', id);
    if (sandbox) {
      sandbox.status = status;
      this.put('sandbox', id, sandbox);
    }
  }

  async saveSandboxResult(result: SandboxResult): Promise<void> {
    this.put('sandbox_result', result.id, result, { parent: result.sandbox_id });
  }

  async getSandboxResult(id: string): Promise<SandboxResult | null> {
    return this.get<SandboxResult>('sandbox_result', id);
  }

  async getSandboxResults(sandboxId: string): Promise<SandboxResult[]> {
    return this.list<SandboxResult>('sandbox_result', 'parent = ?', sandboxId);
  }

  // ============================================================================
  // Redaction Policies
  // ============================================================================

  async saveRedactionPolicy(policy: RedactionPolicy): Promise<void> {
    this.put('redaction_policy', policy.id, policy);
  }

  async getRedactionPolicy(id: string): Promise<RedactionPolicy | null> {
    return this.get<RedactionPolicy>('redaction_policy', id);
  }

  async listRedactionPolicies(): Promise<RedactionPolicy[]> {
    return this.list<RedactionPolicy>('redaction_policy');
  }

  // ============================================================================
  // Tokenization (original values are returned exactly, never revived)
  // ============================================================================

  async saveTokenMapping(token: string, mapping: TokenizationMap[string]): Promise<void> {
    this.put('token_mapping', token, mapping);
  }

  async getTokenMapping(token: string): Promise<TokenizationMap[string] | null> {
    return this.get<TokenizationMap[string]>('token_mapping', token, false);
  }

  // ============================================================================
  // Attestations
  // ============================================================================

  async saveAttestation(attestation: Attestation): Promise<void> {
    this.put('attestation', attestation.id, attestation, {
      owner: attestation.agent_id,
      ts: new Date(attestation.timestamp).getTime(),
    });
  }

  async getAttestation(id: string): Promise<Attestation | null> {
    return this.get<Attestation>('attestation', id);
  }

  async getAttestationsByAgent(agentId: string, limit?: number): Promise<Attestation[]> {
    const rows = this.db
      .prepare(`SELECT data FROM docs WHERE collection = 'attestation' AND owner = ? ORDER BY ts DESC${limit ? ' LIMIT ?' : ''}`)
      .all(...(limit ? [agentId, limit] : [agentId]));
    return rows.map((r) => JSON.parse(r.data as string, reviveDates) as Attestation);
  }

  async getAttestationChain(id: string): Promise<Attestation[]> {
    const chain: Attestation[] = [];
    let currentId: string | undefined = id;

    while (currentId && chain.length < 1000) {
      const attestation: Attestation | null = this.get<Attestation>('attestation', currentId);
      if (!attestation) break;

      chain.push(attestation);
      currentId = attestation.previous_attestation_id;
    }

    return chain;
  }

  // ============================================================================
  // Access Log
  // ============================================================================

  async logAccess(entry: AccessLogEntry): Promise<void> {
    this.put('access_log', entry.id, entry, { owner: entry.agent_id, ts: new Date(entry.timestamp).getTime() });

    // Keep only the most recent entries, like MemoryStorage
    this.db
      .prepare(
        `DELETE FROM docs WHERE collection = 'access_log' AND rowid NOT IN (
           SELECT rowid FROM docs WHERE collection = 'access_log' ORDER BY ts DESC, rowid DESC LIMIT ?)`,
      )
      .run(ACCESS_LOG_LIMIT);
  }

  async getAccessLog(filters: AccessLogFilters): Promise<AccessLogEntry[]> {
    let entries = this.list<AccessLogEntry>('access_log');

    if (filters.agent_id) {
      entries = entries.filter(e => e.agent_id === filters.agent_id);
    }
    if (filters.action) {
      entries = entries.filter(e => e.action === filters.action);
    }
    if (filters.resource) {
      entries = entries.filter(e => e.resource.includes(filters.resource!));
    }
    if (filters.start_date) {
      entries = entries.filter(e => e.timestamp >= filters.start_date!);
    }
    if (filters.end_date) {
      entries = entries.filter(e => e.timestamp <= filters.end_date!);
    }
    if (filters.success !== undefined) {
      entries = entries.filter(e => e.success === filters.success);
    }

    entries.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    if (filters.offset) {
      entries = entries.slice(filters.offset);
    }
    if (filters.limit) {
      entries = entries.slice(0, filters.limit);
    }

    return entries;
  }
}
