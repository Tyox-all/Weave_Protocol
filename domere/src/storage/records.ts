/**
 * Dōmere - The Judge Protocol
 * Persistence for GDPR and CCPA records
 *
 * The GDPR and CCPA managers keep their records in Maps and update many of
 * them in place (a DSAR's status, a consent's withdrawal). PersistentMap is a
 * drop-in Map that writes through to a ComplianceRecordStore: set() and
 * delete() persist at once, and in-place changes are written by flush(),
 * which runs automatically after any synchronous code that read the map and
 * can be called directly (the MCP server does after every tool call).
 *
 * Deletes are real deletes. The SQLite store enables secure_delete, so an
 * erased data subject's records are overwritten on disk, not just unlinked.
 */

import { createRequire } from 'node:module';
import { chmodSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export interface ComplianceRecordStore {
  /** Every record in a collection, in insertion order. */
  load(collection: string): Array<[string, string]>;
  /** Insert or replace a record (serialized JSON); keeps its original position. */
  put(collection: string, id: string, json: string): void;
  remove(collection: string, id: string): void;
  close?(): void;
}

const ISO_DATE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
/** JSON.parse reviver that restores Dates (records compare and sort on them). */
const reviveDates = (_key: string, value: unknown) =>
  typeof value === 'string' && ISO_DATE.test(value) ? new Date(value) : value;

/**
 * A Map whose entries live in a ComplianceRecordStore. Reads are served from
 * memory; the store is only read once, when the map is created.
 */
export class PersistentMap<V> extends Map<string, V> {
  private readonly written = new Map<string, string>();
  private ready = false;
  private flushQueued = false;

  constructor(
    private readonly store: ComplianceRecordStore,
    private readonly collection: string,
  ) {
    super();
    for (const [id, json] of store.load(collection)) {
      super.set(id, JSON.parse(json, reviveDates) as V);
      this.written.set(id, json);
    }
    this.ready = true;
  }

  override set(id: string, value: V): this {
    super.set(id, value);
    if (this.ready) this.write(id, value);
    return this;
  }

  override delete(id: string): boolean {
    const had = super.delete(id);
    if (had) {
      this.store.remove(this.collection, id);
      this.written.delete(id);
    }
    return had;
  }

  override clear(): void {
    for (const id of [...this.keys()]) this.delete(id);
  }

  // Anything that hands out a record may be followed by an in-place change.
  override get(id: string): V | undefined {
    this.queueFlush();
    return super.get(id);
  }
  override values(): MapIterator<V> {
    this.queueFlush();
    return super.values();
  }
  override entries(): MapIterator<[string, V]> {
    this.queueFlush();
    return super.entries();
  }
  override [Symbol.iterator](): MapIterator<[string, V]> {
    this.queueFlush();
    return super[Symbol.iterator]();
  }
  override forEach(fn: (value: V, key: string, map: Map<string, V>) => void, thisArg?: unknown): void {
    this.queueFlush();
    super.forEach(fn, thisArg);
  }

  /** Persist every record that changed in place since it was last written. */
  flush(): void {
    this.flushQueued = false;
    for (const [id, value] of super.entries()) this.write(id, value);
  }

  private write(id: string, value: V): void {
    const json = JSON.stringify(value);
    if (this.written.get(id) === json) return;
    this.store.put(this.collection, id, json);
    this.written.set(id, json);
  }

  private queueFlush(): void {
    if (this.flushQueued) return;
    this.flushQueued = true;
    queueMicrotask(() => this.flush());
  }
}

/** A Map for a collection: persistent when a store is given, plain otherwise. */
export function recordMap<V>(store: ComplianceRecordStore | undefined, collection: string): Map<string, V> {
  return store ? new PersistentMap<V>(store, collection) : new Map<string, V>();
}

/** Flush every PersistentMap among an object's values. */
export function flushRecordMaps(maps: object): void {
  for (const m of Object.values(maps)) if (m instanceof PersistentMap) m.flush();
}

// ─────────────────────────────────────────────────────────
// SQLite store (node:sqlite, loaded only when created)
// ─────────────────────────────────────────────────────────

interface Statement {
  run(...params: unknown[]): unknown;
  all(...params: unknown[]): Record<string, unknown>[];
}
interface Database {
  exec(sql: string): void;
  prepare(sql: string): Statement;
  close(): void;
}

export class SqliteRecordStore implements ComplianceRecordStore {
  private db: Database;
  private putStmt: Statement;
  private removeStmt: Statement;
  private loadStmt: Statement;

  constructor(path: string) {
    const require = createRequire(import.meta.url);
    const { DatabaseSync } = require('node:sqlite') as { DatabaseSync: new (path: string) => Database };
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(path);
    if (path !== ':memory:') chmodSync(path, 0o600);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA secure_delete = ON;
      CREATE TABLE IF NOT EXISTS compliance_records (
        seq        INTEGER PRIMARY KEY AUTOINCREMENT,
        collection TEXT NOT NULL,
        id         TEXT NOT NULL,
        json       TEXT NOT NULL,
        UNIQUE (collection, id)
      );
    `);
    this.putStmt = this.db.prepare(
      'INSERT INTO compliance_records (collection, id, json) VALUES (?, ?, ?) ON CONFLICT (collection, id) DO UPDATE SET json = excluded.json',
    );
    this.removeStmt = this.db.prepare('DELETE FROM compliance_records WHERE collection = ? AND id = ?');
    this.loadStmt = this.db.prepare('SELECT id, json FROM compliance_records WHERE collection = ? ORDER BY seq');
  }

  load(collection: string): Array<[string, string]> {
    return this.loadStmt.all(collection).map((r) => [String(r.id), String(r.json)]);
  }

  put(collection: string, id: string, json: string): void {
    this.putStmt.run(collection, id, json);
  }

  remove(collection: string, id: string): void {
    this.removeStmt.run(collection, id);
    // secure_delete overwrites the main file; fold the WAL in too so no
    // copy of an erased record is left in it.
    this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  }

  close(): void {
    this.db.close();
  }
}
