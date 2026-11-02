/**
 * Hord - The Vault Protocol
 * Storage Module
 */

import type { IHordStorage } from '../types.js';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { MemoryStorage } from './memory.js';
import { SqliteStorage } from './sqlite.js';

export { MemoryStorage } from './memory.js';
export { SqliteStorage } from './sqlite.js';

export type StorageType = 'memory' | 'sqlite' | 'postgres';

export interface StorageOptions {
  /** SQLite file path; default HORD_DATABASE_URL, else ~/.weave/hord.sqlite. ":memory:" for tests. */
  path?: string;
}

export function createStorage(type: StorageType = 'memory', options: StorageOptions = {}): IHordStorage {
  switch (type) {
    case 'memory':
      return new MemoryStorage();
    case 'sqlite':
      return new SqliteStorage(options.path || process.env.HORD_DATABASE_URL || join(homedir(), '.weave', 'hord.sqlite'));
    case 'postgres':
      // Fail loudly rather than silently keeping data in memory.
      throw new Error('PostgreSQL storage is not implemented; use "sqlite" (persistent) or "memory".');
    default:
      throw new Error(`Unknown storage type: ${String(type)}`);
  }
}
