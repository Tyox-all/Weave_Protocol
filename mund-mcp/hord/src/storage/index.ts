/**
 * Hord - The Vault Protocol
 * Storage Module
 */

import type { IHordStorage } from '../types.js';
import { MemoryStorage } from './memory.js';

export { MemoryStorage } from './memory.js';

export type StorageType = 'memory' | 'sqlite' | 'postgres';

export function createStorage(type: StorageType = 'memory'): IHordStorage {
  switch (type) {
    case 'memory':
      return new MemoryStorage();
    case 'sqlite':
      // TODO: Implement SQLite storage
      console.warn('SQLite storage not yet implemented, falling back to memory');
      return new MemoryStorage();
    case 'postgres':
      // TODO: Implement PostgreSQL storage
      console.warn('PostgreSQL storage not yet implemented, falling back to memory');
      return new MemoryStorage();
    default:
      return new MemoryStorage();
  }
}
