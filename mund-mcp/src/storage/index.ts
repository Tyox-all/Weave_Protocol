/**
 * Mund - The Guardian Protocol
 * Storage Index - Exports storage implementations
 */

export { MemoryStorage } from './memory.js';

import { MemoryStorage } from './memory.js';
import type { IStorage, MundConfig } from '../types.js';

/**
 * Create storage instance based on configuration
 */
export function createStorage(config: MundConfig): IStorage {
  switch (config.storage_type) {
    case 'memory':
      return new MemoryStorage();
    case 'sqlite':
      // SQLite implementation would go here
      console.warn('SQLite storage not yet implemented, falling back to memory');
      return new MemoryStorage();
    case 'postgres':
      // PostgreSQL implementation would go here
      console.warn('PostgreSQL storage not yet implemented, falling back to memory');
      return new MemoryStorage();
    default:
      return new MemoryStorage();
  }
}
