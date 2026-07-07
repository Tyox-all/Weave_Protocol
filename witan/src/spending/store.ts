/**
 * Storage abstraction for spending counters.
 *
 * v1.1 ships only InMemorySpendingStore. v1.2 will add RedisSpendingStore
 * and SqliteSpendingStore. The interface is stable across versions.
 *
 * Keys look like:  '<window>:<bucket>:<scope>:<metric>'
 *   metric ∈ { 'usd', 'tokens', 'tool_calls', 'tool:<name>:calls', 'tool:<name>:amount_usd' }
 */

export interface SpendingStore {
  /** Read the current value for a key. Missing = 0. */
  get(key: string): Promise<number>;
  /** Atomically add delta and return the new value. */
  add(key: string, delta: number): Promise<number>;
  /** Reset a key to zero. */
  reset(key: string): Promise<void>;
  /** List keys matching a prefix (for status/CLI queries). */
  listKeys(prefix: string): Promise<string[]>;
  /** Snapshot: return all matching keys and their values. */
  snapshot(prefix: string): Promise<Record<string, number>>;
}

/**
 * Default in-memory store. Zero-config, single-process only.
 * State is lost on process restart — appropriate for v1.1 use cases:
 *   - Claude Code / Antigravity / MSAF sessions (single process, single agent)
 *   - LangChain apps in a Node.js process
 *   - CI/test runs
 *
 * For multi-process, multi-agent, or persistence-across-restart, wait for v1.2.
 */
export class InMemorySpendingStore implements SpendingStore {
  private data = new Map<string, number>();

  async get(key: string): Promise<number> {
    return this.data.get(key) ?? 0;
  }

  async add(key: string, delta: number): Promise<number> {
    const next = (this.data.get(key) ?? 0) + delta;
    this.data.set(key, next);
    return next;
  }

  async reset(key: string): Promise<void> {
    this.data.delete(key);
  }

  async listKeys(prefix: string): Promise<string[]> {
    return Array.from(this.data.keys()).filter((k) => k.startsWith(prefix));
  }

  async snapshot(prefix: string): Promise<Record<string, number>> {
    const out: Record<string, number> = {};
    for (const [k, v] of this.data.entries()) {
      if (k.startsWith(prefix)) out[k] = v;
    }
    return out;
  }
}
