/**
 * Mund - The Guardian Protocol
 * Memory Storage - In-memory storage for development and testing
 */

import type { 
  IStorage, 
  SecurityEvent, 
  DetectionRule, 
  GetEventsInput,
  DetectorType
} from '../types.js';

export class MemoryStorage implements IStorage {
  private events: Map<string, SecurityEvent> = new Map();
  private rules: Map<string, DetectionRule> = new Map();
  private allowlist: Map<string, { pattern: string; type: DetectorType }> = new Map();
  private blocklist: Map<string, { pattern: string; type: DetectorType }> = new Map();

  // ============================================================================
  // Events
  // ============================================================================

  async saveEvent(event: SecurityEvent): Promise<void> {
    this.events.set(event.id, event);
    
    // Keep only last 10000 events in memory
    if (this.events.size > 10000) {
      const oldestKey = this.events.keys().next().value;
      if (oldestKey) {
        this.events.delete(oldestKey);
      }
    }
  }

  async getEvent(id: string): Promise<SecurityEvent | null> {
    return this.events.get(id) || null;
  }

  async getEvents(query: GetEventsInput): Promise<SecurityEvent[]> {
    let events = Array.from(this.events.values());

    // Apply filters
    if (query.severity) {
      events = events.filter(e => e.severity === query.severity);
    }
    if (query.type) {
      events = events.filter(e => e.type === query.type);
    }
    if (query.acknowledged !== undefined) {
      events = events.filter(e => e.acknowledged === query.acknowledged);
    }
    if (query.start_time) {
      events = events.filter(e => e.timestamp >= query.start_time!);
    }
    if (query.end_time) {
      events = events.filter(e => e.timestamp <= query.end_time!);
    }

    // Sort by timestamp descending (newest first)
    events.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    // Apply pagination
    const offset = query.offset || 0;
    const limit = query.limit || 50;
    return events.slice(offset, offset + limit);
  }

  async countEvents(query: GetEventsInput): Promise<number> {
    let events = Array.from(this.events.values());

    if (query.severity) {
      events = events.filter(e => e.severity === query.severity);
    }
    if (query.type) {
      events = events.filter(e => e.type === query.type);
    }
    if (query.acknowledged !== undefined) {
      events = events.filter(e => e.acknowledged === query.acknowledged);
    }
    if (query.start_time) {
      events = events.filter(e => e.timestamp >= query.start_time!);
    }
    if (query.end_time) {
      events = events.filter(e => e.timestamp <= query.end_time!);
    }

    return events.length;
  }

  async acknowledgeEvent(id: string, by?: string): Promise<void> {
    const event = this.events.get(id);
    if (event) {
      event.acknowledged = true;
      event.acknowledged_by = by;
      event.acknowledged_at = new Date();
    }
  }

  // ============================================================================
  // Rules
  // ============================================================================

  async saveRule(rule: DetectionRule): Promise<void> {
    this.rules.set(rule.id, rule);
  }

  async getRule(id: string): Promise<DetectionRule | null> {
    return this.rules.get(id) || null;
  }

  async getRules(): Promise<DetectionRule[]> {
    return Array.from(this.rules.values());
  }

  async deleteRule(id: string): Promise<void> {
    this.rules.delete(id);
  }

  // ============================================================================
  // Allowlist/Blocklist
  // ============================================================================

  async addToAllowlist(pattern: string, type: DetectorType): Promise<void> {
    this.allowlist.set(pattern, { pattern, type });
  }

  async addToBlocklist(pattern: string, type: DetectorType): Promise<void> {
    this.blocklist.set(pattern, { pattern, type });
  }

  async getAllowlist(type?: DetectorType): Promise<string[]> {
    const entries = Array.from(this.allowlist.values());
    if (type) {
      return entries.filter(e => e.type === type).map(e => e.pattern);
    }
    return entries.map(e => e.pattern);
  }

  async getBlocklist(type?: DetectorType): Promise<string[]> {
    const entries = Array.from(this.blocklist.values());
    if (type) {
      return entries.filter(e => e.type === type).map(e => e.pattern);
    }
    return entries.map(e => e.pattern);
  }

  async removeFromAllowlist(pattern: string): Promise<void> {
    this.allowlist.delete(pattern);
  }

  async removeFromBlocklist(pattern: string): Promise<void> {
    this.blocklist.delete(pattern);
  }

  // ============================================================================
  // Cleanup
  // ============================================================================

  async close(): Promise<void> {
    this.events.clear();
    this.rules.clear();
    this.allowlist.clear();
    this.blocklist.clear();
  }

  // ============================================================================
  // Utility Methods
  // ============================================================================

  getStats(): { events: number; rules: number; allowlist: number; blocklist: number } {
    return {
      events: this.events.size,
      rules: this.rules.size,
      allowlist: this.allowlist.size,
      blocklist: this.blocklist.size
    };
  }
}

export default MemoryStorage;
