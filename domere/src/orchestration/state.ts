/**
 * Dōmere - State Manager
 * 
 * Distributed state management with locking, branching, and conflict resolution
 * for multi-agent AI orchestration systems.
 */

import * as crypto from 'crypto';

// =============================================================================
// Types
// =============================================================================

export type ConflictResolution = 'last-write-wins' | 'first-write-wins' | 'merge' | 'manual';
export type LockType = 'exclusive' | 'shared';

export interface StateEntry {
  key: string;
  value: any;
  version: number;
  hash: string;
  created_at: Date;
  updated_at: Date;
  updated_by: string;
  branch: string;
  metadata: Record<string, any>;
}

export interface Lock {
  id: string;
  key: string;
  type: LockType;
  holder: string;
  acquired_at: Date;
  expires_at: Date;
  renewed_count: number;
}

export interface LockRequest {
  key: string;
  holder: string;
  type?: LockType;
  duration_ms?: number;
  wait_ms?: number;  // How long to wait if locked
}

export interface LockResult {
  acquired: boolean;
  lock?: Lock;
  reason?: string;
  current_holder?: string;
  retry_after_ms?: number;
}

export interface Branch {
  name: string;
  parent: string;
  created_at: Date;
  created_by: string;
  head_version: number;
  merged: boolean;
  merged_at?: Date;
}

export interface MergeResult {
  success: boolean;
  conflicts: Conflict[];
  merged_keys: string[];
  source_branch: string;
  target_branch: string;
}

export interface Conflict {
  key: string;
  source_value: any;
  target_value: any;
  source_version: number;
  target_version: number;
  base_value?: any;
}

export interface StateChange {
  type: 'set' | 'delete' | 'merge';
  key: string;
  old_value?: any;
  new_value?: any;
  version: number;
  timestamp: Date;
  agent_id: string;
  branch: string;
}

export interface StateSnapshot {
  id: string;
  branch: string;
  timestamp: Date;
  entries: Map<string, StateEntry>;
  version: number;
}

// =============================================================================
// State Manager
// =============================================================================

export class StateManager {
  private state: Map<string, Map<string, StateEntry>> = new Map();  // branch -> key -> entry
  private locks: Map<string, Lock> = new Map();  // key -> lock
  private branches: Map<string, Branch> = new Map();
  private snapshots: Map<string, StateSnapshot> = new Map();
  private changeLog: StateChange[] = [];
  private changeCallbacks: ((change: StateChange) => void)[] = [];
  
  private conflictResolution: ConflictResolution;
  private defaultLockDuration: number;
  
  constructor(options?: {
    conflict_resolution?: ConflictResolution;
    default_lock_duration_ms?: number;
  }) {
    this.conflictResolution = options?.conflict_resolution || 'last-write-wins';
    this.defaultLockDuration = options?.default_lock_duration_ms || 30000;
    
    // Initialize main branch
    this.branches.set('main', {
      name: 'main',
      parent: '',
      created_at: new Date(),
      created_by: 'system',
      head_version: 0,
      merged: false,
    });
    this.state.set('main', new Map());
    
    // Start lock cleanup timer
    setInterval(() => this.cleanupExpiredLocks(), 5000);
  }
  
  // ===========================================================================
  // Basic State Operations
  // ===========================================================================
  
  /**
   * Get a value
   */
  async get(key: string, options?: { branch?: string }): Promise<any | undefined> {
    const branch = options?.branch || 'main';
    const branchState = this.state.get(branch);
    if (!branchState) return undefined;
    
    const entry = branchState.get(key);
    return entry?.value;
  }
  
  /**
   * Get entry with metadata
   */
  async getEntry(key: string, options?: { branch?: string }): Promise<StateEntry | undefined> {
    const branch = options?.branch || 'main';
    const branchState = this.state.get(branch);
    if (!branchState) return undefined;
    
    return branchState.get(key);
  }
  
  /**
   * Set a value
   */
  async set(key: string, value: any, options?: {
    branch?: string;
    agent_id?: string;
    metadata?: Record<string, any>;
    require_lock?: boolean;
  }): Promise<StateEntry> {
    const branch = options?.branch || 'main';
    const agentId = options?.agent_id || 'unknown';
    
    // Check lock
    if (options?.require_lock) {
      const lock = this.locks.get(key);
      if (!lock || lock.holder !== agentId) {
        throw new Error(`Agent ${agentId} does not hold lock on ${key}`);
      }
    }
    
    // Check for existing exclusive lock by another holder
    const existingLock = this.locks.get(key);
    if (existingLock && existingLock.type === 'exclusive' && existingLock.holder !== agentId) {
      throw new Error(`Key ${key} is exclusively locked by ${existingLock.holder}`);
    }
    
    let branchState = this.state.get(branch);
    if (!branchState) {
      throw new Error(`Branch ${branch} does not exist`);
    }
    
    const existing = branchState.get(key);
    const now = new Date();
    const version = existing ? existing.version + 1 : 1;
    const hash = crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
    
    const entry: StateEntry = {
      key,
      value,
      version,
      hash,
      created_at: existing?.created_at || now,
      updated_at: now,
      updated_by: agentId,
      branch,
      metadata: options?.metadata || existing?.metadata || {},
    };
    
    branchState.set(key, entry);
    
    // Update branch head
    const branchInfo = this.branches.get(branch)!;
    branchInfo.head_version = Math.max(branchInfo.head_version, version);
    
    // Log change
    const change: StateChange = {
      type: 'set',
      key,
      old_value: existing?.value,
      new_value: value,
      version,
      timestamp: now,
      agent_id: agentId,
      branch,
    };
    this.changeLog.push(change);
    this.notifyChange(change);
    
    return entry;
  }
  
  /**
   * Delete a value
   */
  async delete(key: string, options?: {
    branch?: string;
    agent_id?: string;
  }): Promise<boolean> {
    const branch = options?.branch || 'main';
    const agentId = options?.agent_id || 'unknown';
    
    const branchState = this.state.get(branch);
    if (!branchState) return false;
    
    const existing = branchState.get(key);
    if (!existing) return false;
    
    // Check for lock
    const lock = this.locks.get(key);
    if (lock && lock.type === 'exclusive' && lock.holder !== agentId) {
      throw new Error(`Key ${key} is exclusively locked by ${lock.holder}`);
    }
    
    branchState.delete(key);
    
    // Log change
    const change: StateChange = {
      type: 'delete',
      key,
      old_value: existing.value,
      version: existing.version,
      timestamp: new Date(),
      agent_id: agentId,
      branch,
    };
    this.changeLog.push(change);
    this.notifyChange(change);
    
    return true;
  }
  
  /**
   * List all keys
   */
  async keys(options?: { branch?: string; prefix?: string }): Promise<string[]> {
    const branch = options?.branch || 'main';
    const branchState = this.state.get(branch);
    if (!branchState) return [];
    
    let keys = Array.from(branchState.keys());
    
    if (options?.prefix) {
      keys = keys.filter(k => k.startsWith(options.prefix!));
    }
    
    return keys;
  }
  
  /**
   * Check if key exists
   */
  async has(key: string, options?: { branch?: string }): Promise<boolean> {
    const branch = options?.branch || 'main';
    const branchState = this.state.get(branch);
    return branchState?.has(key) || false;
  }
  
  // ===========================================================================
  // Locking
  // ===========================================================================
  
  /**
   * Acquire a lock
   */
  async acquireLock(request: LockRequest): Promise<LockResult> {
    const { key, holder, type = 'exclusive', duration_ms = this.defaultLockDuration, wait_ms = 0 } = request;
    
    const existingLock = this.locks.get(key);
    
    // Check if already locked
    if (existingLock) {
      // Check if expired
      if (new Date() > existingLock.expires_at) {
        this.locks.delete(key);
      } else {
        // Locked by someone else
        if (existingLock.holder !== holder) {
          // Can acquire shared lock if existing is shared
          if (type === 'shared' && existingLock.type === 'shared') {
            // Allow multiple shared locks (simplified: just extend)
          } else {
            // Wait or fail
            if (wait_ms > 0) {
              return {
                acquired: false,
                reason: 'Key is locked',
                current_holder: existingLock.holder,
                retry_after_ms: Math.min(wait_ms, existingLock.expires_at.getTime() - Date.now()),
              };
            }
            return {
              acquired: false,
              reason: 'Key is locked',
              current_holder: existingLock.holder,
            };
          }
        } else {
          // Same holder - renew
          existingLock.expires_at = new Date(Date.now() + duration_ms);
          existingLock.renewed_count++;
          return { acquired: true, lock: existingLock };
        }
      }
    }
    
    // Create new lock
    const lock: Lock = {
      id: `lock_${crypto.randomUUID()}`,
      key,
      type,
      holder,
      acquired_at: new Date(),
      expires_at: new Date(Date.now() + duration_ms),
      renewed_count: 0,
    };
    
    this.locks.set(key, lock);
    
    return { acquired: true, lock };
  }
  
  /**
   * Release a lock
   */
  async releaseLock(key: string, holder: string): Promise<boolean> {
    const lock = this.locks.get(key);
    
    if (!lock) return false;
    if (lock.holder !== holder) {
      throw new Error(`Lock on ${key} is held by ${lock.holder}, not ${holder}`);
    }
    
    this.locks.delete(key);
    return true;
  }
  
  /**
   * Renew a lock
   */
  async renewLock(key: string, holder: string, duration_ms?: number): Promise<LockResult> {
    const lock = this.locks.get(key);
    
    if (!lock) {
      return { acquired: false, reason: 'Lock not found' };
    }
    
    if (lock.holder !== holder) {
      return { acquired: false, reason: 'Lock held by another holder', current_holder: lock.holder };
    }
    
    lock.expires_at = new Date(Date.now() + (duration_ms || this.defaultLockDuration));
    lock.renewed_count++;
    
    return { acquired: true, lock };
  }
  
  /**
   * Check if key is locked
   */
  isLocked(key: string): { locked: boolean; holder?: string; expires_at?: Date } {
    const lock = this.locks.get(key);
    
    if (!lock) {
      return { locked: false };
    }
    
    if (new Date() > lock.expires_at) {
      this.locks.delete(key);
      return { locked: false };
    }
    
    return { locked: true, holder: lock.holder, expires_at: lock.expires_at };
  }
  
  /**
   * Get all locks held by an agent
   */
  getLocksForHolder(holder: string): Lock[] {
    return Array.from(this.locks.values()).filter(l => l.holder === holder);
  }
  
  /**
   * Release all locks held by an agent
   */
  async releaseAllLocks(holder: string): Promise<number> {
    let released = 0;
    
    for (const [key, lock] of this.locks) {
      if (lock.holder === holder) {
        this.locks.delete(key);
        released++;
      }
    }
    
    return released;
  }
  
  // ===========================================================================
  // Branching
  // ===========================================================================
  
  /**
   * Create a branch
   */
  async createBranch(name: string, options?: {
    parent?: string;
    created_by?: string;
  }): Promise<Branch> {
    if (this.branches.has(name)) {
      throw new Error(`Branch ${name} already exists`);
    }
    
    const parent = options?.parent || 'main';
    const parentBranch = this.branches.get(parent);
    if (!parentBranch) {
      throw new Error(`Parent branch ${parent} does not exist`);
    }
    
    const parentState = this.state.get(parent)!;
    
    // Create branch info
    const branch: Branch = {
      name,
      parent,
      created_at: new Date(),
      created_by: options?.created_by || 'unknown',
      head_version: parentBranch.head_version,
      merged: false,
    };
    
    this.branches.set(name, branch);
    
    // Copy state from parent
    const branchState = new Map<string, StateEntry>();
    for (const [key, entry] of parentState) {
      branchState.set(key, { ...entry, branch: name });
    }
    this.state.set(name, branchState);
    
    return branch;
  }
  
  /**
   * List branches
   */
  listBranches(): Branch[] {
    return Array.from(this.branches.values());
  }
  
  /**
   * Get branch info
   */
  getBranch(name: string): Branch | undefined {
    return this.branches.get(name);
  }
  
  /**
   * Merge branch into target
   */
  async merge(source: string, target: string, options?: {
    agent_id?: string;
    resolution?: ConflictResolution;
  }): Promise<MergeResult> {
    const sourceBranch = this.branches.get(source);
    const targetBranch = this.branches.get(target);
    
    if (!sourceBranch) throw new Error(`Source branch ${source} does not exist`);
    if (!targetBranch) throw new Error(`Target branch ${target} does not exist`);
    if (sourceBranch.merged) throw new Error(`Branch ${source} already merged`);
    
    const sourceState = this.state.get(source)!;
    const targetState = this.state.get(target)!;
    
    const conflicts: Conflict[] = [];
    const mergedKeys: string[] = [];
    const resolution = options?.resolution || this.conflictResolution;
    
    // Find all keys
    const allKeys = new Set([...sourceState.keys(), ...targetState.keys()]);
    
    for (const key of allKeys) {
      const sourceEntry = sourceState.get(key);
      const targetEntry = targetState.get(key);
      
      // Key only in source - add to target
      if (sourceEntry && !targetEntry) {
        targetState.set(key, { ...sourceEntry, branch: target });
        mergedKeys.push(key);
        continue;
      }
      
      // Key only in target - keep
      if (!sourceEntry && targetEntry) {
        continue;
      }
      
      // Both have key - check for conflict
      if (sourceEntry && targetEntry) {
        if (sourceEntry.hash === targetEntry.hash) {
          // Same value, no conflict
          continue;
        }
        
        // Conflict!
        const conflict: Conflict = {
          key,
          source_value: sourceEntry.value,
          target_value: targetEntry.value,
          source_version: sourceEntry.version,
          target_version: targetEntry.version,
        };
        
        // Apply resolution strategy
        if (resolution === 'last-write-wins') {
          if (sourceEntry.updated_at > targetEntry.updated_at) {
            targetState.set(key, { ...sourceEntry, branch: target, version: targetEntry.version + 1 });
            mergedKeys.push(key);
          }
          // else keep target
        } else if (resolution === 'first-write-wins') {
          if (sourceEntry.updated_at < targetEntry.updated_at) {
            targetState.set(key, { ...sourceEntry, branch: target, version: targetEntry.version + 1 });
            mergedKeys.push(key);
          }
          // else keep target
        } else if (resolution === 'merge') {
          // Try to merge objects
          if (typeof sourceEntry.value === 'object' && typeof targetEntry.value === 'object') {
            const merged = { ...targetEntry.value, ...sourceEntry.value };
            targetState.set(key, {
              ...targetEntry,
              value: merged,
              version: targetEntry.version + 1,
              updated_at: new Date(),
              hash: crypto.createHash('sha256').update(JSON.stringify(merged)).digest('hex'),
            });
            mergedKeys.push(key);
          } else {
            conflicts.push(conflict);
          }
        } else {
          // Manual resolution needed
          conflicts.push(conflict);
        }
      }
    }
    
    // Mark source as merged if no conflicts
    if (conflicts.length === 0) {
      sourceBranch.merged = true;
      sourceBranch.merged_at = new Date();
    }
    
    return {
      success: conflicts.length === 0,
      conflicts,
      merged_keys: mergedKeys,
      source_branch: source,
      target_branch: target,
    };
  }
  
  /**
   * Resolve conflicts manually
   */
  async resolveConflicts(conflicts: Conflict[], resolutions: Map<string, 'source' | 'target' | any>, options?: {
    source: string;
    target: string;
    agent_id?: string;
  }): Promise<void> {
    if (!options?.source || !options?.target) {
      throw new Error('Source and target branches required');
    }
    
    const sourceState = this.state.get(options.source);
    const targetState = this.state.get(options.target);
    
    if (!sourceState || !targetState) {
      throw new Error('Invalid branches');
    }
    
    for (const conflict of conflicts) {
      const resolution = resolutions.get(conflict.key);
      if (!resolution) continue;
      
      const targetEntry = targetState.get(conflict.key);
      const sourceEntry = sourceState.get(conflict.key);
      
      if (!targetEntry) continue;
      
      let newValue: any;
      if (resolution === 'source' && sourceEntry) {
        newValue = sourceEntry.value;
      } else if (resolution === 'target') {
        continue;  // Keep target
      } else {
        newValue = resolution;  // Custom value
      }
      
      targetState.set(conflict.key, {
        ...targetEntry,
        value: newValue,
        version: targetEntry.version + 1,
        updated_at: new Date(),
        updated_by: options.agent_id || 'unknown',
        hash: crypto.createHash('sha256').update(JSON.stringify(newValue)).digest('hex'),
      });
    }
    
    // Mark source as merged
    const sourceBranch = this.branches.get(options.source);
    if (sourceBranch) {
      sourceBranch.merged = true;
      sourceBranch.merged_at = new Date();
    }
  }
  
  /**
   * Delete a branch
   */
  async deleteBranch(name: string): Promise<boolean> {
    if (name === 'main') {
      throw new Error('Cannot delete main branch');
    }
    
    const branch = this.branches.get(name);
    if (!branch) return false;
    
    this.branches.delete(name);
    this.state.delete(name);
    
    return true;
  }
  
  // ===========================================================================
  // Snapshots
  // ===========================================================================
  
  /**
   * Create a snapshot
   */
  async createSnapshot(options?: { branch?: string }): Promise<StateSnapshot> {
    const branch = options?.branch || 'main';
    const branchState = this.state.get(branch);
    const branchInfo = this.branches.get(branch);
    
    if (!branchState || !branchInfo) {
      throw new Error(`Branch ${branch} does not exist`);
    }
    
    const snapshot: StateSnapshot = {
      id: `snap_${crypto.randomUUID()}`,
      branch,
      timestamp: new Date(),
      entries: new Map(branchState),
      version: branchInfo.head_version,
    };
    
    this.snapshots.set(snapshot.id, snapshot);
    
    return snapshot;
  }
  
  /**
   * Restore from snapshot
   */
  async restoreSnapshot(snapshotId: string): Promise<void> {
    const snapshot = this.snapshots.get(snapshotId);
    if (!snapshot) {
      throw new Error(`Snapshot ${snapshotId} not found`);
    }
    
    // Replace branch state
    this.state.set(snapshot.branch, new Map(snapshot.entries));
    
    // Update branch version
    const branch = this.branches.get(snapshot.branch);
    if (branch) {
      branch.head_version = snapshot.version;
    }
  }
  
  /**
   * List snapshots
   */
  listSnapshots(branch?: string): StateSnapshot[] {
    const snapshots = Array.from(this.snapshots.values());
    
    if (branch) {
      return snapshots.filter(s => s.branch === branch);
    }
    
    return snapshots;
  }
  
  /**
   * Delete a snapshot
   */
  deleteSnapshot(snapshotId: string): boolean {
    return this.snapshots.delete(snapshotId);
  }
  
  // ===========================================================================
  // Change Tracking
  // ===========================================================================
  
  /**
   * Get change history
   */
  getChanges(options?: {
    branch?: string;
    key?: string;
    agent_id?: string;
    since?: Date;
    limit?: number;
  }): StateChange[] {
    let changes = [...this.changeLog];
    
    if (options?.branch) {
      changes = changes.filter(c => c.branch === options.branch);
    }
    if (options?.key) {
      changes = changes.filter(c => c.key === options.key);
    }
    if (options?.agent_id) {
      changes = changes.filter(c => c.agent_id === options.agent_id);
    }
    if (options?.since) {
      changes = changes.filter(c => c.timestamp >= options.since!);
    }
    
    // Sort by timestamp descending
    changes.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
    
    if (options?.limit) {
      changes = changes.slice(0, options.limit);
    }
    
    return changes;
  }
  
  /**
   * Subscribe to changes
   */
  onChange(callback: (change: StateChange) => void): () => void {
    this.changeCallbacks.push(callback);
    
    return () => {
      const index = this.changeCallbacks.indexOf(callback);
      if (index !== -1) this.changeCallbacks.splice(index, 1);
    };
  }
  
  private notifyChange(change: StateChange): void {
    for (const cb of this.changeCallbacks) {
      try {
        cb(change);
      } catch (e) {
        // Ignore
      }
    }
  }
  
  // ===========================================================================
  // Utilities
  // ===========================================================================
  
  private cleanupExpiredLocks(): void {
    const now = new Date();
    
    for (const [key, lock] of this.locks) {
      if (now > lock.expires_at) {
        this.locks.delete(key);
      }
    }
  }
  
  /**
   * Get state statistics
   */
  getStats(): {
    branches: number;
    total_keys: number;
    active_locks: number;
    snapshots: number;
    changes_logged: number;
  } {
    let totalKeys = 0;
    for (const branchState of this.state.values()) {
      totalKeys += branchState.size;
    }
    
    return {
      branches: this.branches.size,
      total_keys: totalKeys,
      active_locks: this.locks.size,
      snapshots: this.snapshots.size,
      changes_logged: this.changeLog.length,
    };
  }
  
  /**
   * Export state for backup
   */
  async exportState(branch?: string): Promise<string> {
    const exportData: any = {
      exported_at: new Date(),
      branches: branch ? [branch] : Array.from(this.branches.keys()),
      data: {},
    };
    
    for (const branchName of exportData.branches) {
      const branchState = this.state.get(branchName);
      if (branchState) {
        exportData.data[branchName] = Object.fromEntries(branchState);
      }
    }
    
    return JSON.stringify(exportData, null, 2);
  }
  
  /**
   * Import state from backup
   */
  async importState(data: string, options?: { merge?: boolean }): Promise<{ imported_keys: number }> {
    const importData = JSON.parse(data);
    let importedKeys = 0;
    
    for (const branchName of Object.keys(importData.data)) {
      if (!this.branches.has(branchName) && branchName !== 'main') {
        await this.createBranch(branchName);
      }
      
      const branchState = this.state.get(branchName)!;
      const entries = importData.data[branchName];
      
      for (const [key, entry] of Object.entries(entries)) {
        if (options?.merge && branchState.has(key)) {
          continue;  // Skip existing
        }
        branchState.set(key, entry as StateEntry);
        importedKeys++;
      }
    }
    
    return { imported_keys: importedKeys };
  }
}

export default StateManager;
