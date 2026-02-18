/**
 * Yoxallismus Vault Cipher
 * 
 * A dual-mechanism obfuscation layer combining:
 * - Tumbler: Revolving permutation (like a vault dial)
 * - Deadbolt: Entropy injection with XOR masking (like a manual lock)
 * 
 * "Through obscurity we find clarity" - Yoxallismus Principle
 */

import * as crypto from 'crypto';

// =============================================================================
// Types
// =============================================================================

export interface YoxallismusConfig {
  /** Master key for derivation */
  key: string;
  
  /** Number of tumbler rotations (1-12, default 7) */
  tumblers?: number;
  
  /** Entropy injection ratio (0.1-0.5, default 0.2 = 20% decoy bytes) */
  entropy_ratio?: number;
  
  /** Enable revolving mode - permutation changes per block */
  revolving?: boolean;
  
  /** Block size for processing (default 64 bytes) */
  block_size?: number;
}

export interface VaultState {
  tumbler_positions: number[];
  deadbolt_mask: Buffer;
  entropy_seed: Buffer;
  revolution: number;
}

// =============================================================================
// Yoxallismus Vault Cipher
// =============================================================================

export class YoxallismusCipher {
  private masterKey: Buffer;
  private tumblers: number;
  private entropyRatio: number;
  private revolving: boolean;
  private blockSize: number;
  
  // Derived keys
  private tumblerKey: Buffer;
  private deadboltKey: Buffer;
  private entropyKey: Buffer;
  
  constructor(config: YoxallismusConfig) {
    this.masterKey = crypto.scryptSync(config.key, 'yoxallismus-vault', 32);
    this.tumblers = Math.min(12, Math.max(1, config.tumblers || 7));
    this.entropyRatio = Math.min(0.5, Math.max(0.1, config.entropy_ratio || 0.2));
    this.revolving = config.revolving !== false;
    this.blockSize = config.block_size || 64;
    
    // Derive separate keys for each mechanism
    this.tumblerKey = this.deriveKey('tumbler');
    this.deadboltKey = this.deriveKey('deadbolt');
    this.entropyKey = this.deriveKey('entropy');
  }
  
  // ===========================================================================
  // Public API
  // ===========================================================================
  
  /**
   * Lock data through the vault (encode/obfuscate)
   */
  lock(data: Buffer | string): Buffer {
    const input = Buffer.isBuffer(data) ? data : Buffer.from(data);
    const state = this.initializeState(input);
    
    // Step 1: Inject entropy (decoy bytes)
    const withEntropy = this.injectEntropy(input, state);
    
    // Step 2: Apply tumbler permutation
    const permuted = this.applyTumblers(withEntropy, state);
    
    // Step 3: Apply deadbolt XOR mask
    const locked = this.applyDeadbolt(permuted, state);
    
    // Prepend state header for unlocking
    return this.packWithHeader(locked, state);
  }
  
  /**
   * Unlock data from the vault (decode/reveal)
   */
  unlock(data: Buffer): Buffer {
    // Extract state from header
    const { payload, state } = this.unpackHeader(data);
    
    // Step 1: Remove deadbolt
    const unbolted = this.removeDeadbolt(payload, state);
    
    // Step 2: Reverse tumbler permutation
    const unpermuted = this.reverseTumblers(unbolted, state);
    
    // Step 3: Remove entropy (decoy bytes)
    const original = this.removeEntropy(unpermuted, state);
    
    return original;
  }
  
  /**
   * Quick encode for string data
   */
  encode(data: string): string {
    return this.lock(data).toString('base64');
  }
  
  /**
   * Quick decode for string data
   */
  decode(data: string): string {
    return this.unlock(Buffer.from(data, 'base64')).toString('utf8');
  }
  
  // ===========================================================================
  // Tumbler Mechanism (Revolving Permutation)
  // ===========================================================================
  
  /**
   * Initialize vault state based on input
   */
  private initializeState(input: Buffer): VaultState {
    // Generate tumbler positions from key + input hash
    const inputHash = crypto.createHash('sha256').update(input).digest();
    const combined = Buffer.concat([this.tumblerKey, inputHash]);
    const seed = crypto.createHash('sha256').update(combined).digest();
    
    const tumblerPositions: number[] = [];
    for (let i = 0; i < this.tumblers; i++) {
      // Each tumbler has 256 positions (like a combination lock)
      tumblerPositions.push(seed[i % seed.length]);
    }
    
    // Generate deadbolt mask
    const deadboltMask = crypto.createHmac('sha512', this.deadboltKey)
      .update(seed)
      .digest();
    
    // Generate entropy seed
    const entropySeed = crypto.createHmac('sha256', this.entropyKey)
      .update(seed)
      .digest();
    
    return {
      tumbler_positions: tumblerPositions,
      deadbolt_mask: deadboltMask,
      entropy_seed: entropySeed,
      revolution: 0,
    };
  }
  
  /**
   * Apply tumbler permutation - revolves through positions
   */
  private applyTumblers(data: Buffer, state: VaultState): Buffer {
    const result = Buffer.alloc(data.length);
    const blockCount = Math.ceil(data.length / this.blockSize);
    
    for (let block = 0; block < blockCount; block++) {
      const start = block * this.blockSize;
      const end = Math.min(start + this.blockSize, data.length);
      const blockData = data.slice(start, end);
      
      // Get permutation for this block
      const permutation = this.generatePermutation(blockData.length, state, block);
      
      // Apply permutation
      for (let i = 0; i < blockData.length; i++) {
        result[start + permutation[i]] = blockData[i];
      }
      
      // Revolve tumblers for next block
      if (this.revolving) {
        this.revolveTumblers(state);
      }
    }
    
    return result;
  }
  
  /**
   * Reverse tumbler permutation
   */
  private reverseTumblers(data: Buffer, state: VaultState): Buffer {
    const result = Buffer.alloc(data.length);
    const blockCount = Math.ceil(data.length / this.blockSize);
    
    // Reset revolution counter
    state.revolution = 0;
    
    for (let block = 0; block < blockCount; block++) {
      const start = block * this.blockSize;
      const end = Math.min(start + this.blockSize, data.length);
      const blockData = data.slice(start, end);
      
      // Get permutation for this block
      const permutation = this.generatePermutation(blockData.length, state, block);
      
      // Reverse permutation
      for (let i = 0; i < blockData.length; i++) {
        result[start + i] = blockData[permutation[i]];
      }
      
      // Revolve tumblers for next block
      if (this.revolving) {
        this.revolveTumblers(state);
      }
    }
    
    return result;
  }
  
  /**
   * Generate permutation array based on tumbler state
   */
  private generatePermutation(length: number, state: VaultState, blockIndex: number): number[] {
    // Create seed from tumbler positions and block index
    const seedData = Buffer.concat([
      Buffer.from(state.tumbler_positions),
      Buffer.from([blockIndex & 0xff, (blockIndex >> 8) & 0xff]),
      this.tumblerKey.slice(0, 16)
    ]);
    
    const hash = crypto.createHash('sha256').update(seedData).digest();
    
    // Fisher-Yates shuffle seeded by hash
    const indices = Array.from({ length }, (_, i) => i);
    
    for (let i = length - 1; i > 0; i--) {
      const hashByte = hash[i % hash.length];
      const j = (hashByte + state.tumbler_positions[i % this.tumblers]) % (i + 1);
      [indices[i], indices[j]] = [indices[j], indices[i]];
    }
    
    return indices;
  }
  
  /**
   * Revolve tumbler positions (like spinning a dial)
   */
  private revolveTumblers(state: VaultState): void {
    state.revolution++;
    
    for (let i = 0; i < this.tumblers; i++) {
      // Each tumbler revolves at different speed based on position
      const speed = (i + 1) * 7 + state.revolution;
      state.tumbler_positions[i] = (state.tumbler_positions[i] + speed) & 0xff;
    }
  }
  
  // ===========================================================================
  // Deadbolt Mechanism (XOR Masking)
  // ===========================================================================
  
  /**
   * Apply deadbolt XOR mask
   */
  private applyDeadbolt(data: Buffer, state: VaultState): Buffer {
    const result = Buffer.alloc(data.length);
    const mask = this.expandMask(state.deadbolt_mask, data.length);
    
    for (let i = 0; i < data.length; i++) {
      // Position-dependent transformation
      const positionKey = (i * 31 + state.tumbler_positions[i % this.tumblers]) & 0xff;
      result[i] = data[i] ^ mask[i] ^ positionKey;
    }
    
    return result;
  }
  
  /**
   * Remove deadbolt XOR mask
   */
  private removeDeadbolt(data: Buffer, state: VaultState): Buffer {
    // XOR is its own inverse
    return this.applyDeadbolt(data, state);
  }
  
  /**
   * Expand mask to required length
   */
  private expandMask(mask: Buffer, length: number): Buffer {
    const result = Buffer.alloc(length);
    
    for (let i = 0; i < length; i++) {
      // Rotate and combine mask bytes
      const idx1 = i % mask.length;
      const idx2 = (i * 7) % mask.length;
      result[i] = mask[idx1] ^ mask[idx2] ^ (i & 0xff);
    }
    
    return result;
  }
  
  // ===========================================================================
  // Entropy Mechanism (Decoy Injection)
  // ===========================================================================
  
  /**
   * Inject entropy (decoy bytes) at deterministic positions
   */
  private injectEntropy(data: Buffer, state: VaultState): Buffer {
    const decoyCount = Math.floor(data.length * this.entropyRatio);
    const totalLength = data.length + decoyCount;
    const result = Buffer.alloc(totalLength);
    
    // Generate decoy positions
    const decoyPositions = this.generateDecoyPositions(data.length, decoyCount, state);
    
    // Generate decoy bytes
    const decoys = this.generateDecoys(decoyCount, state);
    
    let dataIdx = 0;
    let decoyIdx = 0;
    
    for (let i = 0; i < totalLength; i++) {
      if (decoyPositions.has(i)) {
        result[i] = decoys[decoyIdx++];
      } else {
        result[i] = data[dataIdx++];
      }
    }
    
    return result;
  }
  
  /**
   * Remove entropy (decoy bytes)
   */
  private removeEntropy(data: Buffer, state: VaultState): Buffer {
    const originalLength = Math.floor(data.length / (1 + this.entropyRatio));
    const decoyCount = data.length - originalLength;
    
    // Generate same decoy positions
    const decoyPositions = this.generateDecoyPositions(originalLength, decoyCount, state);
    
    const result = Buffer.alloc(originalLength);
    let resultIdx = 0;
    
    for (let i = 0; i < data.length; i++) {
      if (!decoyPositions.has(i)) {
        result[resultIdx++] = data[i];
      }
    }
    
    return result.slice(0, resultIdx);
  }
  
  /**
   * Generate deterministic decoy positions
   */
  private generateDecoyPositions(dataLength: number, decoyCount: number, state: VaultState): Set<number> {
    const positions = new Set<number>();
    const totalLength = dataLength + decoyCount;
    
    // Use entropy seed to determine positions
    const hash = crypto.createHmac('sha256', state.entropy_seed)
      .update(Buffer.from([dataLength & 0xff, (dataLength >> 8) & 0xff]))
      .digest();
    
    let attempt = 0;
    while (positions.size < decoyCount && attempt < decoyCount * 10) {
      const hashIdx = attempt % hash.length;
      const position = (hash[hashIdx] + attempt * 37) % totalLength;
      positions.add(position);
      attempt++;
    }
    
    return positions;
  }
  
  /**
   * Generate decoy bytes (look like real encrypted data)
   */
  private generateDecoys(count: number, state: VaultState): Buffer {
    const decoys = Buffer.alloc(count);
    
    for (let i = 0; i < count; i++) {
      // Make decoys look like encrypted bytes
      const seed = state.entropy_seed[i % state.entropy_seed.length];
      const tumbler = state.tumbler_positions[i % this.tumblers];
      decoys[i] = (seed ^ tumbler ^ (i * 13)) & 0xff;
    }
    
    return decoys;
  }
  
  // ===========================================================================
  // Header Packing
  // ===========================================================================
  
  /**
   * Pack data with state header
   */
  private packWithHeader(data: Buffer, state: VaultState): Buffer {
    // Header: magic(4) + version(1) + tumblers(1) + ratio(1) + revolving(1) + positions(tumblers) + entropyHash(8)
    const headerSize = 8 + this.tumblers + 8;
    const header = Buffer.alloc(headerSize);
    
    // Magic bytes: "YXLS" (Yoxallismus)
    header.write('YXLS', 0);
    header[4] = 1; // Version
    header[5] = this.tumblers;
    header[6] = Math.floor(this.entropyRatio * 100);
    header[7] = this.revolving ? 1 : 0;
    
    // Store tumbler positions
    for (let i = 0; i < this.tumblers; i++) {
      header[8 + i] = state.tumbler_positions[i];
    }
    
    // Store entropy hash for verification
    const entropyHash = crypto.createHash('sha256')
      .update(state.entropy_seed)
      .digest()
      .slice(0, 8);
    entropyHash.copy(header, 8 + this.tumblers);
    
    return Buffer.concat([header, data]);
  }
  
  /**
   * Unpack header and extract state
   */
  private unpackHeader(data: Buffer): { payload: Buffer; state: VaultState } {
    // Verify magic
    const magic = data.slice(0, 4).toString();
    if (magic !== 'YXLS') {
      throw new Error('Invalid Yoxallismus data: bad magic');
    }
    
    const version = data[4];
    if (version !== 1) {
      throw new Error(`Unsupported Yoxallismus version: ${version}`);
    }
    
    const tumblers = data[5];
    const headerSize = 8 + tumblers + 8;
    
    // Extract tumbler positions
    const tumblerPositions: number[] = [];
    for (let i = 0; i < tumblers; i++) {
      tumblerPositions.push(data[8 + i]);
    }
    
    // Reconstruct state
    const state: VaultState = {
      tumbler_positions: tumblerPositions,
      deadbolt_mask: crypto.createHmac('sha512', this.deadboltKey)
        .update(Buffer.from(tumblerPositions))
        .digest(),
      entropy_seed: crypto.createHmac('sha256', this.entropyKey)
        .update(Buffer.from(tumblerPositions))
        .digest(),
      revolution: 0,
    };
    
    return {
      payload: data.slice(headerSize),
      state,
    };
  }
  
  // ===========================================================================
  // Utilities
  // ===========================================================================
  
  /**
   * Derive a key for a specific mechanism
   */
  private deriveKey(purpose: string): Buffer {
    return crypto.createHmac('sha256', this.masterKey)
      .update(`yoxallismus:${purpose}`)
      .digest();
  }
  
  /**
   * Get cipher info
   */
  getInfo(): {
    tumblers: number;
    entropy_ratio: number;
    revolving: boolean;
    block_size: number;
  } {
    return {
      tumblers: this.tumblers,
      entropy_ratio: this.entropyRatio,
      revolving: this.revolving,
      block_size: this.blockSize,
    };
  }
}

export default YoxallismusCipher;
