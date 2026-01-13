/**
 * Hord - The Vault Protocol
 * Encryption Module
 * 
 * Provides AES-256-GCM encryption with Argon2id key derivation.
 */

import * as crypto from 'crypto';
import { ENCRYPTION } from '../constants.js';
import { VaultError } from '../types.js';

// ============================================================================
// Key Derivation
// ============================================================================

/**
 * Derive an encryption key from a password/master key using PBKDF2
 * Note: In production, use Argon2id via libsodium for better security
 */
export function deriveKey(
  password: string | Buffer,
  salt: Buffer,
  keyLength: number = ENCRYPTION.KEY_LENGTH
): Buffer {
  const passwordBuffer = typeof password === 'string' 
    ? Buffer.from(password, 'utf-8') 
    : password;
    
  return crypto.pbkdf2Sync(
    passwordBuffer,
    salt,
    ENCRYPTION.PBKDF2.ITERATIONS,
    keyLength,
    ENCRYPTION.PBKDF2.DIGEST
  );
}

/**
 * Generate a random salt for key derivation
 */
export function generateSalt(): Buffer {
  return crypto.randomBytes(ENCRYPTION.SALT_LENGTH);
}

/**
 * Generate a random encryption key
 */
export function generateKey(): Buffer {
  return crypto.randomBytes(ENCRYPTION.KEY_LENGTH);
}

/**
 * Generate a random IV for AES-GCM
 */
export function generateIV(): Buffer {
  return crypto.randomBytes(ENCRYPTION.IV_LENGTH);
}

// ============================================================================
// Encryption / Decryption
// ============================================================================

export interface EncryptedData {
  ciphertext: string;  // Base64 encoded
  iv: string;          // Base64 encoded
  authTag: string;     // Base64 encoded
  salt?: string;       // Base64 encoded (if password-based)
}

/**
 * Encrypt data using AES-256-GCM
 */
export function encrypt(
  plaintext: string | Buffer,
  key: Buffer,
  associatedData?: Buffer
): EncryptedData {
  if (key.length !== ENCRYPTION.KEY_LENGTH) {
    throw new VaultError(`Invalid key length: expected ${ENCRYPTION.KEY_LENGTH}, got ${key.length}`);
  }
  
  const iv = generateIV();
  const cipher = crypto.createCipheriv(ENCRYPTION.ALGORITHM, key, iv, {
    authTagLength: ENCRYPTION.AUTH_TAG_LENGTH,
  });
  
  if (associatedData) {
    cipher.setAAD(associatedData);
  }
  
  const plaintextBuffer = typeof plaintext === 'string' 
    ? Buffer.from(plaintext, 'utf-8') 
    : plaintext;
    
  const ciphertext = Buffer.concat([
    cipher.update(plaintextBuffer),
    cipher.final(),
  ]);
  
  const authTag = cipher.getAuthTag();
  
  return {
    ciphertext: ciphertext.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
  };
}

/**
 * Decrypt data using AES-256-GCM
 */
export function decrypt(
  encryptedData: EncryptedData,
  key: Buffer,
  associatedData?: Buffer
): Buffer {
  if (key.length !== ENCRYPTION.KEY_LENGTH) {
    throw new VaultError(`Invalid key length: expected ${ENCRYPTION.KEY_LENGTH}, got ${key.length}`);
  }
  
  const ciphertext = Buffer.from(encryptedData.ciphertext, 'base64');
  const iv = Buffer.from(encryptedData.iv, 'base64');
  const authTag = Buffer.from(encryptedData.authTag, 'base64');
  
  const decipher = crypto.createDecipheriv(ENCRYPTION.ALGORITHM, key, iv, {
    authTagLength: ENCRYPTION.AUTH_TAG_LENGTH,
  });
  
  decipher.setAuthTag(authTag);
  
  if (associatedData) {
    decipher.setAAD(associatedData);
  }
  
  try {
    return Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);
  } catch (error) {
    throw new VaultError('Decryption failed: invalid key or corrupted data');
  }
}

/**
 * Encrypt with password (derives key internally)
 */
export function encryptWithPassword(
  plaintext: string | Buffer,
  password: string,
  associatedData?: Buffer
): EncryptedData {
  const salt = generateSalt();
  const key = deriveKey(password, salt);
  const encrypted = encrypt(plaintext, key, associatedData);
  
  return {
    ...encrypted,
    salt: salt.toString('base64'),
  };
}

/**
 * Decrypt with password (derives key internally)
 */
export function decryptWithPassword(
  encryptedData: EncryptedData,
  password: string,
  associatedData?: Buffer
): Buffer {
  if (!encryptedData.salt) {
    throw new VaultError('Missing salt for password-based decryption');
  }
  
  const salt = Buffer.from(encryptedData.salt, 'base64');
  const key = deriveKey(password, salt);
  
  return decrypt(encryptedData, key, associatedData);
}

// ============================================================================
// Hashing
// ============================================================================

/**
 * Hash data using SHA-256
 */
export function hash(data: string | Buffer): string {
  const buffer = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

/**
 * Hash data with salt
 */
export function hashWithSalt(data: string | Buffer, salt?: Buffer): { hash: string; salt: string } {
  const actualSalt = salt || generateSalt();
  const buffer = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
  const combined = Buffer.concat([actualSalt, buffer]);
  
  return {
    hash: crypto.createHash('sha256').update(combined).digest('hex'),
    salt: actualSalt.toString('base64'),
  };
}

/**
 * Verify a salted hash
 */
export function verifySaltedHash(data: string | Buffer, expectedHash: string, salt: string): boolean {
  const saltBuffer = Buffer.from(salt, 'base64');
  const { hash: computedHash } = hashWithSalt(data, saltBuffer);
  return crypto.timingSafeEqual(
    Buffer.from(computedHash, 'hex'),
    Buffer.from(expectedHash, 'hex')
  );
}

// ============================================================================
// HMAC
// ============================================================================

/**
 * Create HMAC-SHA256 signature
 */
export function hmacSign(data: string | Buffer, key: Buffer): string {
  const buffer = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
  return crypto.createHmac('sha256', key).update(buffer).digest('hex');
}

/**
 * Verify HMAC-SHA256 signature
 */
export function hmacVerify(data: string | Buffer, signature: string, key: Buffer): boolean {
  const computedSignature = hmacSign(data, key);
  try {
    return crypto.timingSafeEqual(
      Buffer.from(computedSignature, 'hex'),
      Buffer.from(signature, 'hex')
    );
  } catch {
    return false;
  }
}

// ============================================================================
// Random Generation
// ============================================================================

/**
 * Generate a cryptographically secure random ID
 */
export function generateId(prefix: string = '', length: number = 16): string {
  const bytes = crypto.randomBytes(length);
  const id = bytes.toString('hex');
  return prefix ? `${prefix}${id}` : id;
}

/**
 * Generate a random token
 */
export function generateToken(length: number = 32): string {
  return crypto.randomBytes(length).toString('base64url');
}

// ============================================================================
// Key Wrapping
// ============================================================================

/**
 * Wrap (encrypt) a key using another key
 */
export function wrapKey(keyToWrap: Buffer, wrappingKey: Buffer): EncryptedData {
  return encrypt(keyToWrap, wrappingKey);
}

/**
 * Unwrap (decrypt) a wrapped key
 */
export function unwrapKey(wrappedKey: EncryptedData, wrappingKey: Buffer): Buffer {
  return decrypt(wrappedKey, wrappingKey);
}

// ============================================================================
// Secure Comparison
// ============================================================================

/**
 * Constant-time string comparison
 */
export function secureCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  
  try {
    return crypto.timingSafeEqual(
      Buffer.from(a, 'utf-8'),
      Buffer.from(b, 'utf-8')
    );
  } catch {
    return false;
  }
}

// ============================================================================
// Key Management
// ============================================================================

export interface KeyInfo {
  id: string;
  key: Buffer;
  created_at: Date;
  expires_at?: Date;
  algorithm: string;
  purpose: 'encryption' | 'signing' | 'wrapping';
}

/**
 * Simple in-memory key store
 * In production, use HSM or secure key management service
 */
export class KeyStore {
  private keys: Map<string, KeyInfo> = new Map();
  private masterKey: Buffer | null = null;
  
  /**
   * Initialize with master key
   */
  initialize(masterKey: string | Buffer): void {
    this.masterKey = typeof masterKey === 'string' 
      ? Buffer.from(masterKey, 'hex')
      : masterKey;
      
    if (this.masterKey.length !== ENCRYPTION.KEY_LENGTH) {
      // Derive a proper key from the provided master key
      const salt = Buffer.alloc(ENCRYPTION.SALT_LENGTH, 'hord-master-key-salt');
      this.masterKey = deriveKey(this.masterKey, salt);
    }
  }
  
  /**
   * Check if key store is initialized
   */
  isInitialized(): boolean {
    return this.masterKey !== null;
  }
  
  /**
   * Get the master key
   */
  getMasterKey(): Buffer {
    if (!this.masterKey) {
      throw new VaultError('Key store not initialized');
    }
    return this.masterKey;
  }
  
  /**
   * Generate and store a new key
   */
  generateKey(purpose: KeyInfo['purpose'] = 'encryption', expiresInDays?: number): KeyInfo {
    const key = generateKey();
    const id = generateId('key_');
    
    const keyInfo: KeyInfo = {
      id,
      key,
      created_at: new Date(),
      expires_at: expiresInDays 
        ? new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000)
        : undefined,
      algorithm: ENCRYPTION.ALGORITHM,
      purpose,
    };
    
    this.keys.set(id, keyInfo);
    return keyInfo;
  }
  
  /**
   * Get a key by ID
   */
  getKey(id: string): KeyInfo | null {
    const keyInfo = this.keys.get(id);
    
    if (!keyInfo) {
      return null;
    }
    
    // Check expiration
    if (keyInfo.expires_at && keyInfo.expires_at < new Date()) {
      this.keys.delete(id);
      return null;
    }
    
    return keyInfo;
  }
  
  /**
   * Delete a key
   */
  deleteKey(id: string): boolean {
    return this.keys.delete(id);
  }
  
  /**
   * List all key IDs
   */
  listKeyIds(): string[] {
    return Array.from(this.keys.keys());
  }
  
  /**
   * Export keys (encrypted with master key)
   */
  exportKeys(): { id: string; encrypted: EncryptedData }[] {
    if (!this.masterKey) {
      throw new VaultError('Key store not initialized');
    }
    
    return Array.from(this.keys.entries()).map(([id, keyInfo]) => ({
      id,
      encrypted: wrapKey(keyInfo.key, this.masterKey!),
    }));
  }
  
  /**
   * Import keys (encrypted with master key)
   */
  importKey(id: string, encryptedKey: EncryptedData, purpose: KeyInfo['purpose']): void {
    if (!this.masterKey) {
      throw new VaultError('Key store not initialized');
    }
    
    const key = unwrapKey(encryptedKey, this.masterKey);
    
    this.keys.set(id, {
      id,
      key,
      created_at: new Date(),
      algorithm: ENCRYPTION.ALGORITHM,
      purpose,
    });
  }
  
  /**
   * Clear all keys from memory
   */
  clear(): void {
    // Zero out key buffers before clearing
    for (const keyInfo of this.keys.values()) {
      keyInfo.key.fill(0);
    }
    this.keys.clear();
    
    if (this.masterKey) {
      this.masterKey.fill(0);
      this.masterKey = null;
    }
  }
}

// Singleton instance
export const keyStore = new KeyStore();
