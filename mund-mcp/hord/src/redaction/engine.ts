/**
 * Hord - The Vault Protocol
 * Redaction Engine
 * 
 * Semantic redaction and tokenization for sensitive data.
 */

import type {
  RedactionPolicy,
  RedactionPolicyConfig,
  RedactionRule,
  RedactionStrategy,
  RedactedData,
  TokenizationMap,
  DataType,
  IHordStorage,
} from '../types.js';
import { RedactionError, RedactionStrategyType } from '../types.js';
import { REDACTION } from '../constants.js';
import { generateId, hash, hashWithSalt, encrypt, decrypt, keyStore } from '../vault/encryption.js';

// ============================================================================
// Redaction Engine
// ============================================================================

export class RedactionEngine {
  private storage: IHordStorage;
  private tokenMap: Map<string, TokenizationMap[string]> = new Map();
  
  constructor(storage: IHordStorage) {
    this.storage = storage;
  }
  
  /**
   * Create a new redaction policy
   */
  async createPolicy(config: RedactionPolicyConfig): Promise<RedactionPolicy> {
    const policy: RedactionPolicy = {
      id: config.id || generateId('policy_'),
      name: config.name,
      description: config.description,
      rules: config.rules.map(r => ({ ...r, id: r.id || generateId('rule_') })),
      default_strategy: config.default_strategy,
      created_at: new Date(),
      updated_at: new Date(),
      version: 1,
    };
    
    await this.storage.saveRedactionPolicy(policy);
    return policy;
  }
  
  /**
   * Get a redaction policy
   */
  async getPolicy(policyId: string): Promise<RedactionPolicy | null> {
    return this.storage.getRedactionPolicy(policyId);
  }
  
  /**
   * List all redaction policies
   */
  async listPolicies(): Promise<RedactionPolicy[]> {
    return this.storage.listRedactionPolicies();
  }
  
  /**
   * Redact content according to a policy
   */
  async redact(
    content: unknown,
    policyId: string
  ): Promise<RedactedData> {
    const policy = await this.storage.getRedactionPolicy(policyId);
    if (!policy) {
      throw new RedactionError('Redaction policy not found', { policy_id: policyId });
    }
    
    const redactionMap: Record<string, { original: string; strategy: string }> = {};
    let reversibleCount = 0;
    let irreversibleCount = 0;
    
    // Deep clone content to avoid mutation
    let redactedContent = JSON.parse(JSON.stringify(content));
    
    // Apply each rule
    for (const rule of policy.rules) {
      const result = this.applyRule(redactedContent, rule, redactionMap);
      redactedContent = result.content;
      reversibleCount += result.reversibleCount;
      irreversibleCount += result.irreversibleCount;
    }
    
    // Auto-detect and redact PII if no rules matched
    if (reversibleCount === 0 && irreversibleCount === 0) {
      const autoResult = this.autoRedactPII(redactedContent, redactionMap);
      redactedContent = autoResult.content;
      irreversibleCount += autoResult.count;
    }
    
    // Encrypt redaction map for storage
    const redactionMapEncrypted = this.encryptRedactionMap(redactionMap);
    
    return {
      data: redactedContent,
      redaction_map_encrypted: redactionMapEncrypted,
      policy_id: policyId,
      policy_version: policy.version,
      timestamp: new Date(),
      reversible_count: reversibleCount,
      irreversible_count: irreversibleCount,
    };
  }
  
  /**
   * De-redact content (reverse redaction)
   */
  async deRedact(
    redactedData: RedactedData,
    _capabilityTokenId?: string  // Would verify capability in production
  ): Promise<unknown> {
    // Decrypt redaction map
    const redactionMap = this.decryptRedactionMap(redactedData.redaction_map_encrypted);
    
    // Deep clone
    let content = JSON.parse(JSON.stringify(redactedData.data));
    
    // Reverse tokenizations
    content = this.reverseTokenizations(content, redactionMap);
    
    return content;
  }
  
  /**
   * Tokenize PII in text
   */
  async tokenizePII(text: string): Promise<{ tokenized: string; tokens: string[] }> {
    let result = text;
    const tokens: string[] = [];
    
    for (const [dataType, pattern] of Object.entries(REDACTION.PII_PATTERNS)) {
      result = result.replace(pattern, (match) => {
        const token = this.generateToken(dataType as DataType, match);
        tokens.push(token);
        return token;
      });
    }
    
    return { tokenized: result, tokens };
  }
  
  /**
   * De-tokenize text
   */
  async deTokenize(text: string): Promise<string> {
    let result = text;
    
    // Find all tokens in text
    const tokenPattern = new RegExp(`${REDACTION.TOKEN_PREFIX}[A-Z]+_[a-f0-9]+`, 'g');
    const matches = text.match(tokenPattern) || [];
    
    for (const token of matches) {
      const mapping = await this.storage.getTokenMapping(token);
      if (mapping) {
        const original = this.decryptTokenValue(mapping.original_encrypted);
        result = result.replace(token, original);
      }
    }
    
    return result;
  }
  
  // ============================================================================
  // Private Methods
  // ============================================================================
  
  private applyRule(
    content: unknown,
    rule: RedactionRule,
    redactionMap: Record<string, { original: string; strategy: string }>
  ): { content: unknown; reversibleCount: number; irreversibleCount: number } {
    let reversibleCount = 0;
    let irreversibleCount = 0;
    
    // Handle different field patterns
    if (rule.field_pattern.startsWith('$.')) {
      // JSONPath-like pattern
      const path = rule.field_pattern.slice(2).split('.');
      content = this.redactAtPath(content, path, rule, redactionMap, (r, i) => {
        reversibleCount += r;
        irreversibleCount += i;
      });
    } else if (rule.field_pattern.startsWith('/') && rule.field_pattern.endsWith('/')) {
      // Regex pattern - apply to all string values
      const regex = new RegExp(rule.field_pattern.slice(1, -1), 'g');
      content = this.redactByRegex(content, regex, rule, redactionMap, (r, i) => {
        reversibleCount += r;
        irreversibleCount += i;
      });
    } else {
      // Simple field name
      content = this.redactAtPath(content, [rule.field_pattern], rule, redactionMap, (r, i) => {
        reversibleCount += r;
        irreversibleCount += i;
      });
    }
    
    return { content, reversibleCount, irreversibleCount };
  }
  
  private redactAtPath(
    content: unknown,
    path: string[],
    rule: RedactionRule,
    redactionMap: Record<string, { original: string; strategy: string }>,
    countCallback: (reversible: number, irreversible: number) => void
  ): unknown {
    if (path.length === 0 || content === null || content === undefined) {
      return content;
    }
    
    if (Array.isArray(content)) {
      return content.map(item => 
        this.redactAtPath(item, path, rule, redactionMap, countCallback)
      );
    }
    
    if (typeof content === 'object') {
      const obj = content as Record<string, unknown>;
      const [key, ...rest] = path;
      
      if (key === '*') {
        // Wildcard - apply to all keys
        const result: Record<string, unknown> = {};
        for (const k of Object.keys(obj)) {
          result[k] = this.redactAtPath(obj[k], rest, rule, redactionMap, countCallback);
        }
        return result;
      }
      
      if (key in obj) {
        if (rest.length === 0) {
          // We're at the target field
          const original = String(obj[key]);
          const redacted = this.applyStrategy(original, rule.strategy, rule.data_type);
          
          if (rule.reversible) {
            const mapKey = generateId('redact_');
            redactionMap[mapKey] = { original, strategy: rule.strategy.type };
            countCallback(1, 0);
          } else {
            countCallback(0, 1);
          }
          
          return { ...obj, [key]: redacted };
        } else {
          return {
            ...obj,
            [key]: this.redactAtPath(obj[key], rest, rule, redactionMap, countCallback),
          };
        }
      }
    }
    
    return content;
  }
  
  private redactByRegex(
    content: unknown,
    regex: RegExp,
    rule: RedactionRule,
    redactionMap: Record<string, { original: string; strategy: string }>,
    countCallback: (reversible: number, irreversible: number) => void
  ): unknown {
    if (typeof content === 'string') {
      return content.replace(regex, (match) => {
        const redacted = this.applyStrategy(match, rule.strategy, rule.data_type);
        
        if (rule.reversible) {
          const mapKey = generateId('redact_');
          redactionMap[mapKey] = { original: match, strategy: rule.strategy.type };
          countCallback(1, 0);
        } else {
          countCallback(0, 1);
        }
        
        return redacted;
      });
    }
    
    if (Array.isArray(content)) {
      return content.map(item => 
        this.redactByRegex(item, regex, rule, redactionMap, countCallback)
      );
    }
    
    if (typeof content === 'object' && content !== null) {
      const result: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(content)) {
        result[key] = this.redactByRegex(value, regex, rule, redactionMap, countCallback);
      }
      return result;
    }
    
    return content;
  }
  
  private applyStrategy(value: string, strategy: RedactionStrategy, dataType: DataType): string {
    switch (strategy.type) {
      case RedactionStrategyType.MASK:
        return this.applyMask(value, strategy.char, strategy.preserve_length, strategy.show_last);
        
      case RedactionStrategyType.HASH:
        return this.applyHash(value, strategy.algorithm, strategy.salted);
        
      case RedactionStrategyType.TOKENIZE:
        return this.generateToken(dataType, value);
        
      case RedactionStrategyType.GENERALIZE:
        return this.applyGeneralization(value, dataType, strategy.level);
        
      case RedactionStrategyType.ENCRYPT:
        // For encrypt strategy, we'd use the specified key
        return `[ENCRYPTED:${strategy.key_id}]`;
        
      case RedactionStrategyType.SYNTHETIC:
        return this.generateSynthetic(dataType, strategy.generator);
        
      default:
        return REDACTION.DEFAULT_MASK_CHAR.repeat(value.length);
    }
  }
  
  private applyMask(value: string, char: string, preserveLength: boolean, showLast?: number): string {
    const maskChar = char || REDACTION.DEFAULT_MASK_CHAR;
    
    if (showLast && showLast > 0 && value.length > showLast) {
      const masked = preserveLength
        ? maskChar.repeat(value.length - showLast)
        : maskChar.repeat(4);
      return masked + value.slice(-showLast);
    }
    
    return preserveLength
      ? maskChar.repeat(value.length)
      : maskChar.repeat(8);
  }
  
  private applyHash(value: string, algorithm: string, salted: boolean): string {
    if (salted) {
      const { hash: h } = hashWithSalt(value);
      return h.slice(0, 16);
    }
    return hash(value).slice(0, 16);
  }
  
  private generateToken(dataType: DataType, originalValue: string): string {
    const typePrefix = dataType.toUpperCase().slice(0, 3);
    const tokenId = hash(originalValue + Date.now().toString()).slice(0, 12);
    const token = `${REDACTION.TOKEN_PREFIX}${typePrefix}_${tokenId}`;
    
    // Store mapping
    const encryptedOriginal = this.encryptTokenValue(originalValue);
    this.tokenMap.set(token, {
      original_encrypted: encryptedOriginal,
      data_type: dataType,
      created_at: new Date(),
    });
    
    // Also persist to storage
    this.storage.saveTokenMapping(token, {
      original_encrypted: encryptedOriginal,
      data_type: dataType,
      created_at: new Date(),
    }).catch(() => {}); // Fire and forget
    
    return token;
  }
  
  private applyGeneralization(value: string, dataType: DataType, level: number): string {
    switch (dataType) {
      case 'date_of_birth':
        // Parse date and generalize
        try {
          const date = new Date(value);
          if (level >= 3) return `${date.getFullYear()}`;
          if (level >= 2) return `Q${Math.ceil((date.getMonth() + 1) / 3)} ${date.getFullYear()}`;
          if (level >= 1) return `${date.toLocaleString('default', { month: 'long' })} ${date.getFullYear()}`;
          return value;
        } catch {
          return '[REDACTED_DATE]';
        }
        
      case 'address':
        // For addresses, remove specific parts based on level
        const parts = value.split(',').map(p => p.trim());
        if (level >= 3 && parts.length > 0) return parts[parts.length - 1]; // Country only
        if (level >= 2 && parts.length > 1) return parts.slice(-2).join(', '); // State, Country
        if (level >= 1 && parts.length > 2) return parts.slice(-3).join(', '); // City, State, Country
        return value;
        
      default:
        return '[GENERALIZED]';
    }
  }
  
  private generateSynthetic(dataType: DataType, _generator: string): string {
    // Generate realistic-looking but fake data
    switch (dataType) {
      case 'ssn':
        return `${this.randomDigits(3)}-${this.randomDigits(2)}-${this.randomDigits(4)}`;
        
      case 'credit_card':
        return `4${this.randomDigits(15)}`; // Visa-like
        
      case 'email':
        return `user${this.randomDigits(6)}@example.com`;
        
      case 'phone':
        return `(555) ${this.randomDigits(3)}-${this.randomDigits(4)}`;
        
      case 'name':
        const names = ['John Smith', 'Jane Doe', 'Alex Johnson', 'Sam Wilson'];
        return names[Math.floor(Math.random() * names.length)];
        
      default:
        return '[SYNTHETIC]';
    }
  }
  
  private randomDigits(count: number): string {
    return Array.from({ length: count }, () => Math.floor(Math.random() * 10)).join('');
  }
  
  private autoRedactPII(
    content: unknown,
    redactionMap: Record<string, { original: string; strategy: string }>
  ): { content: unknown; count: number } {
    let count = 0;
    
    const redact = (value: unknown): unknown => {
      if (typeof value === 'string') {
        let result = value;
        
        for (const [dataType, pattern] of Object.entries(REDACTION.PII_PATTERNS)) {
          result = result.replace(pattern, (match) => {
            count++;
            return this.applyMask(match, REDACTION.DEFAULT_MASK_CHAR, false, 4);
          });
        }
        
        return result;
      }
      
      if (Array.isArray(value)) {
        return value.map(redact);
      }
      
      if (typeof value === 'object' && value !== null) {
        const result: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(value)) {
          result[k] = redact(v);
        }
        return result;
      }
      
      return value;
    };
    
    return { content: redact(content), count };
  }
  
  private encryptRedactionMap(map: Record<string, { original: string; strategy: string }>): string {
    if (!keyStore.isInitialized()) {
      return JSON.stringify(map);  // Fallback for testing
    }
    
    const key = keyStore.getMasterKey();
    const encrypted = encrypt(JSON.stringify(map), key);
    return JSON.stringify(encrypted);
  }
  
  private decryptRedactionMap(encrypted: string): Record<string, { original: string; strategy: string }> {
    if (!keyStore.isInitialized()) {
      return JSON.parse(encrypted);  // Fallback for testing
    }
    
    try {
      const key = keyStore.getMasterKey();
      const encryptedData = JSON.parse(encrypted);
      const decrypted = decrypt(encryptedData, key);
      return JSON.parse(decrypted.toString('utf-8'));
    } catch {
      return {};
    }
  }
  
  private encryptTokenValue(value: string): string {
    if (!keyStore.isInitialized()) {
      return Buffer.from(value).toString('base64');  // Fallback
    }
    
    const key = keyStore.getMasterKey();
    const encrypted = encrypt(value, key);
    return JSON.stringify(encrypted);
  }
  
  private decryptTokenValue(encrypted: string): string {
    if (!keyStore.isInitialized()) {
      return Buffer.from(encrypted, 'base64').toString('utf-8');  // Fallback
    }
    
    try {
      const key = keyStore.getMasterKey();
      const encryptedData = JSON.parse(encrypted);
      const decrypted = decrypt(encryptedData, key);
      return decrypted.toString('utf-8');
    } catch {
      return '[DECRYPTION_FAILED]';
    }
  }
  
  private reverseTokenizations(
    content: unknown,
    _redactionMap: Record<string, { original: string; strategy: string }>
  ): unknown {
    const reverse = (value: unknown): unknown => {
      if (typeof value === 'string') {
        // Check for tokens
        const tokenPattern = new RegExp(`${REDACTION.TOKEN_PREFIX}[A-Z]+_[a-f0-9]+`, 'g');
        return value.replace(tokenPattern, (token) => {
          const mapping = this.tokenMap.get(token);
          if (mapping) {
            return this.decryptTokenValue(mapping.original_encrypted);
          }
          return token;
        });
      }
      
      if (Array.isArray(value)) {
        return value.map(reverse);
      }
      
      if (typeof value === 'object' && value !== null) {
        const result: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(value)) {
          result[k] = reverse(v);
        }
        return result;
      }
      
      return value;
    };
    
    return reverse(content);
  }
}
