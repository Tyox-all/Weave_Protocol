/**
 * Hord - The Vault Protocol
 * Constants and Default Configuration
 */

import type {
  HordConfig,
  RedactionPolicy,
  RedactionStrategyType,
  DataClassification,
  NetworkPolicy,
  FilesystemPolicy,
  ResourceLimits,
} from './types.js';

// ============================================================================
// Default Configuration
// ============================================================================

export const DEFAULT_CONFIG: HordConfig = {
  port: 3001,
  host: '127.0.0.1',
  transport: 'stdio',
  log_level: 'info',
  storage: 'memory',
  
  encryption: {
    key_rotation_days: 90,
    use_hardware_key: false,
  },
  
  sandbox: {
    runtime: 'process',
    default_timeout_ms: 30000,
    default_memory_mb: 512,
  },
  
  attestation: {
    chain_attestations: true,
  },
  
  integration: {},
};

// ============================================================================
// Encryption Constants
// ============================================================================

export const ENCRYPTION = {
  ALGORITHM: 'aes-256-gcm' as const,
  KEY_LENGTH: 32,  // 256 bits
  IV_LENGTH: 12,   // 96 bits for GCM
  AUTH_TAG_LENGTH: 16,  // 128 bits
  SALT_LENGTH: 32,
  
  // Argon2id parameters
  ARGON2: {
    TIME_COST: 3,
    MEMORY_COST: 65536,  // 64 MB
    PARALLELISM: 4,
  },
  
  // PBKDF2 fallback parameters
  PBKDF2: {
    ITERATIONS: 100000,
    DIGEST: 'sha512',
  },
};

// ============================================================================
// Capability Token Constants
// ============================================================================

export const CAPABILITY = {
  DEFAULT_VALIDITY_HOURS: 24,
  MAX_VALIDITY_DAYS: 365,
  MAX_DELEGATION_DEPTH: 5,
  MAX_USES_DEFAULT: 1000,
  
  // Rate limit defaults
  RATE_LIMIT: {
    DEFAULT_REQUESTS: 100,
    DEFAULT_WINDOW_SECONDS: 60,
  },
  
  // Token format
  TOKEN_PREFIX: 'hord_cap_',
  TOKEN_VERSION: 1,
};

// ============================================================================
// Sandbox Constants
// ============================================================================

export const SANDBOX = {
  // Default resource limits
  DEFAULT_LIMITS: {
    cpu_seconds: 30,
    memory_mb: 512,
    disk_mb: 100,
    network_bytes: 0,  // No network by default
    max_processes: 10,
    max_file_descriptors: 100,
    max_file_size_mb: 50,
  } as ResourceLimits,
  
  // Default network policy (restrictive)
  DEFAULT_NETWORK_POLICY: {
    allow_outbound: false,
    allowed_hosts: [],
    allowed_ports: [],
    blocked_hosts: [],
    max_connections: 0,
    dns_policy: 'block',
  } as NetworkPolicy,
  
  // Default filesystem policy
  DEFAULT_FILESYSTEM_POLICY: {
    writable_paths: ['/tmp', '/home/sandbox'],
    readable_paths: ['/usr', '/lib', '/bin', '/etc/alternatives'],
    blocked_paths: ['/etc/passwd', '/etc/shadow', '/root', '/home'],
    max_files: 100,
    allow_symlinks: false,
  } as FilesystemPolicy,
  
  // Dangerous syscalls to flag
  DANGEROUS_SYSCALLS: [
    'ptrace',
    'process_vm_readv',
    'process_vm_writev',
    'mount',
    'umount',
    'pivot_root',
    'setuid',
    'setgid',
    'setreuid',
    'setregid',
    'capset',
    'init_module',
    'finit_module',
    'delete_module',
    'kexec_load',
    'reboot',
  ],
  
  // Suspicious patterns in code
  SUSPICIOUS_CODE_PATTERNS: [
    /eval\s*\(/i,
    /exec\s*\(/i,
    /subprocess\.(call|run|Popen)/i,
    /os\.system/i,
    /shell\s*=\s*True/i,
    /\$\(.*\)/,  // Shell command substitution
    /`.*`/,      // Backtick execution
    /import\s+(socket|requests|urllib|httplib)/i,
    /require\s*\(['"](child_process|net|http|https)['"]\)/i,
  ],
  
  // Max execution time before auto-kill
  MAX_TIMEOUT_MS: 300000,  // 5 minutes absolute max
};

// ============================================================================
// Redaction Constants
// ============================================================================

export const REDACTION = {
  // Default masking character
  DEFAULT_MASK_CHAR: '*',
  
  // Token prefix for format-preserving tokenization
  TOKEN_PREFIX: 'TOK_',
  
  // PII patterns for detection
  PII_PATTERNS: {
    ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
    credit_card: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
    email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    phone: /\b(?:\+1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b/g,
    ip_address: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
  },
  
  // Generalization levels
  GENERALIZATION: {
    // For dates: 0 = exact, 1 = month, 2 = quarter, 3 = year, 4 = decade
    DATE_LEVELS: ['exact', 'month', 'quarter', 'year', 'decade'],
    // For locations: 0 = exact, 1 = city, 2 = state, 3 = region, 4 = country
    LOCATION_LEVELS: ['exact', 'city', 'state', 'region', 'country'],
    // For ages: 0 = exact, 1 = 5-year bucket, 2 = 10-year bucket, 3 = generation
    AGE_LEVELS: ['exact', '5-year', '10-year', 'generation'],
  },
};

// ============================================================================
// Default Redaction Policies
// ============================================================================

export const DEFAULT_REDACTION_POLICIES: Omit<RedactionPolicy, 'id' | 'created_at' | 'updated_at' | 'version'>[] = [
  {
    name: 'pii-standard',
    description: 'Standard PII redaction policy',
    rules: [
      {
        field_pattern: '$.ssn',
        data_type: 'ssn',
        strategy: { type: 'tokenize' as RedactionStrategyType.TOKENIZE, format_preserving: true },
        reversible: true,
      },
      {
        field_pattern: '$.social_security_number',
        data_type: 'ssn',
        strategy: { type: 'tokenize' as RedactionStrategyType.TOKENIZE, format_preserving: true },
        reversible: true,
      },
      {
        field_pattern: '$.credit_card',
        data_type: 'credit_card',
        strategy: { type: 'mask' as RedactionStrategyType.MASK, char: '*', preserve_length: true, show_last: 4 },
        reversible: false,
      },
      {
        field_pattern: '$.email',
        data_type: 'email',
        strategy: { type: 'hash' as RedactionStrategyType.HASH, algorithm: 'sha256', salted: true },
        reversible: false,
      },
      {
        field_pattern: '$.phone',
        data_type: 'phone',
        strategy: { type: 'mask' as RedactionStrategyType.MASK, char: '*', preserve_length: true, show_last: 4 },
        reversible: false,
      },
    ],
  },
  {
    name: 'hipaa-compliant',
    description: 'HIPAA-compliant redaction for healthcare data',
    rules: [
      {
        field_pattern: '$.patient_name',
        data_type: 'name',
        strategy: { type: 'tokenize' as RedactionStrategyType.TOKENIZE, format_preserving: false, token_prefix: 'PAT_' },
        reversible: true,
      },
      {
        field_pattern: '$.date_of_birth',
        data_type: 'date_of_birth',
        strategy: { type: 'generalize' as RedactionStrategyType.GENERALIZE, level: 3 },  // Year only
        reversible: false,
      },
      {
        field_pattern: '$.address',
        data_type: 'address',
        strategy: { type: 'generalize' as RedactionStrategyType.GENERALIZE, level: 2 },  // State only
        reversible: false,
      },
      {
        field_pattern: '$.ssn',
        data_type: 'ssn',
        strategy: { type: 'hash' as RedactionStrategyType.HASH, algorithm: 'sha256', salted: true },
        reversible: false,
      },
    ],
  },
  {
    name: 'api-keys',
    description: 'Redaction policy for API keys and secrets',
    rules: [
      {
        field_pattern: '$.api_key',
        data_type: 'api_key',
        strategy: { type: 'mask' as RedactionStrategyType.MASK, char: '*', preserve_length: false, show_last: 4 },
        reversible: false,
      },
      {
        field_pattern: '$.password',
        data_type: 'password',
        strategy: { type: 'mask' as RedactionStrategyType.MASK, char: '*', preserve_length: false },
        reversible: false,
      },
      {
        field_pattern: '$.secret',
        data_type: 'api_key',
        strategy: { type: 'mask' as RedactionStrategyType.MASK, char: '*', preserve_length: false, show_last: 4 },
        reversible: false,
      },
    ],
  },
];

// ============================================================================
// Attestation Constants
// ============================================================================

export const ATTESTATION = {
  // Signature algorithm
  SIGNATURE_ALGORITHM: 'ed25519' as const,
  
  // Hash algorithm for content
  HASH_ALGORITHM: 'sha256' as const,
  
  // Certificate validity
  CERT_VALIDITY_DAYS: 365,
  
  // Chain depth limit
  MAX_CHAIN_DEPTH: 1000,
  
  // Timestamp tolerance (for verification)
  TIMESTAMP_TOLERANCE_MS: 60000,  // 1 minute
};

// ============================================================================
// Data Classification Levels
// ============================================================================

export const CLASSIFICATION_HIERARCHY: Record<DataClassification, number> = {
  [DataClassification.PUBLIC]: 0,
  [DataClassification.INTERNAL]: 1,
  [DataClassification.CONFIDENTIAL]: 2,
  [DataClassification.SECRET]: 3,
  [DataClassification.TOP_SECRET]: 4,
};

export function canAccessClassification(
  requiredLevel: DataClassification,
  grantedLevel: DataClassification
): boolean {
  return CLASSIFICATION_HIERARCHY[grantedLevel] >= CLASSIFICATION_HIERARCHY[requiredLevel];
}

// ============================================================================
// Error Codes
// ============================================================================

export const ERROR_CODES = {
  // Vault errors
  VAULT_NOT_FOUND: 'VAULT_NOT_FOUND',
  VAULT_SEALED: 'VAULT_SEALED',
  VAULT_ALREADY_EXISTS: 'VAULT_ALREADY_EXISTS',
  VAULT_ENCRYPTION_FAILED: 'VAULT_ENCRYPTION_FAILED',
  VAULT_DECRYPTION_FAILED: 'VAULT_DECRYPTION_FAILED',
  
  // Capability errors
  CAPABILITY_INVALID: 'CAPABILITY_INVALID',
  CAPABILITY_EXPIRED: 'CAPABILITY_EXPIRED',
  CAPABILITY_REVOKED: 'CAPABILITY_REVOKED',
  CAPABILITY_INSUFFICIENT: 'CAPABILITY_INSUFFICIENT',
  CAPABILITY_RATE_LIMITED: 'CAPABILITY_RATE_LIMITED',
  CAPABILITY_DELEGATION_DEPTH_EXCEEDED: 'CAPABILITY_DELEGATION_DEPTH_EXCEEDED',
  
  // Sandbox errors
  SANDBOX_NOT_FOUND: 'SANDBOX_NOT_FOUND',
  SANDBOX_CREATION_FAILED: 'SANDBOX_CREATION_FAILED',
  SANDBOX_EXECUTION_FAILED: 'SANDBOX_EXECUTION_FAILED',
  SANDBOX_TIMEOUT: 'SANDBOX_TIMEOUT',
  SANDBOX_VIOLATION: 'SANDBOX_VIOLATION',
  
  // Redaction errors
  REDACTION_POLICY_NOT_FOUND: 'REDACTION_POLICY_NOT_FOUND',
  REDACTION_FAILED: 'REDACTION_FAILED',
  DEREDACTION_NOT_ALLOWED: 'DEREDACTION_NOT_ALLOWED',
  DEREDACTION_FAILED: 'DEREDACTION_FAILED',
  
  // Attestation errors
  ATTESTATION_NOT_FOUND: 'ATTESTATION_NOT_FOUND',
  ATTESTATION_INVALID: 'ATTESTATION_INVALID',
  ATTESTATION_SIGNATURE_INVALID: 'ATTESTATION_SIGNATURE_INVALID',
  
  // General errors
  ACCESS_DENIED: 'ACCESS_DENIED',
  INVALID_INPUT: 'INVALID_INPUT',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
};

// ============================================================================
// MCP Server Info
// ============================================================================

export const SERVER_INFO = {
  name: 'hord-mcp',
  version: '0.1.0',
  description: 'The Vault Protocol - Cryptographic containment for AI agents',
};
