/**
 * Hord - The Vault Protocol
 * Type Definitions
 * 
 * Cryptographic containment and capability management for AI agents.
 */

// ============================================================================
// Core Enums
// ============================================================================

export enum DataClassification {
  PUBLIC = 'public',
  INTERNAL = 'internal',
  CONFIDENTIAL = 'confidential',
  SECRET = 'secret',
  TOP_SECRET = 'top_secret'
}

export enum ActionType {
  READ = 'read',
  WRITE = 'write',
  EXECUTE = 'execute',
  DELETE = 'delete',
  DELEGATE = 'delegate'
}

export enum IsolationLevel {
  PROCESS = 'process',
  CONTAINER = 'container',
  VM = 'vm'
}

export enum PromotionRecommendation {
  SAFE = 'safe',
  REVIEW = 'review',
  BLOCK = 'block'
}

export enum RedactionStrategyType {
  MASK = 'mask',
  HASH = 'hash',
  TOKENIZE = 'tokenize',
  GENERALIZE = 'generalize',
  ENCRYPT = 'encrypt',
  SYNTHETIC = 'synthetic'
}

// ============================================================================
// Vault Types
// ============================================================================

export interface VaultConfig {
  id?: string;
  agent_id: string;
  name: string;
  description?: string;
  access_policy: AccessPolicy;
  encryption_algorithm?: 'aes-256-gcm';
  key_derivation?: 'argon2id' | 'pbkdf2';
}

export interface Vault {
  id: string;
  agent_id: string;
  name: string;
  description?: string;
  created_at: Date;
  updated_at: Date;
  encryption: {
    algorithm: 'aes-256-gcm';
    key_derivation: 'argon2id' | 'pbkdf2';
    key_id: string;
    iv: string;
  };
  access_policy: AccessPolicy;
  sealed: boolean;
  version: number;
}

export interface AccessPolicy {
  require_attestation?: boolean;
  allowed_contexts?: string[];
  allowed_agents?: string[];
  time_restrictions?: TimeRestriction[];
  max_access_count?: number;
  classification_required?: DataClassification;
}

export interface TimeRestriction {
  days_of_week?: number[];  // 0-6, Sunday = 0
  start_hour?: number;      // 0-23
  end_hour?: number;        // 0-23
  timezone?: string;
}

export interface VaultContents {
  memories: Memory[];
  credentials: StoredCredential[];
  state: Record<string, unknown>;
  artifacts: Artifact[];
}

export interface Memory {
  id: string;
  content: string;
  embedding?: number[];
  created_at: Date;
  metadata: Record<string, unknown>;
  classification: DataClassification;
}

export interface StoredCredential {
  id: string;
  name: string;
  type: 'api_key' | 'password' | 'token' | 'certificate' | 'private_key' | 'other';
  value_encrypted: string;  // Never stored plaintext
  classification: DataClassification;
  created_at: Date;
  expires_at?: Date;
  last_accessed?: Date;
  access_count: number;
  metadata: Record<string, unknown>;
}

export interface Artifact {
  id: string;
  type: 'code' | 'document' | 'image' | 'data' | 'other';
  content_hash: string;
  content_encrypted: string;
  classification: DataClassification;
  created_at: Date;
  metadata: Record<string, unknown>;
}

// ============================================================================
// Capability Token Types
// ============================================================================

export interface CapabilityTokenConfig {
  agent_id: string;
  resource: ResourceDescriptor;
  actions: ActionType[];
  constraints?: CapabilityConstraints;
  delegatable?: boolean;
  justification?: string;
}

export interface CapabilityToken {
  id: string;
  agent_id: string;
  resource: ResourceDescriptor;
  actions: ActionType[];
  constraints: CapabilityConstraints;
  delegatable: boolean;
  parent_token_id?: string;
  delegation_depth: number;
  issued_at: Date;
  issuer: string;
  signature: string;
  revoked: boolean;
  uses: number;
}

export interface ResourceDescriptor {
  type: 'vault' | 'secret' | 'file' | 'api' | 'network' | 'sandbox' | 'any';
  id: string;
  path?: string;
  pattern?: string;  // For wildcard matching
}

export interface CapabilityConstraints {
  valid_from: Date;
  valid_until: Date;
  max_uses?: number;
  current_uses?: number;
  rate_limit?: RateLimit;
  requires_attestation?: boolean;
  allowed_contexts?: string[];
  data_classification_max: DataClassification;
  ip_allowlist?: string[];
  requires_mfa?: boolean;
}

export interface RateLimit {
  requests: number;
  window_seconds: number;
  current_window_start?: Date;
  current_count?: number;
}

export interface DelegationRequest {
  parent_token_id: string;
  delegate_to_agent: string;
  attenuated_actions?: ActionType[];
  attenuated_constraints?: Partial<CapabilityConstraints>;
  justification: string;
}

// ============================================================================
// Sandbox Types
// ============================================================================

export interface SandboxConfig {
  id?: string;
  type: 'code' | 'command' | 'network' | 'file';
  isolation_level: IsolationLevel;
  resource_limits: ResourceLimits;
  allowed_syscalls?: string[];
  network_policy: NetworkPolicy;
  filesystem_policy: FilesystemPolicy;
  environment?: Record<string, string>;
  timeout_ms?: number;
}

export interface Sandbox {
  id: string;
  config: SandboxConfig;
  status: 'created' | 'running' | 'completed' | 'failed' | 'timeout' | 'destroyed';
  created_at: Date;
  started_at?: Date;
  completed_at?: Date;
  container_id?: string;
  pid?: number;
}

export interface ResourceLimits {
  cpu_seconds: number;
  memory_mb: number;
  disk_mb: number;
  network_bytes: number;
  max_processes: number;
  max_file_descriptors?: number;
  max_file_size_mb?: number;
}

export interface NetworkPolicy {
  allow_outbound: boolean;
  allowed_hosts?: string[];
  allowed_ports?: number[];
  blocked_hosts?: string[];
  max_connections?: number;
  dns_policy: 'allow' | 'block' | 'intercept';
}

export interface FilesystemPolicy {
  writable_paths: string[];
  readable_paths: string[];
  blocked_paths: string[];
  max_files?: number;
  allow_symlinks: boolean;
}

export interface SandboxExecutionRequest {
  sandbox_id: string;
  type: 'code' | 'command';
  content: string;
  language?: string;  // For code execution
  declared_intent: string;
  inputs?: Record<string, unknown>;
}

export interface SandboxResult {
  id: string;
  sandbox_id: string;
  status: 'success' | 'failure' | 'timeout' | 'violation' | 'error';
  exit_code?: number;
  stdout: string;
  stderr: string;
  duration_ms: number;
  resource_usage: ResourceUsage;
  syscalls: SyscallTrace[];
  network_activity: NetworkActivity[];
  filesystem_changes: FilesystemChange[];
  security_events: SecurityEvent[];
  promotion_recommendation: PromotionRecommendation;
  recommendation_reasons: string[];
}

export interface ResourceUsage {
  cpu_seconds_used: number;
  memory_peak_mb: number;
  disk_written_mb: number;
  network_bytes_sent: number;
  network_bytes_received: number;
  processes_spawned: number;
}

export interface SyscallTrace {
  timestamp: Date;
  syscall: string;
  args: string[];
  return_value: number;
  flagged: boolean;
  reason?: string;
}

export interface NetworkActivity {
  timestamp: Date;
  direction: 'inbound' | 'outbound';
  protocol: 'tcp' | 'udp' | 'dns' | 'other';
  remote_host: string;
  remote_port: number;
  bytes: number;
  blocked: boolean;
  reason?: string;
}

export interface FilesystemChange {
  timestamp: Date;
  operation: 'create' | 'modify' | 'delete' | 'rename' | 'chmod';
  path: string;
  new_path?: string;  // For rename
  size_bytes?: number;
  flagged: boolean;
  reason?: string;
}

export interface SecurityEvent {
  timestamp: Date;
  severity: 'info' | 'warning' | 'critical';
  type: string;
  description: string;
  details: Record<string, unknown>;
}

// ============================================================================
// Redaction Types
// ============================================================================

export interface RedactionPolicyConfig {
  id?: string;
  name: string;
  description?: string;
  rules: RedactionRule[];
  default_strategy?: RedactionStrategy;
}

export interface RedactionPolicy {
  id: string;
  name: string;
  description?: string;
  rules: RedactionRule[];
  default_strategy?: RedactionStrategy;
  created_at: Date;
  updated_at: Date;
  version: number;
}

export interface RedactionRule {
  id?: string;
  field_pattern: string;       // JSONPath, regex, or field name
  data_type: DataType;
  strategy: RedactionStrategy;
  reversible: boolean;
  conditions?: RedactionCondition[];
}

export type DataType = 
  | 'ssn'
  | 'credit_card'
  | 'email'
  | 'phone'
  | 'ip_address'
  | 'name'
  | 'address'
  | 'date_of_birth'
  | 'api_key'
  | 'password'
  | 'custom';

export type RedactionStrategy =
  | { type: RedactionStrategyType.MASK; char: string; preserve_length: boolean; show_last?: number }
  | { type: RedactionStrategyType.HASH; algorithm: 'sha256' | 'blake3'; salted: boolean }
  | { type: RedactionStrategyType.TOKENIZE; format_preserving: boolean; token_prefix?: string }
  | { type: RedactionStrategyType.GENERALIZE; level: number }
  | { type: RedactionStrategyType.ENCRYPT; key_id: string }
  | { type: RedactionStrategyType.SYNTHETIC; generator: string };

export interface RedactionCondition {
  field: string;
  operator: 'equals' | 'contains' | 'matches' | 'greater_than' | 'less_than';
  value: unknown;
}

export interface RedactedData {
  data: unknown;
  redaction_map_encrypted: string;  // Encrypted map for reversal
  policy_id: string;
  policy_version: number;
  timestamp: Date;
  reversible_count: number;
  irreversible_count: number;
}

export interface TokenizationMap {
  [token: string]: {
    original_encrypted: string;
    data_type: DataType;
    created_at: Date;
  };
}

// ============================================================================
// Attestation Types
// ============================================================================

export interface AttestationRequest {
  agent_id: string;
  action: AttestableAction;
  inputs_hash?: string;
  outputs_hash?: string;
  context?: Partial<AttestationContext>;
}

export interface Attestation {
  id: string;
  timestamp: Date;
  agent_id: string;
  action: AttestableAction;
  inputs_hash: string;
  outputs_hash: string;
  context: AttestationContext;
  previous_attestation_id?: string;  // For chaining
  signature: string;
  certificate_chain: string[];
  verified: boolean;
}

export interface AttestableAction {
  type: string;
  description: string;
  resources_accessed: string[];
  capabilities_used: string[];
  sandbox_id?: string;
  duration_ms: number;
  result: 'success' | 'failure' | 'partial';
}

export interface AttestationContext {
  environment: Record<string, string>;
  caller_chain: string[];
  policy_version: string;
  hord_version: string;
  timestamp_source: 'local' | 'ntp' | 'trusted';
  additional: Record<string, unknown>;
}

export interface AttestationVerification {
  attestation_id: string;
  valid: boolean;
  signature_valid: boolean;
  certificate_valid: boolean;
  timestamp_valid: boolean;
  chain_valid: boolean;
  errors: string[];
  verified_at: Date;
}

// ============================================================================
// Storage Types
// ============================================================================

export interface IHordStorage {
  // Vaults
  saveVault(vault: Vault): Promise<void>;
  getVault(id: string): Promise<Vault | null>;
  getVaultsByAgent(agentId: string): Promise<Vault[]>;
  updateVault(vault: Vault): Promise<void>;
  deleteVault(id: string): Promise<void>;
  
  // Vault Contents (encrypted)
  saveVaultContents(vaultId: string, contents: string): Promise<void>;
  getVaultContents(vaultId: string): Promise<string | null>;
  
  // Capability Tokens
  saveCapabilityToken(token: CapabilityToken): Promise<void>;
  getCapabilityToken(id: string): Promise<CapabilityToken | null>;
  getCapabilityTokensByAgent(agentId: string): Promise<CapabilityToken[]>;
  revokeCapabilityToken(id: string): Promise<void>;
  incrementTokenUse(id: string): Promise<void>;
  
  // Sandboxes
  saveSandbox(sandbox: Sandbox): Promise<void>;
  getSandbox(id: string): Promise<Sandbox | null>;
  updateSandboxStatus(id: string, status: Sandbox['status']): Promise<void>;
  
  // Sandbox Results
  saveSandboxResult(result: SandboxResult): Promise<void>;
  getSandboxResult(id: string): Promise<SandboxResult | null>;
  getSandboxResults(sandboxId: string): Promise<SandboxResult[]>;
  
  // Redaction Policies
  saveRedactionPolicy(policy: RedactionPolicy): Promise<void>;
  getRedactionPolicy(id: string): Promise<RedactionPolicy | null>;
  listRedactionPolicies(): Promise<RedactionPolicy[]>;
  
  // Tokenization Map
  saveTokenMapping(token: string, mapping: TokenizationMap[string]): Promise<void>;
  getTokenMapping(token: string): Promise<TokenizationMap[string] | null>;
  
  // Attestations
  saveAttestation(attestation: Attestation): Promise<void>;
  getAttestation(id: string): Promise<Attestation | null>;
  getAttestationsByAgent(agentId: string, limit?: number): Promise<Attestation[]>;
  getAttestationChain(id: string): Promise<Attestation[]>;
  
  // Audit Log
  logAccess(entry: AccessLogEntry): Promise<void>;
  getAccessLog(filters: AccessLogFilters): Promise<AccessLogEntry[]>;
}

export interface AccessLogEntry {
  id: string;
  timestamp: Date;
  agent_id: string;
  action: string;
  resource: string;
  capability_token_id?: string;
  success: boolean;
  error_message?: string;
  ip_address?: string;
  context?: Record<string, unknown>;
}

export interface AccessLogFilters {
  agent_id?: string;
  action?: string;
  resource?: string;
  start_date?: Date;
  end_date?: Date;
  success?: boolean;
  limit?: number;
  offset?: number;
}

// ============================================================================
// Configuration Types
// ============================================================================

export interface HordConfig {
  port: number;
  host: string;
  transport: 'stdio' | 'http';
  log_level: 'debug' | 'info' | 'warn' | 'error';
  storage: 'memory' | 'sqlite' | 'postgres';
  database_url?: string;
  
  encryption: {
    master_key_file?: string;
    master_key?: string;  // For testing only!
    key_rotation_days: number;
    use_hardware_key: boolean;
  };
  
  sandbox: {
    runtime: 'process' | 'docker' | 'firecracker';
    default_timeout_ms: number;
    default_memory_mb: number;
    image?: string;
  };
  
  attestation: {
    key_file?: string;
    cert_file?: string;
    chain_attestations: boolean;
  };
  
  integration: {
    mund_url?: string;
    mund_api_key?: string;
  };
}

// ============================================================================
// Error Types
// ============================================================================

export class HordError extends Error {
  constructor(
    message: string,
    public code: string,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'HordError';
  }
}

export class VaultError extends HordError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'VAULT_ERROR', details);
    this.name = 'VaultError';
  }
}

export class CapabilityError extends HordError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'CAPABILITY_ERROR', details);
    this.name = 'CapabilityError';
  }
}

export class SandboxError extends HordError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'SANDBOX_ERROR', details);
    this.name = 'SandboxError';
  }
}

export class RedactionError extends HordError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'REDACTION_ERROR', details);
    this.name = 'RedactionError';
  }
}

export class AttestationError extends HordError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'ATTESTATION_ERROR', details);
    this.name = 'AttestationError';
  }
}
