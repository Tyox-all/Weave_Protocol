/**
 * Mund - The Guardian Protocol
 * Core type definitions
 */

// ============================================================================
// Severity and Action Types
// ============================================================================

export enum Severity {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFO = 'info'
}

export enum ActionType {
  ALERT = 'alert',
  BLOCK = 'block',
  LOG = 'log',
  QUARANTINE = 'quarantine'
}

export enum DetectorType {
  SECRET = 'secret',
  PII = 'pii',
  CODE_PATTERN = 'code_pattern',
  INJECTION = 'injection',
  EXFILTRATION = 'exfiltration',
  BEHAVIORAL = 'behavioral'
}

// ============================================================================
// Detection Rules
// ============================================================================

export interface DetectionRule {
  id: string;
  name: string;
  description?: string;
  type: DetectorType;
  pattern?: string;
  condition?: string;
  severity: Severity;
  action: ActionType;
  enabled: boolean;
  metadata?: Record<string, unknown>;
}

export interface SecretRule extends DetectionRule {
  type: DetectorType.SECRET;
  pattern: string;
  entropy_threshold?: number;
}

export interface BehavioralRule extends DetectionRule {
  type: DetectorType.BEHAVIORAL;
  condition: string;
  time_window_seconds: number;
  threshold: number;
}

// ============================================================================
// Security Events
// ============================================================================

export interface SecurityEvent {
  id: string;
  timestamp: Date;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  type: DetectorType;
  action_taken: ActionType;
  content_snippet: string;
  full_content_hash: string;
  context: EventContext;
  acknowledged: boolean;
  acknowledged_by?: string;
  acknowledged_at?: Date;
  metadata?: Record<string, unknown>;
}

export interface EventContext {
  tool_name?: string;
  tool_args?: Record<string, unknown>;
  source?: string;
  agent_id?: string;
  session_id?: string;
  user_id?: string;
  ip_address?: string;
}

// ============================================================================
// Scan Results
// ============================================================================

export interface ScanResult {
  id: string;
  timestamp: Date;
  content_hash: string;
  issues: SecurityIssue[];
  scan_duration_ms: number;
  rules_checked: number;
}

export interface SecurityIssue {
  rule_id: string;
  rule_name: string;
  type: DetectorType;
  severity: Severity;
  action: ActionType;
  match: string;
  location?: IssueLocation;
  suggestion?: string;
}

export interface IssueLocation {
  start: number;
  end: number;
  line?: number;
  column?: number;
}

// ============================================================================
// Configuration
// ============================================================================

export interface MundConfig {
  // Server settings
  port: number;
  host: string;
  transport: 'stdio' | 'http';
  
  // Logging
  log_level: 'debug' | 'info' | 'warn' | 'error';
  
  // Storage
  storage_type: 'memory' | 'sqlite' | 'postgres';
  database_url?: string;
  
  // Security mode
  block_mode: boolean;
  
  // API
  api_key?: string;
  
  // Notifications
  notifications: NotificationConfig;
  
  // Rules
  rules_path?: string;
  custom_rules?: DetectionRule[];
}

export interface NotificationConfig {
  slack?: SlackConfig;
  teams?: TeamsConfig;
  email?: EmailConfig;
  webhooks?: WebhookConfig[];
}

export interface SlackConfig {
  webhook_url: string;
  channel?: string;
  username?: string;
  icon_emoji?: string;
  min_severity?: Severity;
}

export interface TeamsConfig {
  webhook_url: string;
  min_severity?: Severity;
}

export interface EmailConfig {
  smtp_host: string;
  smtp_port: number;
  smtp_secure: boolean;
  smtp_user?: string;
  smtp_pass?: string;
  from_address: string;
  to_addresses: string[];
  min_severity?: Severity;
}

export interface WebhookConfig {
  url: string;
  method: 'POST' | 'PUT';
  headers?: Record<string, string>;
  min_severity?: Severity;
}

// ============================================================================
// Notification Payloads
// ============================================================================

export interface NotificationPayload {
  event: SecurityEvent;
  config: MundConfig;
  formatted_message: string;
}

// ============================================================================
// API Types
// ============================================================================

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  timestamp: Date;
}

export interface PaginatedResponse<T> extends ApiResponse<T[]> {
  total: number;
  offset: number;
  limit: number;
  has_more: boolean;
}

// ============================================================================
// Tool Input/Output Types
// ============================================================================

export interface ScanContentInput {
  content: string;
  content_type?: 'text' | 'code' | 'json' | 'yaml';
  context?: EventContext;
}

export interface CheckUrlInput {
  url: string;
  context?: EventContext;
}

export interface ValidateCommandInput {
  command: string;
  context?: EventContext;
}

export interface GetEventsInput {
  limit?: number;
  offset?: number;
  severity?: Severity;
  type?: DetectorType;
  start_time?: Date;
  end_time?: Date;
  acknowledged?: boolean;
}

export interface AddRuleInput {
  id: string;
  name: string;
  description?: string;
  type: DetectorType;
  pattern?: string;
  condition?: string;
  severity: Severity;
  action: ActionType;
  metadata?: Record<string, unknown>;
}

export interface ConfigureNotificationInput {
  type: 'slack' | 'teams' | 'email' | 'webhook';
  config: SlackConfig | TeamsConfig | EmailConfig | WebhookConfig;
}

// ============================================================================
// Storage Interface
// ============================================================================

export interface IStorage {
  // Events
  saveEvent(event: SecurityEvent): Promise<void>;
  getEvent(id: string): Promise<SecurityEvent | null>;
  getEvents(query: GetEventsInput): Promise<SecurityEvent[]>;
  countEvents(query: GetEventsInput): Promise<number>;
  acknowledgeEvent(id: string, by?: string): Promise<void>;
  
  // Rules
  saveRule(rule: DetectionRule): Promise<void>;
  getRule(id: string): Promise<DetectionRule | null>;
  getRules(): Promise<DetectionRule[]>;
  deleteRule(id: string): Promise<void>;
  
  // Allowlist/Blocklist
  addToAllowlist(pattern: string, type: DetectorType): Promise<void>;
  addToBlocklist(pattern: string, type: DetectorType): Promise<void>;
  getAllowlist(type?: DetectorType): Promise<string[]>;
  getBlocklist(type?: DetectorType): Promise<string[]>;
  removeFromAllowlist(pattern: string): Promise<void>;
  removeFromBlocklist(pattern: string): Promise<void>;
  
  // Cleanup
  close(): Promise<void>;
}

// ============================================================================
// Analyzer Interface
// ============================================================================

export interface IAnalyzer {
  name: string;
  type: DetectorType;
  analyze(content: string, rules: DetectionRule[]): Promise<SecurityIssue[]>;
}

// ============================================================================
// Notifier Interface
// ============================================================================

export interface INotifier {
  name: string;
  send(payload: NotificationPayload): Promise<boolean>;
}
