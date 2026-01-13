/**
 * Dōmere - The Judge Protocol
 * Type Definitions
 */

// ============================================================================
// Thread Identity Types
// ============================================================================

export interface Thread {
  id: string;
  
  origin: ThreadOrigin;
  intent: ThreadIntent;
  hops: ThreadHop[];
  
  weave_signature: string;        // Rolling signature of entire thread
  merkle_root?: string;           // Merkle root of all hops
  
  status: ThreadStatus;
  created_at: Date;
  updated_at: Date;
  closed_at?: Date;
  
  metadata: Record<string, unknown>;
}

export type ThreadStatus = 
  | 'active'      // Thread is in progress
  | 'complete'    // Successfully completed
  | 'violated'    // Policy violation detected
  | 'disputed'    // Under arbitration
  | 'abandoned';  // Timed out or abandoned

export interface ThreadOrigin {
  type: 'human' | 'system' | 'scheduled' | 'delegated';
  identity: string;               // User ID, system ID, cron reference, or parent thread
  verification?: VerificationInfo;
  timestamp: Date;
  context?: Record<string, unknown>;
}

export interface VerificationInfo {
  method: 'sso' | 'oauth' | 'api_key' | 'certificate' | 'spiffe' | 'none';
  provider?: string;
  verified: boolean;
  verified_at?: Date;
  claims?: Record<string, unknown>;
}

export interface ThreadIntent {
  raw: string;                    // Original request text
  hash: string;                   // Cryptographic hash of intent
  normalized?: string;            // Normalized/cleaned version
  
  classification: IntentClassification;
  constraints: string[];          // What it should NOT do
  
  entities: ExtractedEntity[];    // Entities mentioned
  actions_implied: string[];      // What the intent implies will happen
  
  language_analysis?: LanguageAnalysis;
}

export type IntentClassification = 
  | 'query'       // Read/fetch data
  | 'mutation'    // Create/update data
  | 'deletion'    // Delete data
  | 'execution'   // Run code/command
  | 'communication' // Send message/email
  | 'analysis'    // Analyze/summarize
  | 'generation'  // Create content
  | 'unknown';

export interface ThreadHop {
  sequence: number;
  hop_id: string;
  
  agent: AgentInfo;
  
  // Intent verification
  received_intent: string;
  received_intent_hash: string;
  intent_preserved: boolean;
  intent_drift: DriftAnalysis;
  
  // Actions
  actions: HopAction[];
  
  // Security checks
  language_analysis: LanguageAnalysis;
  security_scan?: SecurityScanResult;
  sandbox_result?: SandboxReference;
  
  // Cryptographic proof
  hop_signature: string;
  cumulative_hash: string;        // Hash including all previous hops
  
  // Timing
  started_at: Date;
  completed_at: Date;
  duration_ms: number;
  
  // Outcome
  status: 'success' | 'failure' | 'blocked' | 'timeout';
  error?: string;
}

export interface AgentInfo {
  id: string;
  type: string;                   // 'claude', 'gpt', 'custom', etc.
  version?: string;
  capabilities?: string[];
  metadata?: Record<string, unknown>;
}

export interface HopAction {
  type: ActionType;
  target?: string;
  description: string;
  input_hash?: string;
  output_hash?: string;
  timestamp: Date;
  metadata?: Record<string, unknown>;
}

export type ActionType = 
  | 'route'       // Route to another agent
  | 'query'       // Query data
  | 'mutate'      // Modify data
  | 'execute'     // Execute code
  | 'generate'    // Generate content
  | 'send'        // Send communication
  | 'analyze'     // Analyze content
  | 'transform'   // Transform data
  | 'validate'    // Validate something
  | 'other';

// ============================================================================
// Language Analysis Types
// ============================================================================

export interface LanguageAnalysis {
  detected_languages: DetectedLanguage[];
  primary_language: string;
  confidence: number;
  
  semantic?: SemanticAnalysis;
  code_analysis?: CodeAnalysis;
  nl_analysis?: NLAnalysis;
}

export interface DetectedLanguage {
  language: LanguageType;
  confidence: number;
  segments: LanguageSegment[];
}

export type LanguageType = 
  // Natural languages
  | 'english' | 'spanish' | 'french' | 'german' | 'chinese' | 'japanese'
  // Programming languages
  | 'javascript' | 'typescript' | 'python' | 'java' | 'csharp' | 'go' | 'rust'
  | 'ruby' | 'php' | 'swift' | 'kotlin' | 'scala' | 'r'
  // Data/Config languages
  | 'sql' | 'json' | 'yaml' | 'xml' | 'html' | 'css' | 'markdown'
  | 'toml' | 'ini' | 'csv'
  // Shell/Script
  | 'bash' | 'powershell' | 'shell'
  // Other
  | 'regex' | 'graphql' | 'protobuf'
  | 'unknown' | 'mixed';

export interface LanguageSegment {
  start: number;
  end: number;
  language: LanguageType;
  content: string;
  confidence: number;
}

export interface SemanticAnalysis {
  intent_classification: IntentClassification;
  entities: ExtractedEntity[];
  actions_implied: string[];
  topics: string[];
  sentiment?: number;             // -1 to 1
  formality?: number;             // 0 to 1
  urgency?: number;               // 0 to 1
}

export interface ExtractedEntity {
  type: EntityType;
  value: string;
  normalized?: string;
  confidence: number;
  position: { start: number; end: number };
  metadata?: Record<string, unknown>;
}

export type EntityType = 
  | 'person' | 'organization' | 'location' | 'datetime'
  | 'money' | 'percent' | 'quantity'
  | 'email' | 'phone' | 'url' | 'ip_address'
  | 'file_path' | 'database' | 'table' | 'api_endpoint'
  | 'credential' | 'pii'
  | 'custom';

export interface CodeAnalysis {
  language: LanguageType;
  
  // Structure
  functions: string[];
  classes: string[];
  imports: string[];
  exports: string[];
  
  // Security
  dangerous_patterns: DangerousPattern[];
  data_flows: DataFlow[];
  external_calls: ExternalCall[];
  
  // Quality
  complexity_score?: number;
  
  // Recommendations
  sandbox_required: boolean;
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  recommendations: string[];
}

export interface DangerousPattern {
  pattern: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  line?: number;
  column?: number;
  recommendation: string;
}

export interface DataFlow {
  source: string;
  destination: string;
  data_type?: string;
  sensitive: boolean;
}

export interface ExternalCall {
  type: 'http' | 'database' | 'file' | 'process' | 'network' | 'other';
  target: string;
  method?: string;
  risk_level: 'low' | 'medium' | 'high';
}

export interface NLAnalysis {
  // Manipulation detection
  manipulation_score: number;     // 0-1
  manipulation_indicators: ManipulationIndicator[];
  
  // Authority/instruction analysis
  authority_claims: string[];
  instruction_overrides: string[];
  hidden_instructions: HiddenInstruction[];
  
  // Jailbreak detection
  jailbreak_score: number;        // 0-1
  jailbreak_patterns: string[];
  
  // Overall assessment
  risk_level: 'low' | 'medium' | 'high' | 'critical';
}

export interface ManipulationIndicator {
  type: string;
  description: string;
  evidence: string;
  severity: 'low' | 'medium' | 'high';
}

export interface HiddenInstruction {
  instruction: string;
  encoding?: string;              // 'base64', 'unicode', 'steganographic', etc.
  position: { start: number; end: number };
  confidence: number;
}

// ============================================================================
// Intent Drift Types
// ============================================================================

export interface DriftAnalysis {
  original_intent: string;
  current_interpretation: string;
  
  metrics: DriftMetrics;
  cumulative_drift: number;       // 0-1, total drift so far
  hop_drift: number;              // 0-1, drift at this hop specifically
  
  max_acceptable_drift: number;   // Policy-defined threshold
  
  verdict: 'aligned' | 'minor_drift' | 'significant_drift' | 'violated';
  explanation: string;
  
  constraint_violations: string[];
}

export interface DriftMetrics {
  semantic_similarity: number;    // 0-1
  action_alignment: number;       // 0-1
  scope_creep: number;            // 0-1, negative means scope narrowed
  entity_preservation: number;    // 0-1, are same entities referenced
  constraint_adherence: number;   // 0-1
}

// ============================================================================
// Security Types
// ============================================================================

export interface SecurityScanResult {
  scanner: 'mund' | 'custom';
  timestamp: Date;
  
  clean: boolean;
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  
  findings: SecurityFinding[];
  
  scan_duration_ms: number;
}

export interface SecurityFinding {
  type: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  description: string;
  evidence?: string;
  recommendation?: string;
  false_positive_likelihood?: number;
}

export interface SandboxReference {
  sandbox_id: string;
  result_id: string;
  status: 'safe' | 'review' | 'blocked';
  summary: string;
}

// ============================================================================
// Compliance Types
// ============================================================================

export interface CompliancePolicy {
  id: string;
  name: string;
  version: string;
  description: string;
  
  rules: ComplianceRule[];
  
  jurisdiction?: string;
  effective_date: Date;
  
  metadata?: Record<string, unknown>;
}

export interface ComplianceRule {
  id: string;
  description: string;
  
  // What to check
  condition: RuleCondition;
  
  // Outcome
  severity: 'info' | 'warning' | 'violation' | 'critical';
  remediation?: string;
  
  // Evidence
  evidence_required: string[];
}

export interface RuleCondition {
  type: 'intent' | 'action' | 'data' | 'agent' | 'drift' | 'custom';
  operator: 'equals' | 'contains' | 'matches' | 'exceeds' | 'custom';
  value: unknown;
  custom_fn?: string;             // For custom conditions
}

export interface ComplianceResult {
  thread_id: string;
  policy_id: string;
  policy_version: string;
  
  compliant: boolean;
  violations: ComplianceViolation[];
  warnings: ComplianceWarning[];
  
  checked_at: Date;
  
  proof?: ComplianceProof;
}

export interface ComplianceViolation {
  rule_id: string;
  rule_description: string;
  severity: 'violation' | 'critical';
  
  evidence: string;
  hop_id?: string;
  
  remediation?: string;
}

export interface ComplianceWarning {
  rule_id: string;
  rule_description: string;
  
  evidence: string;
  hop_id?: string;
}

export interface ComplianceProof {
  id: string;
  thread_id: string;
  policy_id: string;
  
  claims: ProofClaim[];
  
  proof_type: 'hash' | 'merkle' | 'zk';
  proof_data: string;
  
  generated_at: Date;
  
  anchor?: AnchorReference;
}

export interface ProofClaim {
  claim: string;
  evidence_hash: string;
  verified: boolean;
}

// ============================================================================
// Anchoring Types
// ============================================================================

export type BlockchainNetwork = 'solana' | 'ethereum' | 'solana-devnet' | 'ethereum-sepolia';

export interface AnchorRequest {
  thread_id: string;
  merkle_root: string;
  hop_count: number;
  intent_hash: string;
  compliant: boolean;
  
  network: BlockchainNetwork;
  wallet?: WalletInfo;            // User provides their wallet
}

export interface WalletInfo {
  type: 'solana' | 'ethereum';
  public_key: string;
  // Private key is NEVER stored - signing happens client-side
}

export interface AnchorResult {
  success: boolean;
  
  network: BlockchainNetwork;
  transaction_id: string;
  block?: number;
  slot?: number;                  // Solana
  timestamp: Date;
  
  // Costs
  network_fee: string;
  protocol_fee: string;
  total_cost: string;
  
  // Verification
  verification_url: string;
  
  error?: string;
}

export interface AnchorReference {
  network: BlockchainNetwork;
  transaction_id: string;
  block?: number;
  slot?: number;
  timestamp: Date;
  verified: boolean;
}

export interface AnchorVerification {
  valid: boolean;
  
  thread_id: string;
  merkle_root: string;
  
  anchor: AnchorReference;
  
  on_chain_data?: {
    merkle_root: string;
    hop_count: number;
    intent_hash: string;
    compliant: boolean;
    timestamp: number;
    anchorer: string;
  };
  
  verified_at: Date;
  error?: string;
}

// ============================================================================
// Arbitration Types
// ============================================================================

export interface ArbitrationCase {
  id: string;
  thread_id: string;
  
  dispute: Dispute;
  
  status: 'open' | 'evidence' | 'review' | 'resolved' | 'appealed';
  
  evidence: ArbitrationEvidence[];
  
  resolution?: Resolution;
  
  created_at: Date;
  updated_at: Date;
  resolved_at?: Date;
  
  anchor?: AnchorReference;
}

export interface Dispute {
  type: DisputeType;
  description: string;
  agents_involved: string[];
  
  claimed_by: string;
  claimed_at: Date;
}

export type DisputeType = 
  | 'intent_conflict'     // Agents disagree on intent
  | 'resource_conflict'   // Competing for same resource
  | 'result_conflict'     // Different results from same input
  | 'policy_violation'    // Alleged policy violation
  | 'drift_dispute'       // Dispute over intent drift
  | 'other';

export interface ArbitrationEvidence {
  id: string;
  case_id: string;
  
  type: 'thread' | 'hop' | 'scan' | 'attestation' | 'document' | 'other';
  description: string;
  
  data_hash: string;
  data?: unknown;                 // Actual evidence data
  
  submitted_by: string;
  submitted_at: Date;
}

export interface Resolution {
  method: 'automatic' | 'human' | 'committee';
  
  decision: string;
  reasoning: string;
  
  outcome: 'upheld' | 'rejected' | 'partial' | 'withdrawn';
  
  actions_required: ResolutionAction[];
  policy_updates?: string[];
  
  resolved_by: string;
  resolved_at: Date;
  
  dissenting_opinions?: string[];
}

export interface ResolutionAction {
  action: string;
  target: string;
  deadline?: Date;
  completed?: boolean;
}

// ============================================================================
// Storage Types
// ============================================================================

export interface IDomereStorage {
  // Threads
  saveThread(thread: Thread): Promise<void>;
  getThread(id: string): Promise<Thread | null>;
  updateThread(thread: Thread): Promise<void>;
  listThreads(filters?: ThreadFilters): Promise<Thread[]>;
  
  // Hops
  addHop(threadId: string, hop: ThreadHop): Promise<void>;
  getHops(threadId: string): Promise<ThreadHop[]>;
  
  // Compliance
  saveComplianceResult(result: ComplianceResult): Promise<void>;
  getComplianceResults(threadId: string): Promise<ComplianceResult[]>;
  
  // Policies
  savePolicy(policy: CompliancePolicy): Promise<void>;
  getPolicy(id: string): Promise<CompliancePolicy | null>;
  listPolicies(): Promise<CompliancePolicy[]>;
  
  // Anchors
  saveAnchor(threadId: string, anchor: AnchorReference): Promise<void>;
  getAnchors(threadId: string): Promise<AnchorReference[]>;
  
  // Arbitration
  saveCase(case_: ArbitrationCase): Promise<void>;
  getCase(id: string): Promise<ArbitrationCase | null>;
  listCases(filters?: CaseFilters): Promise<ArbitrationCase[]>;
  
  // Evidence
  saveEvidence(evidence: ArbitrationEvidence): Promise<void>;
  getEvidence(caseId: string): Promise<ArbitrationEvidence[]>;
}

export interface ThreadFilters {
  status?: ThreadStatus;
  origin_type?: ThreadOrigin['type'];
  origin_identity?: string;
  since?: Date;
  until?: Date;
  limit?: number;
  offset?: number;
}

export interface CaseFilters {
  status?: ArbitrationCase['status'];
  dispute_type?: DisputeType;
  thread_id?: string;
  limit?: number;
  offset?: number;
}

// ============================================================================
// Configuration Types
// ============================================================================

export interface DomereConfig {
  port: number;
  host: string;
  transport: 'stdio' | 'http';
  log_level: 'debug' | 'info' | 'warn' | 'error';
  storage: 'memory' | 'sqlite';
  
  // Language analysis
  language: {
    enable_semantic: boolean;
    enable_code_analysis: boolean;
    enable_nl_analysis: boolean;
  };
  
  // Drift detection
  drift: {
    max_acceptable_drift: number;   // 0-1, default 0.3
    warn_threshold: number;         // 0-1, default 0.2
  };
  
  // Anchoring
  anchoring: {
    solana_rpc: string;
    solana_program_id: string;
    ethereum_rpc: string;
    ethereum_contract: string;
    protocol_fee_bps: number;       // Basis points, 500 = 5%
  };
  
  // Integration
  integration: {
    mund_url?: string;
    hord_url?: string;
  };
}

// ============================================================================
// Error Types
// ============================================================================

export class DomereError extends Error {
  constructor(
    message: string,
    public code: string,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'DomereError';
  }
}

export class ThreadError extends DomereError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'THREAD_ERROR', details);
    this.name = 'ThreadError';
  }
}

export class LanguageAnalysisError extends DomereError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'LANGUAGE_ERROR', details);
    this.name = 'LanguageAnalysisError';
  }
}

export class ComplianceError extends DomereError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'COMPLIANCE_ERROR', details);
    this.name = 'ComplianceError';
  }
}

export class AnchoringError extends DomereError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'ANCHORING_ERROR', details);
    this.name = 'AnchoringError';
  }
}

export class ArbitrationError extends DomereError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'ARBITRATION_ERROR', details);
    this.name = 'ArbitrationError';
  }
}
