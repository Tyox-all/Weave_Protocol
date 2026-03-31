/**
 * Weave Protocol LangChain Integration Types
 * @weave_protocol/langchain
 */

// ============================================================================
// Security Configuration
// ============================================================================

export type SecurityAction = 'block' | 'warn' | 'log' | 'passthrough';

export type ScanTarget = 'input' | 'output' | 'both';

export interface SecurityConfig {
  /** Action to take when threats are detected */
  action: SecurityAction;
  
  /** What to scan: input, output, or both */
  scanTarget: ScanTarget;
  
  /** Minimum severity to trigger action */
  minSeverity: 'low' | 'medium' | 'high' | 'critical';
  
  /** Categories to scan for */
  categories?: string[];
  
  /** Whether to scan tool inputs/outputs */
  scanTools: boolean;
  
  /** Whether to scan retriever results */
  scanRetrievers: boolean;
  
  /** Whether to include MITRE ATT&CK info in logs */
  includeMitre: boolean;
  
  /** Custom callback for security events */
  onSecurityEvent?: (event: SecurityEvent) => void | Promise<void>;
  
  /** Mund API endpoint (if using remote) */
  mundEndpoint?: string;
  
  /** Hundredmen session ID (for drift detection) */
  hundredmenSessionId?: string;
}

export const DEFAULT_CONFIG: SecurityConfig = {
  action: 'warn',
  scanTarget: 'both',
  minSeverity: 'medium',
  scanTools: true,
  scanRetrievers: true,
  includeMitre: true,
};

// ============================================================================
// Security Events
// ============================================================================

export type SecurityEventType = 
  | 'threat_detected'
  | 'scan_completed'
  | 'action_blocked'
  | 'tool_intercepted'
  | 'retriever_scanned';

export interface ThreatMatch {
  patternId: string;
  patternName: string;
  category: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  matchedText: string;
  mitreId?: string;
  mitreTactic?: string;
}

export interface SecurityEvent {
  type: SecurityEventType;
  timestamp: Date;
  source: 'llm' | 'chain' | 'tool' | 'retriever' | 'agent';
  sourceName?: string;
  direction: 'input' | 'output';
  content: string;
  contentLength: number;
  threats: ThreatMatch[];
  actionTaken: SecurityAction;
  blocked: boolean;
  scanDurationMs: number;
  metadata?: Record<string, any>;
}

// ============================================================================
// Scan Results
// ============================================================================

export interface ScanResult {
  safe: boolean;
  threatCount: number;
  threats: ThreatMatch[];
  highestSeverity: 'low' | 'medium' | 'high' | 'critical' | null;
  scanDurationMs: number;
  recommendations: string[];
}

// ============================================================================
// Tool & Retriever Wrappers
// ============================================================================

export interface SecureToolConfig {
  /** Tool name for logging */
  name: string;
  
  /** Security config overrides */
  security?: Partial<SecurityConfig>;
  
  /** Allowed input patterns (regex strings) */
  allowedInputPatterns?: string[];
  
  /** Blocked input patterns (regex strings) */
  blockedInputPatterns?: string[];
  
  /** Maximum input length */
  maxInputLength?: number;
  
  /** Require explicit approval for this tool */
  requireApproval?: boolean;
}

export interface SecureRetrieverConfig {
  /** Retriever name for logging */
  name: string;
  
  /** Security config overrides */
  security?: Partial<SecurityConfig>;
  
  /** Scan retrieved documents */
  scanDocuments: boolean;
  
  /** Maximum documents to scan */
  maxDocumentsToScan?: number;
  
  /** Redact sensitive content from results */
  redactSensitive?: boolean;
}

// ============================================================================
// Callback Stats
// ============================================================================

export interface CallbackStats {
  totalScans: number;
  threatsDetected: number;
  actionsBlocked: number;
  scansBySource: Record<string, number>;
  threatsByCategory: Record<string, number>;
  threatsBySeverity: Record<string, number>;
  averageScanTimeMs: number;
  startTime: Date;
}

// ============================================================================
// Integration Options
// ============================================================================

export interface WeaveIntegrationOptions {
  /** Use local Mund instance */
  useLocalMund?: boolean;
  
  /** Mund API endpoint */
  mundEndpoint?: string;
  
  /** API key for remote Mund */
  mundApiKey?: string;
  
  /** Enable Hundredmen integration for drift detection */
  enableHundredmen?: boolean;
  
  /** Hundredmen endpoint */
  hundredmenEndpoint?: string;
  
  /** Agent ID for Hundredmen session */
  agentId?: string;
  
  /** Declared intent for Hundredmen */
  declaredIntent?: string;
  
  /** Enable verbose logging */
  verbose?: boolean;
}
