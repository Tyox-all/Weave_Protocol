/**
 * @weave_protocol/ward - Type definitions
 *
 * A WARD.md file declares the security policy for an AI agent. It pairs
 * with AGENTS.md (the agent's purpose) and SKILL.md (the agent's
 * capabilities) to form the complete infrastructure-as-code definition
 * for an agentic system.
 *
 * Structure:
 *   - YAML frontmatter for machine-readable metadata
 *   - Markdown sections for each policy domain
 *   - Each section parses to a typed sub-policy
 */

export type WardVersion = "1.0";

/**
 * Top-level parsed WARD policy.
 */
export interface WardPolicy {
  /** Spec version (always "1.0" for now). */
  version: WardVersion;
  /** Optional reference to an AGENTS.md file (relative path or ID). */
  agent?: string;
  /** Optional human-readable name for the policy. */
  name?: string;
  /** Optional description. */
  description?: string;
  /** Defines what the agent is permitted to do on the filesystem. */
  filesystem?: FilesystemPolicy;
  /** Defines what network endpoints the agent can reach. */
  network?: NetworkPolicy;
  /** Defines which tool/capability invocations are allowed. */
  capabilities?: CapabilitiesPolicy;
  /** Controls what kinds of data can leave the agent's boundary. */
  dataBoundaries?: DataBoundariesPolicy;
  /** Resource limits — iterations, runtime, spend, tokens. */
  behavioral?: BehavioralPolicy;
  /** Multi-agent trust and isolation rules. */
  multiAgent?: MultiAgentPolicy;
  /** Compliance frameworks that auto-apply additional rules. */
  compliance?: CompliancePolicy;
  /** Required verification/attestation parameters. */
  verification?: VerificationPolicy;
  /** Threat model declaration. */
  threatModel?: ThreatModelPolicy;
  /** What to do when policy is violated. */
  incidentResponse?: IncidentResponsePolicy;
  /** Any unrecognized sections preserved as raw text. */
  raw?: Record<string, string>;
}

// ─────────────────────────────────────────────────────────
// Filesystem
// ─────────────────────────────────────────────────────────

export interface FilesystemPolicy {
  allow?: FilesystemRule[];
  deny?: FilesystemRule[];
  /** Default action when no rule matches. */
  default?: "allow" | "deny";
}

export interface FilesystemRule {
  /** Operation: read, write, execute, delete, list. */
  op: FilesystemOp;
  /** Glob pattern (e.g., "/workspace/**", "~/Documents/*.txt"). */
  path: string;
}

export type FilesystemOp = "read" | "write" | "execute" | "delete" | "list";

// ─────────────────────────────────────────────────────────
// Network
// ─────────────────────────────────────────────────────────

export interface NetworkPolicy {
  allow?: NetworkRule[];
  deny?: NetworkRule[];
  default?: "allow" | "deny";
}

export interface NetworkRule {
  /** URL pattern with glob support (e.g., "https://api.company.com/**"). */
  url: string;
  /** Optional method restriction. */
  methods?: HttpMethod[];
}

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";

// ─────────────────────────────────────────────────────────
// Capabilities (tools / function calls)
// ─────────────────────────────────────────────────────────

export interface CapabilitiesPolicy {
  /** Tools that may be called. */
  allow?: string[];
  /** Tools that may NOT be called (overrides allow if conflicting). */
  deny?: string[];
  /** Tools that require human-in-the-loop approval before execution. */
  requireApproval?: string[];
  /** Default action when a tool is not listed. */
  default?: "allow" | "deny";
}

// ─────────────────────────────────────────────────────────
// Data boundaries
// ─────────────────────────────────────────────────────────

export interface DataBoundariesPolicy {
  /** Data classifications allowed to leave the agent. */
  egressAllow?: DataClassification[];
  /** Data classifications that must never leave the agent. */
  egressDeny?: DataClassification[];
  /** Redaction rules to apply to any outbound data. */
  redact?: RedactionRule[];
}

export type DataClassification =
  | "public"
  | "internal"
  | "confidential"
  | "secret"
  | "pii"
  | "phi"
  | "pci"
  | "credentials";

export interface RedactionRule {
  /** Type of data to redact. */
  type: DataClassification | string;
  /** Replacement string (e.g., "[REDACTED]"). */
  replacement?: string;
}

// ─────────────────────────────────────────────────────────
// Behavioral limits
// ─────────────────────────────────────────────────────────

export interface BehavioralPolicy {
  /** Max number of agent loop iterations. */
  maxIterations?: number;
  /** Max total runtime in seconds. */
  maxRuntimeSeconds?: number;
  /** Max cost in USD (uses provider's reported cost). */
  maxCostUSD?: number;
  /** Max total tokens consumed. */
  maxTokens?: number;
  /** Max number of tool invocations. */
  maxToolCalls?: number;
  /** Max number of distinct external services contacted. */
  maxExternalServices?: number;
}

// ─────────────────────────────────────────────────────────
// Multi-agent
// ─────────────────────────────────────────────────────────

export interface MultiAgentPolicy {
  /** Trust chain — which agents can hand work to this one, and vice versa. */
  trustChain?: TrustChain;
  /** Isolation level between this agent and others in the harness. */
  isolation?: IsolationLevel;
  /** Semantic drift threshold (0-1). If intent drifts more than this between
   *  agent handoffs, halt and require attestation. */
  maxSemanticDrift?: number;
}

export interface TrustChain {
  /** Agents that may invoke this agent. */
  upstream?: string[];
  /** Agents this agent may invoke. */
  downstream?: string[];
}

export type IsolationLevel = "none" | "soft" | "strict" | "sandboxed";

// ─────────────────────────────────────────────────────────
// Compliance
// ─────────────────────────────────────────────────────────

export interface CompliancePolicy {
  /** Frameworks to apply (auto-injects additional rules). */
  frameworks?: ComplianceFramework[];
  /** Required to use a specific compliance backend. */
  backend?: "domere" | "custom";
}

export type ComplianceFramework =
  | "soc2"
  | "hipaa"
  | "pci-dss"
  | "iso27001"
  | "gdpr"
  | "ccpa"
  | "fedramp"
  | "nist-csf";

// ─────────────────────────────────────────────────────────
// Verification / attestation
// ─────────────────────────────────────────────────────────

export interface VerificationPolicy {
  /** Whether attestation is required. */
  required?: boolean;
  /** Backend to use. */
  backend?: "domere" | "custom";
  /** Blockchain to anchor to. */
  blockchain?: "solana" | "ethereum" | "polygon" | "none";
  /** How often to attest. */
  frequency?: AttestationFrequency;
  /** Public key or DID for the attesting party. */
  attestor?: string;
}

export type AttestationFrequency =
  | "every_action"
  | "every_handoff"
  | "every_iteration"
  | "session_end"
  | "manual";

// ─────────────────────────────────────────────────────────
// Threat model
// ─────────────────────────────────────────────────────────

export interface ThreatModelPolicy {
  /** Threats this policy is designed to defend against. */
  inScope?: ThreatCategory[];
  /** Threats explicitly NOT covered (informational). */
  outOfScope?: ThreatCategory[];
}

export type ThreatCategory =
  | "prompt_injection"
  | "data_exfil"
  | "credential_theft"
  | "supply_chain"
  | "model_extraction"
  | "jailbreak"
  | "tool_misuse"
  | "semantic_drift"
  | "emergent_behavior"
  | "side_channel"
  | "physical_attack"
  | "denial_of_service"
  | string;

// ─────────────────────────────────────────────────────────
// Incident response
// ─────────────────────────────────────────────────────────

export interface IncidentResponsePolicy {
  /** Actions to take when a violation is detected. */
  onViolation?: ViolationAction[];
  /** Severity threshold above which to take action. */
  severityThreshold?: ViolationSeverity;
}

export interface ViolationAction {
  type: ViolationActionType;
  /** Only apply this action for violations at or above this severity. */
  minSeverity?: ViolationSeverity;
  /** Optional target (email, webhook URL, etc.). */
  target?: string;
}

export type ViolationActionType =
  | "log"
  | "alert"
  | "terminate"
  | "rollback"
  | "attest_violation"
  | "notify_human"
  | "block_further";

export type ViolationSeverity = "low" | "medium" | "high" | "critical";

// ─────────────────────────────────────────────────────────
// Validation results
// ─────────────────────────────────────────────────────────

export interface ValidationResult {
  valid: boolean;
  errors: ValidationIssue[];
  warnings: ValidationIssue[];
  policy?: WardPolicy;
}

export interface ValidationIssue {
  level: "error" | "warning";
  section?: string;
  message: string;
  suggestion?: string;
}
