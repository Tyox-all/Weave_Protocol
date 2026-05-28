/**
 * Types for the Microsoft Agent Framework adapter.
 *
 * MSAF supports three middleware types (per the v1.0 docs):
 *   1. Agent middleware    — wraps full agent runs (once per turn)
 *   2. Function middleware — wraps individual tool calls
 *   3. Chat middleware     — wraps raw model requests
 *
 * For WARD enforcement we primarily care about function middleware
 * (since WARD gates tool calls), but we also expose an agent-middleware
 * variant for users who want a turn-level gate.
 */

/**
 * A proposed function/tool call that MSAF is about to execute.
 * Shape mirrors what MSAF's function middleware exposes via its context.
 */
export interface MsafToolCall {
  toolName: string;
  args: Record<string, unknown>;
  // The MSAF context carries more, but we only need name + args for WARD.
  raw?: unknown;
}

/**
 * Result of a WARD evaluation for an MSAF middleware.
 */
export interface MsafMiddlewareResult {
  decision: 'allow' | 'deny' | 'require_approval';
  reasons: string[];
  policySource?: string;
}

/**
 * Standardized error thrown by the middleware when a call is denied.
 * MSAF middleware short-circuits by throwing (or by not calling next()),
 * so we provide a typed error so users can catch and handle it.
 */
export class WardDeniedError extends Error {
  public readonly decision: 'deny' | 'require_approval';
  public readonly reasons: string[];
  public readonly policySource: string | undefined;
  public readonly toolName: string;

  constructor(
    decision: 'deny' | 'require_approval',
    reasons: string[],
    toolName: string,
    policySource?: string,
  ) {
    super(
      `WARD ${decision === 'deny' ? 'denied' : 'requires approval for'} tool '${toolName}': ${reasons.join(' | ')}`,
    );
    this.name = 'WardDeniedError';
    this.decision = decision;
    this.reasons = reasons;
    this.policySource = policySource;
    this.toolName = toolName;
  }
}

/**
 * Mapping from MSAF tool names to their nature.
 *
 * MSAF tools are user-defined, but several conventions are widely
 * established (especially through the Copilot/Claude Code SDK harness
 * integrations and the local agent runtime which exposes shell/file/
 * messaging tools). The mappings below cover those well-known names.
 *
 * Users can also register custom mappings via MiddlewareOptions.toolMappings.
 */
export interface ToolMapping {
  capability: string;
  pathField?: string;
  fsOp?: 'read' | 'write' | 'execute' | 'delete' | 'list';
  urlField?: string;
  commandField?: string;
}

export const TOOL_MAPPINGS: Record<string, ToolMapping> = {
  // MSAF local agent runtime tools
  ShellExec: { capability: 'shell_exec', commandField: 'command' },
  Bash: { capability: 'shell_exec', commandField: 'command' },
  FileRead: { capability: 'file_read', pathField: 'path', fsOp: 'read' },
  FileWrite: { capability: 'file_write', pathField: 'path', fsOp: 'write' },
  FileEdit: { capability: 'file_write', pathField: 'path', fsOp: 'write' },
  FileDelete: { capability: 'file_delete', pathField: 'path', fsOp: 'delete' },
  ListDirectory: { capability: 'file_list', pathField: 'path', fsOp: 'list' },
  HttpRequest: { capability: 'http_request', urlField: 'url' },
  WebFetch: { capability: 'http_request', urlField: 'url' },

  // Copilot SDK integration patterns
  RunCommand: { capability: 'shell_exec', commandField: 'command' },
  EditFile: { capability: 'file_write', pathField: 'file_path', fsOp: 'write' },
  ReadFile: { capability: 'file_read', pathField: 'file_path', fsOp: 'read' },

  // Claude Code SDK integration (via MSAF) - share with adapter-claudecode names
  Bash_via_claude: { capability: 'shell_exec', commandField: 'command' },
  Edit: { capability: 'file_write', pathField: 'file_path', fsOp: 'write' },
  Write: { capability: 'file_write', pathField: 'file_path', fsOp: 'write' },
  Read: { capability: 'file_read', pathField: 'file_path', fsOp: 'read' },

  // Common workflow/automation tools
  SendEmail: { capability: 'send_email' },
  PostMessage: { capability: 'send_message' },
  CreateIssue: { capability: 'create_issue' },
  Subagent: { capability: 'subagent' },
};

/**
 * Options when creating a WardMiddleware instance.
 */
export interface MiddlewareOptions {
  /**
   * Explicit path to a WARD.md file. If omitted, resolves via:
   *   $WEAVE_WARD_PATH → <cwd>/WARD.md → <cwd>/.weave/WARD.md → <cwd>/.msaf/WARD.md
   */
  wardPath?: string;

  /**
   * Raw WARD.md content (alternative to wardPath). Useful for tests or
   * embedding the policy in code.
   */
  wardSource?: string;

  /**
   * Custom tool name → capability mappings. Merged on top of the built-in
   * TOOL_MAPPINGS so users can override or add.
   */
  toolMappings?: Record<string, ToolMapping>;

  /**
   * Fail mode:
   *   - 'open' (default): if WARD can't be loaded, allow the call and warn
   *   - 'closed': if WARD can't be loaded, deny the call
   */
  failMode?: 'open' | 'closed';

  /**
   * Optional callback when a call is allowed. Useful for logging/attestation.
   */
  onAllow?: (call: MsafToolCall, result: MsafMiddlewareResult) => void | Promise<void>;

  /**
   * Optional callback when a call is denied. Useful for alerting.
   * If you return false, the call is allowed despite the WARD decision.
   * (Generally don't do that — but it's available for emergency overrides.)
   */
  onDeny?: (call: MsafToolCall, result: MsafMiddlewareResult) => boolean | void | Promise<boolean | void>;
}
