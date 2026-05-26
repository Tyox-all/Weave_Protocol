/**
 * Types for the Google Antigravity adapter.
 */

/**
 * Shape of the JSON payload Antigravity sends to a hook on stdin.
 * Based on the JSON hook format introduced in Antigravity 2.0, which
 * mirrors the Claude Code hook payload shape closely.
 */
export interface AntigravityHookInput {
  session_id?: string;
  transcript_path?: string;
  cwd?: string;
  hook_event_name?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  tool_response?: unknown;
}

/**
 * JSON returned on stdout to control Antigravity's behavior.
 *
 * For PreToolUse hooks:
 *   - { "decision": "approve" }                → auto-approve
 *   - { "decision": "block", "reason": "..." } → block the call with reason
 *   - {} (or no output)                        → default behavior
 */
export interface AntigravityHookOutput {
  decision?: 'approve' | 'block';
  reason?: string;
  continue?: boolean;
  stopReason?: string;
  systemMessage?: string;
  suppressOutput?: boolean;
}

/**
 * Hook lifecycle event types in Antigravity 2.0.
 * v0.1 ships PreToolUse only; the rest are placeholders for v0.2+.
 */
export type HookType = 'pre-tool-use' | 'post-tool-use' | 'stop' | 'session-start';

/**
 * Mapping from Antigravity tool names to their nature.
 *
 * NOTE: Antigravity inherits much of its built-in tool naming from the
 * Gemini CLI lineage. The list below covers the documented common tools.
 * Unknown tools fall through with the tool name itself as the capability.
 */
export interface ToolMapping {
  /** Generic capability name for WARD `## Capabilities`. */
  capability: string;
  /** Args field that contains a filesystem path, if any. */
  pathField?: string;
  /** Implied filesystem operation for that path. */
  fsOp?: 'read' | 'write' | 'execute' | 'delete' | 'list';
  /** Args field that contains a URL, if any. */
  urlField?: string;
  /** Args field that contains a shell command, if any. */
  commandField?: string;
}

/**
 * Built-in mappings for Antigravity's standard tools.
 *
 * Documented tools (Bash/Edit/Write/Read) confirmed from public hook
 * documentation. Others inferred from the shared Gemini CLI / Antigravity
 * harness lineage. Users can also reference these by their raw names
 * in WARD.md directly.
 */
export const TOOL_MAPPINGS: Record<string, ToolMapping> = {
  // Confirmed from public Antigravity hook docs
  Bash: { capability: 'shell_exec', commandField: 'command' },
  Edit: { capability: 'file_write', pathField: 'file_path', fsOp: 'write' },
  Write: { capability: 'file_write', pathField: 'file_path', fsOp: 'write' },
  Read: { capability: 'file_read', pathField: 'file_path', fsOp: 'read' },

  // Inherited from Gemini CLI / shared agent harness
  MultiEdit: { capability: 'file_write', pathField: 'file_path', fsOp: 'write' },
  Glob: { capability: 'file_list', pathField: 'path', fsOp: 'list' },
  Grep: { capability: 'file_read', pathField: 'path', fsOp: 'read' },
  LS: { capability: 'file_list', pathField: 'path', fsOp: 'list' },
  WebFetch: { capability: 'http_request', urlField: 'url' },
  WebSearch: { capability: 'web_search' },

  // Antigravity-specific / shared
  Subagent: { capability: 'subagent' },
  Task: { capability: 'subagent' },
  RunCode: { capability: 'execute_code' },
  Plugin: { capability: 'plugin_invoke' },
};

/**
 * Settings file entry shape under hooks.<EventName>[]
 */
export interface AntigravitySettingsHooksEntry {
  matcher?: string;
  hooks: Array<{
    type: 'command' | 'prompt';
    command?: string;
    prompt?: string;
    timeout?: number;
  }>;
}
