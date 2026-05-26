/**
 * Types for the Claude Code adapter.
 */

/**
 * Shape of the JSON sent to a Claude Code hook on stdin.
 * Based on Claude Code's documented hook input format.
 */
export interface ClaudeCodeHookInput {
  session_id?: string;
  transcript_path?: string;
  cwd?: string;
  hook_event_name?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  tool_response?: unknown;
}

/**
 * Shape of the JSON returned on stdout to control Claude Code's behavior.
 *
 * For PreToolUse:
 *   - { "decision": "approve" }            → auto-approve (skip user confirm)
 *   - { "decision": "block", "reason": …}  → block the call with reason
 *   - {} (or no output)                    → let Claude Code decide normally
 *
 * Optional "systemMessage" appears in the conversation; "continue" controls
 * whether the overall turn proceeds.
 */
export interface ClaudeCodeHookOutput {
  decision?: 'approve' | 'block';
  reason?: string;
  continue?: boolean;
  stopReason?: string;
  systemMessage?: string;
  suppressOutput?: boolean;
}

/**
 * The hook type. v0.1 only ships PreToolUse; PostToolUse and Stop come later.
 */
export type HookType = 'pre-tool-use' | 'post-tool-use' | 'stop' | 'session-start';

/**
 * Mapping from Claude Code tool names to their nature.
 * Used to extract the right args and apply the right WARD checks.
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
 * Built-in mappings for Claude Code's standard tools.
 * Unknown tools fall through with the tool name as the capability.
 */
export const TOOL_MAPPINGS: Record<string, ToolMapping> = {
  Bash: { capability: 'shell_exec', commandField: 'command' },
  Edit: { capability: 'file_write', pathField: 'file_path', fsOp: 'write' },
  MultiEdit: { capability: 'file_write', pathField: 'file_path', fsOp: 'write' },
  Write: { capability: 'file_write', pathField: 'file_path', fsOp: 'write' },
  Read: { capability: 'file_read', pathField: 'file_path', fsOp: 'read' },
  Glob: { capability: 'file_list', pathField: 'path', fsOp: 'list' },
  Grep: { capability: 'file_read', pathField: 'path', fsOp: 'read' },
  LS: { capability: 'file_list', pathField: 'path', fsOp: 'list' },
  WebFetch: { capability: 'http_request', urlField: 'url' },
  WebSearch: { capability: 'web_search' },
  Task: { capability: 'subagent' },
  TodoWrite: { capability: 'todo_write' },
  NotebookEdit: { capability: 'notebook_edit', pathField: 'notebook_path', fsOp: 'write' },
};

/**
 * Settings written into ~/.claude/settings.json for the WARD hook.
 */
export interface ClaudeSettingsHooksEntry {
  matcher?: string;
  hooks: Array<{
    type: 'command';
    command: string;
    timeout?: number;
  }>;
}
