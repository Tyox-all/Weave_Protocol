/**
 * Types for the Google Antigravity adapter.
 */

/**
 * JSON Antigravity sends to a hook on stdin (camelCase), per
 * https://antigravity.google/docs/hooks:
 *   { toolCall: { name, args }, stepIdx, conversationId, workspacePaths,
 *     transcriptPath, artifactDirectoryPath, modelName }
 * The legacy snake_case fields are still read as a fallback.
 */
export interface AntigravityHookInput {
  toolCall?: { name?: string; args?: Record<string, unknown> };
  workspacePaths?: string[];
  conversationId?: string;
  stepIdx?: number;
  transcriptPath?: string;
  modelName?: string;
  /** @deprecated pre-0.2 assumption; Antigravity sends toolCall.name */
  tool_name?: string;
  /** @deprecated pre-0.2 assumption; Antigravity sends toolCall.args */
  tool_input?: Record<string, unknown>;
  /** @deprecated pre-0.2 assumption; Antigravity sends workspacePaths */
  cwd?: string;
}

/**
 * JSON a PreToolUse hook returns on stdout. `decision` is required when a
 * hook returns output; printing nothing leaves the call to Antigravity.
 */
export interface AntigravityHookOutput {
  decision: 'allow' | 'auto_approve' | 'deny' | 'ask' | 'force_ask' | 'deny_unless_prior_grant';
  reason?: string;
}

/**
 * Hook lifecycle event types in Antigravity 2.0.
 * v0.1 ships PreToolUse only; the rest are placeholders for v0.2+.
 */
export type HookType = 'pre-tool-use' | 'post-tool-use' | 'stop' | 'session-start';

/**
 * Mapping from Antigravity tool names to their nature.
 *
 * Unknown tools (including MCP tools) fall through with the tool name
 * itself as the capability, so WARD.md can name them directly.
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
 * Built-in mappings for Antigravity's documented tools and their argument
 * names. WARD.md can also reference any tool by its raw name.
 */
export const TOOL_MAPPINGS: Record<string, ToolMapping> = {
  // Antigravity built-in tools (https://antigravity.google/docs/hooks)
  run_command: { capability: 'shell_exec', commandField: 'CommandLine' },
  // Antigravity CLI (agy 1.4.x) file tools, observed live: Path may be relative to the workspace
  read_file: { capability: 'file_read', pathField: 'Path', fsOp: 'read' },
  write_file: { capability: 'file_write', pathField: 'Path', fsOp: 'write' },
  edit_file: { capability: 'file_write', pathField: 'Path', fsOp: 'write' },
  view_file: { capability: 'file_read', pathField: 'AbsolutePath', fsOp: 'read' },
  write_to_file: { capability: 'file_write', pathField: 'TargetFile', fsOp: 'write' },
  replace_file_content: { capability: 'file_write', pathField: 'TargetFile', fsOp: 'write' },
  multi_replace_file_content: { capability: 'file_write', pathField: 'TargetFile', fsOp: 'write' },
  list_dir: { capability: 'file_list', pathField: 'DirectoryPath', fsOp: 'list' },
  find_by_name: { capability: 'file_list', pathField: 'SearchDirectory', fsOp: 'list' },
  grep_search: { capability: 'file_read', pathField: 'SearchPath', fsOp: 'read' },
  read_url_content: { capability: 'http_request', urlField: 'Url' },
  search_web: { capability: 'web_search' },
  invoke_subagent: { capability: 'subagent' },
  define_subagent: { capability: 'subagent' },
  send_message: { capability: 'agent_message' },
  manage_task: { capability: 'task_control' },
  schedule: { capability: 'schedule' },
  generate_image: { capability: 'generate_image' },
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
