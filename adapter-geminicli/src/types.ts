/**
 * Gemini CLI hook contract (https://geminicli.com/docs/hooks/reference):
 *
 *   stdin  { session_id, transcript_path, cwd, hook_event_name, timestamp,
 *            tool_name, tool_input, mcp_context? }
 *   stdout { decision: "allow" | "deny", reason }   (JSON only)
 *
 * There is no "ask" decision, so a WARD require_approval is a deny whose
 * reason says approval is needed. MCP tools arrive as mcp_<server>_<tool>.
 */

import type { ToolMapping } from '@weave_protocol/ward';

export interface GeminiHookInput {
  session_id?: string;
  transcript_path?: string;
  cwd?: string;
  hook_event_name?: string;
  timestamp?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  mcp_context?: Record<string, unknown>;
}

export interface GeminiHookOutput {
  decision?: 'allow' | 'deny';
  reason?: string;
}

/** Shared by the planning and interaction tools, so a policy can allow them in one line. */
const PLANNING: ToolMapping = { capability: 'task_planning' };

/**
 * Gemini CLI's built-in tools (https://geminicli.com/docs/reference/tools).
 * Unknown tools, including MCP tools, use their own name as the capability;
 * Ward still checks every path- and URL-named argument they carry.
 */
export const TOOL_MAPPINGS: Record<string, ToolMapping> = {
  // dir_path is where the command runs: checked as a read
  run_shell_command: { capability: 'shell_exec', commandField: 'command', pathField: 'dir_path', fsOp: 'read' },
  read_file: { capability: 'file_read', pathField: 'file_path', fsOp: 'read' },
  read_many_files: { capability: 'file_read', pathField: 'include', fsOp: 'read' },
  write_file: { capability: 'file_write', pathField: 'file_path', fsOp: 'write' },
  replace: { capability: 'file_write', pathField: 'file_path', fsOp: 'write' },
  list_directory: { capability: 'file_list', pathField: 'dir_path', fsOp: 'list' },
  glob: { capability: 'file_list', pathField: 'dir_path', fsOp: 'list' },
  grep_search: { capability: 'file_read', pathField: 'dir_path', fsOp: 'read' },
  search_file_content: { capability: 'file_read', pathField: 'dir_path', fsOp: 'read' },
  // web_fetch takes a free-text prompt; the hook pulls its URLs into "urls"
  web_fetch: { capability: 'http_request', urlField: 'urls' },
  google_web_search: { capability: 'web_search' },
  save_memory: { capability: 'memory_write' },
  // Not in the tools reference, but offered by 0.66.0
  invoke_agent: { capability: 'subagent' },
  activate_skill: { capability: 'skill' },
  get_internal_docs: { capability: 'docs_read' },
  ask_user: PLANNING,
  write_todos: PLANNING,
  enter_plan_mode: PLANNING,
  exit_plan_mode: PLANNING,
  update_topic: PLANNING,
  tracker_create_task: PLANNING,
  tracker_update_task: PLANNING,
  tracker_get_task: PLANNING,
  tracker_list_tasks: PLANNING,
  tracker_add_dependency: PLANNING,
  tracker_visualize: PLANNING,
};

/** One BeforeTool entry in settings.json. */
export interface GeminiHookEntry {
  matcher?: string;
  sequential?: boolean;
  hooks: Array<{
    type: 'command';
    command: string;
    name?: string;
    timeout?: number;
    description?: string;
  }>;
}
