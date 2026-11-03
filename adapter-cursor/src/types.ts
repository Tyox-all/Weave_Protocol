/**
 * Cursor agent hooks (https://cursor.com/docs/agent/hooks).
 *
 * One command is registered on four events and tells them apart by
 * hook_event_name:
 *
 *   beforeShellExecution  { command, cwd }                       → Shell
 *   beforeMCPExecution    { tool_name, tool_input (JSON string),
 *                           mcp_server_name }                    → mcp__<server>__<tool>
 *   beforeReadFile        { file_path }                          → Read
 *   preToolUse            { tool_name, tool_input, cwd }         → every other tool
 *                         (Shell, Read and MCP:* are left to the events above,
 *                          which carry richer fields)
 *
 * Output: { permission: "allow" | "deny" | "ask", user_message, agent_message }.
 * Common fields: workspace_roots, conversation_id, hook_event_name, ...
 */

import type { ToolMapping } from '@weave_protocol/ward';

export type CursorEvent = 'beforeShellExecution' | 'beforeMCPExecution' | 'beforeReadFile' | 'preToolUse';

export const EVENTS: CursorEvent[] = ['beforeShellExecution', 'beforeMCPExecution', 'beforeReadFile', 'preToolUse'];

export interface CursorHookInput {
  hook_event_name?: string;
  conversation_id?: string;
  workspace_roots?: string[];
  cwd?: string;
  // beforeShellExecution
  command?: string;
  // beforeMCPExecution / preToolUse
  tool_name?: string;
  tool_input?: unknown;
  mcp_server_name?: string;
  // beforeReadFile
  file_path?: string;
}

export interface CursorHookOutput {
  permission?: 'allow' | 'deny' | 'ask';
  user_message?: string;
  agent_message?: string;
}

/**
 * Cursor's tool names (preToolUse matcher values: Shell, Read, Write, Grep,
 * Delete, Task). Write and Delete arguments aren't documented, so Ward checks
 * every path-named argument they carry (file_path, path, target_file, ...).
 */
export const TOOL_MAPPINGS: Record<string, ToolMapping> = {
  // cwd is where the command runs: checked as a read, like the other adapters' workdir
  Shell: { capability: 'shell_exec', commandField: 'command', pathField: 'cwd', fsOp: 'read' },
  Read: { capability: 'file_read', pathField: 'file_path', fsOp: 'read' },
  Write: { capability: 'file_write', fsOp: 'write' },
  Delete: { capability: 'file_delete', fsOp: 'delete' },
  Grep: { capability: 'file_read', fsOp: 'read' },
  Glob: { capability: 'file_list', fsOp: 'list' },
  Task: { capability: 'subagent' },
};

/** One hooks.json entry. */
export interface CursorHookEntry {
  command: string;
  type?: 'command' | 'prompt';
  timeout?: number;
  matcher?: string;
  failClosed?: boolean;
}
