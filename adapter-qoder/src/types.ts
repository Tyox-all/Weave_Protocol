/**
 * Qoder CLI hook contract (https://docs.qoder.com/cli/hooks):
 *
 *   stdin  { session_id, transcript_path, cwd, hook_event_name, permission_mode,
 *            agent_id, agent_type, tool_name, tool_input, tool_use_id,
 *            mcp_context?, original_request_name? }
 *   stdout { hookSpecificOutput: { hookEventName: "PreToolUse",
 *            permissionDecision: "allow" | "deny" | "ask", permissionDecisionReason } }
 *
 * A "deny" holds even in bypass-permissions mode. Only exit code 2 or a
 * "deny" blocks; any other failure lets the call through, so the hook never
 * exits non-zero. Tool names and arguments follow Claude Code's (Bash, Read,
 * Write, Edit, Glob, Grep, ...); MCP tools are mcp__<server>__<tool>.
 */

import type { ToolMapping } from '@weave_protocol/ward';

export interface HookInput {
  session_id?: string;
  transcript_path?: string;
  cwd?: string;
  hook_event_name?: string;
  permission_mode?: string;
  agent_id?: string;
  agent_type?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  tool_use_id?: string;
}

export interface HookOutput {
  hookSpecificOutput?: {
    hookEventName: 'PreToolUse';
    permissionDecision: 'allow' | 'deny' | 'ask';
    permissionDecisionReason: string;
  };
}

const PLANNING: ToolMapping = { capability: 'task_planning' };

/**
 * Qoder CLI's built-in tools. Unknown tools, including MCP tools, use their
 * own name as the capability; Ward still checks every path- and URL-named
 * argument they carry.
 */
export const TOOL_MAPPINGS: Record<string, ToolMapping> = {
  Bash: { capability: 'shell_exec', commandField: 'command' },
  Read: { capability: 'file_read', pathField: 'file_path', fsOp: 'read' },
  Write: { capability: 'file_write', pathField: 'file_path', fsOp: 'write' },
  Edit: { capability: 'file_write', pathField: 'file_path', fsOp: 'write' },
  MultiEdit: { capability: 'file_write', pathField: 'file_path', fsOp: 'write' },
  NotebookEdit: { capability: 'file_write', pathField: 'notebook_path', fsOp: 'write' },
  Glob: { capability: 'file_list', pathField: 'path', fsOp: 'list' },
  Grep: { capability: 'file_read', pathField: 'path', fsOp: 'read' },
  LS: { capability: 'file_list', pathField: 'path', fsOp: 'list' },
  WebFetch: { capability: 'http_request', urlField: 'url' },
  WebSearch: { capability: 'web_search' },
  Task: { capability: 'subagent' },
  Agent: { capability: 'subagent' },
  Skill: { capability: 'skill' },
  TodoWrite: PLANNING,
  AskUserQuestion: PLANNING,
  ExitPlanMode: PLANNING,
};

/** One PreToolUse entry in settings.json. */
export interface HookEntry {
  matcher?: string;
  hooks: Array<{ type?: 'command'; command: string; name?: string; timeout?: number }>;
}
