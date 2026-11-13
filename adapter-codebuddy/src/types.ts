/**
 * CodeBuddy Code hook contract (https://www.codebuddy.ai/docs/cli/hooks):
 *
 *   stdin  { session_id, transcript_path, cwd, permission_mode, hook_event_name,
 *            tool_name, tool_input }
 *   stdout { hookSpecificOutput: { hookEventName: "PreToolUse",
 *            permissionDecision: "allow" | "deny" | "ask", permissionDecisionReason } }
 *
 * PreToolUse runs before CodeBuddy Code's permission prompts. "allow" would
 * bypass them, so this adapter never sends it. Only exit code 2 or a "deny"
 * blocks; any other failure lets the call through, so the hook never exits
 * non-zero. Tool names and arguments follow Claude Code's (Bash, Read, Write,
 * Edit, MultiEdit, Glob, Grep, WebFetch, Task/Agent, ...); MCP tools are
 * mcp__<server>__<tool>.
 */

import type { ToolMapping } from '@weave_protocol/ward';

export interface HookInput {
  session_id?: string;
  transcript_path?: string;
  cwd?: string;
  permission_mode?: string;
  hook_event_name?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
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
 * CodeBuddy Code's built-in tools. Unknown tools, including MCP tools, use
 * their own name as the capability; Ward still checks every path- and
 * URL-named argument they carry.
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
