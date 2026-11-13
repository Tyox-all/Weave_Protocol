/**
 * TRAE hook contract (https://docs.trae.ai/ide/hook-configuration-reference):
 *
 *   stdin  { session_id, cwd, hook_event_name, workspace_roots[],
 *            tool_use_id, tool_name, llm_tool_name, tool_input }
 *   stdout { hookSpecificOutput: { hookEventName: "PreToolUse",
 *            permissionDecision: "allow" | "deny" | "ask", permissionDecisionReason } }
 *
 * With several PreToolUse hooks the strictest wins (deny, then ask, then
 * allow), so another hook can't override a WARD deny. Only exit code 2 or a
 * "deny" blocks; any other failure is ignored, so the hook never exits
 * non-zero. tool_name is TRAE's standardized name: Read, Write, Edit, Glob,
 * Grep, LS, RunCommand, WebSearch, WebFetch, AskUserQuestion, Skill, and
 * mcp__<server>__<tool>.
 */

import type { ToolMapping } from '@weave_protocol/ward';

export interface HookInput {
  session_id?: string;
  cwd?: string;
  hook_event_name?: string;
  workspace_roots?: string[];
  tool_use_id?: string;
  tool_name?: string;
  llm_tool_name?: string;
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
 * TRAE's standardized tool names. RunCommand carries its command in
 * tool_input.command. TRAE doesn't document the other tools' argument
 * names; Ward checks every path- and URL-named argument whatever it's
 * called, and the mapped names below are the Claude Code ones TRAE imports.
 */
export const TOOL_MAPPINGS: Record<string, ToolMapping> = {
  RunCommand: { capability: 'shell_exec', commandField: 'command' },
  Read: { capability: 'file_read', pathField: 'file_path', fsOp: 'read' },
  Write: { capability: 'file_write', pathField: 'file_path', fsOp: 'write' },
  Edit: { capability: 'file_write', pathField: 'file_path', fsOp: 'write' },
  Glob: { capability: 'file_list', pathField: 'path', fsOp: 'list' },
  Grep: { capability: 'file_read', pathField: 'path', fsOp: 'read' },
  LS: { capability: 'file_list', pathField: 'path', fsOp: 'list' },
  WebFetch: { capability: 'http_request', urlField: 'url' },
  WebSearch: { capability: 'web_search' },
  Skill: { capability: 'skill' },
  AskUserQuestion: PLANNING,
};

/** One PreToolUse group in hooks.json. */
export interface HookEntry {
  matcher?: string;
  hooks: Array<{ command: string; name?: string; timeout?: number }>;
}
