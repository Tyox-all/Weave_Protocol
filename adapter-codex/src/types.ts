/**
 * Codex CLI hook contract (https://developers.openai.com/codex/hooks):
 *
 *   stdin  { session_id, transcript_path, cwd, hook_event_name, model,
 *            turn_id, tool_name, tool_use_id, tool_input, permission_mode }
 *   stdout { hookSpecificOutput: { hookEventName: "PreToolUse",
 *            permissionDecision: "deny", permissionDecisionReason } }
 *          or nothing (the call continues)
 *
 * Shell commands (including unified exec) arrive as tool_name "Bash" with
 * tool_input.command; file edits as "apply_patch" with the patch text in
 * tool_input.command; MCP tools as mcp__<server>__<tool>. "ask" is not
 * supported, so a WARD require_approval is a deny whose reason says so.
 * Hosted tools (web search) never reach PreToolUse.
 */

import type { ToolMapping } from '@weave_protocol/ward';

export interface CodexHookInput {
  session_id?: string;
  transcript_path?: string | null;
  cwd?: string;
  hook_event_name?: string;
  model?: string;
  turn_id?: string;
  tool_name?: string;
  tool_use_id?: string;
  tool_input?: unknown;
  permission_mode?: string;
}

export interface CodexHookOutput {
  hookSpecificOutput?: {
    hookEventName: 'PreToolUse';
    permissionDecision: 'deny';
    permissionDecisionReason: string;
  };
}

/**
 * Codex's local tools. apply_patch is decided from the files its patch
 * touches (see patch.ts); unknown tools, including MCP tools, use their own
 * name as the capability and Ward checks their path and URL arguments.
 */
export const TOOL_MAPPINGS: Record<string, ToolMapping> = {
  Bash: { capability: 'shell_exec', commandField: 'command' },
  apply_patch: { capability: 'file_write' },
  view_image: { capability: 'file_read', pathField: 'path', fsOp: 'read' },
  update_plan: { capability: 'task_planning' },
  spawn_agent: { capability: 'subagent' },
};

/** One PreToolUse matcher group in hooks.json. */
export interface CodexHookGroup {
  matcher?: string;
  hooks: Array<{
    type: 'command' | 'mcp_tool';
    command?: string;
    timeout?: number;
    statusMessage?: string;
    async?: boolean;
  }>;
}
