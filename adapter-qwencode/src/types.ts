/**
 * Qwen Code hook contract (https://qwenlm.github.io/qwen-code-docs/en/users/features/hooks/):
 *
 *   stdin  { session_id, transcript_path, cwd, hook_event_name, timestamp,
 *            permission_mode, tool_name, tool_input, tool_use_id, ... }
 *   stdout { hookSpecificOutput: { hookEventName: "PreToolUse",
 *            permissionDecision: "allow" | "deny" | "ask",
 *            permissionDecisionReason } }
 *
 * Only exit code 2 or a "deny" decision blocks. A crash, a timeout or any
 * other exit code lets the call through, so the hook never exits non-zero:
 * every failure becomes an explicit decision. "ask" prompts in the TUI and
 * is treated as "deny" in headless runs, background subagents and ACP.
 */

import type { ToolMapping } from '@weave_protocol/ward';

export interface QwenHookInput {
  session_id?: string;
  transcript_path?: string;
  cwd?: string;
  hook_event_name?: string;
  timestamp?: string;
  permission_mode?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  tool_use_id?: string;
}

export interface QwenHookOutput {
  hookSpecificOutput?: {
    hookEventName: 'PreToolUse';
    permissionDecision: 'allow' | 'deny' | 'ask';
    permissionDecisionReason: string;
  };
}

/** Planning and interaction tools share one capability, so a policy can allow them in one line. */
const PLANNING: ToolMapping = { capability: 'task_planning' };

/**
 * Qwen Code's built-in tools, from packages/core/src/tools/tool-names.ts and
 * each tool's parameter schema. Unknown tools, including MCP tools, use their
 * own name as the capability; Ward still checks every path- and URL-named
 * argument they carry. tool_call is unwrapped by the hook (see hook.ts).
 */
export const TOOL_MAPPINGS: Record<string, ToolMapping> = {
  // directory is where the command runs: checked as a read
  run_shell_command: { capability: 'shell_exec', commandField: 'command', pathField: 'directory', fsOp: 'read' },
  // Code mode: JavaScript that can call other tools. Its source is scanned like
  // a command (URLs, secret references, dangerous commands).
  exec: { capability: 'code_exec', commandField: 'source' },
  read_file: { capability: 'file_read', pathField: 'file_path', fsOp: 'read' },
  write_file: { capability: 'file_write', pathField: 'file_path', fsOp: 'write' },
  edit: { capability: 'file_write', pathField: 'file_path', fsOp: 'write' },
  notebook_edit: { capability: 'file_write', pathField: 'notebook_path', fsOp: 'write' },
  list_directory: { capability: 'file_list', pathField: 'path', fsOp: 'list' },
  glob: { capability: 'file_list', pathField: 'path', fsOp: 'list' },
  grep_search: { capability: 'file_read', pathField: 'path', fsOp: 'read' },
  web_fetch: { capability: 'http_request', urlField: 'url' },
  web_search: { capability: 'web_search' },
  save_memory: { capability: 'memory_write' },
  manage_memory: { capability: 'memory_write' },
  search_memory: { capability: 'memory_read' },
  agent: { capability: 'subagent' },
  create_sub_session: { capability: 'subagent' },
  skill: { capability: 'skill' },
  // Scheduling work that runs later, unattended
  cron_create: { capability: 'scheduled_task' },
  cron_delete: { capability: 'scheduled_task' },
  cron_list: PLANNING,
  send_message: { capability: 'agent_message' },
  autofix_pr: { capability: 'git_push' },
  enter_worktree: { capability: 'git_worktree' },
  exit_worktree: { capability: 'git_worktree' },
  image_gen: { capability: 'image_generation' },
  read_mcp_resource: { capability: 'mcp_read' },
  lsp: { capability: 'code_intel' },
  todo_write: PLANNING,
  ask_user_question: PLANNING,
  enter_plan_mode: PLANNING,
  exit_plan_mode: PLANNING,
  task_create: PLANNING,
  task_update: PLANNING,
  task_list: PLANNING,
  task_stop: PLANNING,
  list_agents: PLANNING,
  tool_search: PLANNING,
};

/** One PreToolUse entry in settings.json. */
export interface QwenHookEntry {
  matcher?: string;
  hooks: Array<{
    type: 'command';
    command: string;
    name?: string;
    timeout?: number;
  }>;
}
