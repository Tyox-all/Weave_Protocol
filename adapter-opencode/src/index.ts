/**
 * @weave_protocol/adapter-opencode — the OpenCode plugin.
 *
 * Add the package to the "plugin" list in opencode.json (weave-ward-opencode
 * init does this) and every tool call is checked against WARD.md in
 * tool.execute.before; a blocked call throws, and the agent sees the reason.
 *
 * This entry default-exports only the plugin (OpenCode's v1 plugin format:
 * { id, server }). Helpers live at "@weave_protocol/adapter-opencode/lib".
 *
 * WARD.md is read on every call, so policy edits apply without a restart.
 * An invalid WARD.md blocks every call rather than switching enforcement off.
 */

import { resolveWard, evaluateCall, blockMessage } from './policy.js';

interface PluginInput {
  directory?: string;
  worktree?: string;
}

interface ToolBefore {
  tool: string;
  sessionID?: string;
  callID?: string;
}

const WardPlugin = async ({ directory, worktree }: PluginInput) => {
  const dir = directory || worktree || process.cwd();
  return {
    'tool.execute.before': async (input: ToolBefore, output: { args?: unknown }) => {
      let ward;
      try {
        ward = resolveWard(dir);
      } catch (err) {
        throw new Error(`WARD policy could not be loaded: ${err instanceof Error ? err.message : String(err)}. Fix WARD.md to continue.`);
      }
      if (!ward) return;
      const message = blockMessage(evaluateCall(ward.policy, input.tool, output.args, dir), ward.source);
      if (message) throw new Error(message);
    },
  };
};

export default { id: 'weave-ward', server: WardPlugin };
