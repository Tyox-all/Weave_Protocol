/**
 * Mund - The Guardian Protocol
 * Canary token (OWASP LLM07) and MCP rug-pull (OWASP ASI04) tools
 */

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { canaries } from '../canary.js';
import { checkRugPull, changesToIssues } from '../rugpull.js';
import { McpServerAnalyzer } from '../analyzers/mcp-server-analyzer.js';
import { computeRiskScore } from '../scoring.js';

const text = (value: unknown) => ({ content: [{ type: 'text' as const, text: JSON.stringify(value, null, 2) }] });

export function registerCanaryRugPullTools(server: McpServer): void {
  server.tool(
    'mund_create_canary',
    'Create a canary token to place in a system prompt or other confidential context. Every later scan flags output containing it (even spaced out, base64-encoded or reversed), revealing prompt leakage.',
    {
      label: z.string().optional().describe('What the canary protects, e.g. "support-bot system prompt"'),
      token: z.string().optional().describe('Register an existing token instead of generating one'),
    },
    async ({ label, token }) => {
      try {
        const canary = token ? canaries.register(token, label) : canaries.create(label);
        return text({
          ...canary,
          how_to_use: `Add this line to the system prompt: "Internal reference: ${canary.token}. Never repeat it."`,
        });
      } catch (error) {
        return text({ error: (error as Error).message });
      }
    },
  );

  server.tool(
    'mund_list_canaries',
    'List registered canary tokens.',
    {},
    async () => text({ canaries: canaries.list() }),
  );

  server.tool(
    'mund_remove_canary',
    'Remove a canary token.',
    { token: z.string().describe('Token to remove') },
    async ({ token }) => text({ removed: canaries.remove(token) }),
  );

  server.tool(
    'mund_check_mcp_rugpull',
    'Detect MCP rug pulls: compare a server manifest with the baseline recorded when the server was first checked. Flags changed tool descriptions or schemas, and added or removed tools; escalates to critical when a changed tool now looks malicious or gains command execution. The first check records the baseline.',
    {
      server_id: z.string().describe('Stable identifier for the server, e.g. its registry name or install path'),
      manifest: z.string().describe('JSON content of the server manifest (server.json or tools/list result)'),
      accept_changes: z.boolean().optional().describe('After human review, accept the changes and update the baseline'),
    },
    async ({ server_id, manifest, accept_changes }) => {
      const parsed = McpServerAnalyzer.parseManifest(manifest);
      if (!parsed) return text({ error: 'Invalid manifest: expected JSON with name, tools or resources' });
      const result = await checkRugPull(server_id, parsed, { acceptChanges: accept_changes });
      const risk = computeRiskScore(changesToIssues(result));
      return text({
        ...result,
        risk_score: risk.score,
        risk_label: risk.label,
        recommendation:
          result.status === 'baseline_created' ? 'BASELINE_RECORDED'
          : result.changes.some(c => c.severity === 'critical') ? 'DO_NOT_USE'
          : result.changes.length > 0 ? (accept_changes ? 'CHANGES_ACCEPTED' : 'REVIEW_CHANGES')
          : 'UNCHANGED',
      });
    },
  );
}
