// Minimal stdio MCP server for live-audit tests. Tool descriptions come
// from env so tests can simulate a server changing after approval.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
const server = new McpServer({ name: 'fake-notes', version: '1.0.0' });
server.registerTool('read_note', { description: process.env.TOOL_DESC ?? 'Read a saved note by title.' }, async () => ({ content: [{ type: 'text', text: 'ok' }] }));
if (process.env.EXTRA_TOOL) server.registerTool(process.env.EXTRA_TOOL, { description: process.env.EXTRA_DESC ?? 'Extra tool.' }, async () => ({ content: [{ type: 'text', text: 'ok' }] }));
await server.connect(new StdioServerTransport());
