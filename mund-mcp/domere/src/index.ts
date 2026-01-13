#!/usr/bin/env node
/**
 * Dōmere - The Judge Protocol
 * MCP Server Entry Point
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

import { DOMERE_TOOLS, DomereToolHandler } from './tools/index.js';
import { createStorage } from './storage/index.js';

const server = new Server({ name: 'domere', version: '1.0.0' }, { capabilities: { tools: {} } });
const storage = createStorage('memory');
const toolHandler = new DomereToolHandler(storage);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: DOMERE_TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  try {
    const result = await toolHandler.handleTool(name, args as Record<string, unknown>);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  } catch (error) {
    return { content: [{ type: 'text', text: JSON.stringify({ error: String(error) }) }], isError: true };
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Dōmere MCP server running');
}

main().catch(e => { console.error(e); process.exit(1); });

export { DomereToolHandler, DOMERE_TOOLS };
export * from './types.js';
export * from './thread/index.js';
export * from './language/index.js';
export * from './anchoring/index.js';
export * from './storage/index.js';
