#!/usr/bin/env node
/**
 * Hundredmen MCP Server
 * @weave_protocol/hundredmen
 * 
 * Real-time MCP security proxy with live feed and reputation scoring
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

import { Interceptor } from './interceptor.js';
import { ReputationManager } from './reputation.js';
import { hundredmenTools, createHundredmenToolHandlers } from './tools.js';

// ============================================================================
// Initialize Components
// ============================================================================

const interceptor = new Interceptor();
const reputationManager = new ReputationManager();

// Wire up reputation checker
interceptor.setReputationChecker(async (serverId: string) => {
  return reputationManager.getScore(serverId);
});

// Wire up reputation alerts
reputationManager.onAlert((alert) => {
  console.error(`[REPUTATION ALERT] ${alert.message}`);
});

// Create tool handlers
const handlers = createHundredmenToolHandlers(interceptor, reputationManager);

// ============================================================================
// MCP Server
// ============================================================================

const server = new Server(
  {
    name: 'weave-hundredmen',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: hundredmenTools.map(tool => ({
      name: tool.name,
      description: tool.description,
      inputSchema: tool.inputSchema,
    })),
  };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  
  const handler = handlers[name as keyof typeof handlers];
  if (!handler) {
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({ error: `Unknown tool: ${name}` }),
        },
      ],
    };
  }
  
  try {
    const result = await handler(args as any);
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  } catch (error: any) {
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            error: error.message,
            stack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
          }),
        },
      ],
    };
  }
});

// ============================================================================
// Start Server
// ============================================================================

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('🔍 Weave Hundredmen MCP Server running');
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});

// Re-export classes for API integration
export { Interceptor } from './interceptor.js';
export { ReputationManager } from './reputation.js';
export * from './types.js';

// Re-export for API integration
export { Interceptor } from './interceptor.js';
export { ReputationManager } from './reputation.js';
export * from './types.js';
