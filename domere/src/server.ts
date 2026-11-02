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
import { GDPRManager } from './gdpr-manager.js';
import { gdprTools, createGDPRToolHandlers } from './gdpr-tools.js';
import { CCPAManager } from './ccpa-manager.js';
import { ccpaTools, createCCPAToolHandlers } from './ccpa-tools.js';

const server = new Server({ name: 'domere', version: '1.0.0' }, { capabilities: { tools: {} } });
const storage = createStorage(process.env.DOMERE_STORAGE === 'sqlite' ? 'sqlite' : 'memory');
const toolHandler = new DomereToolHandler(storage);

// GDPR controller / CCPA business identity for records and reports. Unset
// values say so plainly rather than inventing an organization.
const env = (key: string, fallback: string) => process.env[key] || fallback;
const UNSET = '(not configured)';
const gdpr = new GDPRManager({
  name: env('DOMERE_ORG_NAME', UNSET),
  email: env('DOMERE_ORG_EMAIL', UNSET),
  address: process.env.DOMERE_ORG_ADDRESS,
  dpoContact: process.env.DOMERE_DPO_CONTACT,
});
const ccpa = new CCPAManager({
  id: env('DOMERE_ORG_ID', 'default'),
  name: env('DOMERE_ORG_NAME', UNSET),
  address: env('DOMERE_ORG_ADDRESS', UNSET),
  privacyPolicyUrl: env('DOMERE_PRIVACY_POLICY_URL', UNSET),
  doNotSellUrl: env('DOMERE_DO_NOT_SELL_URL', UNSET),
  contactEmail: env('DOMERE_ORG_EMAIL', UNSET),
  meetsThreshold: process.env.DOMERE_CCPA_MEETS_THRESHOLD !== 'false',
  createdAt: new Date(),
  updatedAt: new Date(),
});

type Handler = (args: any) => unknown;
const extraHandlers: Record<string, Handler> = {
  ...(createGDPRToolHandlers(gdpr) as Record<string, Handler>),
  ...(createCCPAToolHandlers(ccpa) as Record<string, Handler>),
};
const TOOLS = [...DOMERE_TOOLS, ...gdprTools, ...ccpaTools];

const names = TOOLS.map((t) => t.name);
const duplicate = names.find((n, i) => names.indexOf(n) !== i);
if (duplicate) throw new Error(`Duplicate tool name: ${duplicate}`);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  try {
    const extra = extraHandlers[name];
    const result = extra ? await extra(args ?? {}) : await toolHandler.handleTool(name, args as Record<string, unknown>);
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
