#!/usr/bin/env node
/**
 * Dōmere - The Judge Protocol
 * MCP Server Entry Point
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

import { DOMERE_TOOLS, DomereToolHandler } from './tools/index.js';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { createStorage } from './storage/index.js';
import { SqliteRecordStore } from './storage/records.js';
import { GDPRManager } from './gdpr-manager.js';
import { gdprTools, createGDPRToolHandlers } from './gdpr-tools.js';
import { CCPAManager } from './ccpa-manager.js';
import { ccpaTools, createCCPAToolHandlers } from './ccpa-tools.js';

const server = new Server({ name: 'domere', version: '1.0.0' }, { capabilities: { tools: {} } });
const useSqlite = process.env.DOMERE_STORAGE === 'sqlite';
const storage = createStorage(useSqlite ? 'sqlite' : 'memory');
const toolHandler = new DomereToolHandler(storage);
// GDPR and CCPA records go in the same SQLite file as threads.
const records = useSqlite
  ? new SqliteRecordStore(process.env.DOMERE_DATABASE_URL || join(homedir(), '.weave', 'domere.sqlite'))
  : undefined;

// GDPR controller / CCPA business identity for records and reports. Unset
// values say so plainly rather than inventing an organization.
const env = (key: string, fallback: string) => process.env[key] || fallback;
const UNSET = '(not configured)';
const gdpr = new GDPRManager({
  name: env('DOMERE_ORG_NAME', UNSET),
  email: env('DOMERE_ORG_EMAIL', UNSET),
  address: process.env.DOMERE_ORG_ADDRESS,
  dpoContact: process.env.DOMERE_DPO_CONTACT,
}, { store: records });
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
}, { store: records });

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
  } finally {
    // Persist records the call changed in place before answering the next one
    gdpr.flush();
    ccpa.flush();
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Dōmere MCP server running');
}

main().catch(e => { console.error(e); process.exit(1); });
