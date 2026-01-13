/**
 * Mund - The Guardian Protocol
 * Tools Index - Exports all MCP tools
 */

export { registerMonitoringTools } from './monitoring.js';
export { registerConfigurationTools } from './configuration.js';

import { registerMonitoringTools } from './monitoring.js';
import { registerConfigurationTools } from './configuration.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { IStorage, DetectionRule } from '../types.js';
import { AnalyzerEngine } from '../analyzers/index.js';
import { NotificationHub } from '../notifications/index.js';

/**
 * Register all Mund MCP tools
 */
export function registerAllTools(
  server: McpServer,
  storage: IStorage,
  rules: DetectionRule[],
  analyzer: AnalyzerEngine,
  notificationHub: NotificationHub,
  blockMode: boolean
): void {
  registerMonitoringTools(server, storage, rules, analyzer, notificationHub, blockMode);
  registerConfigurationTools(server, storage, rules);
}
