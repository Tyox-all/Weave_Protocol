#!/usr/bin/env node
/**
 * Mund - The Guardian Protocol
 * Main Entry Point
 * 
 * An MCP-based security monitoring protocol for agentic AI systems.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import express from 'express';

import type { MundConfig, DetectionRule } from './types.js';
import { DEFAULT_CONFIG, DEFAULT_RULES } from './constants.js';
import { createStorage } from './storage/index.js';
import { AnalyzerEngine } from './analyzers/index.js';
import { NotificationHub } from './notifications/index.js';
import { registerAllTools } from './tools/index.js';

// ============================================================================
// Configuration Loading
// ============================================================================

function loadConfig(): MundConfig {
  const config: MundConfig = {
    ...DEFAULT_CONFIG,
    
    // Server settings from environment
    port: parseInt(process.env.MUND_PORT || '3000'),
    host: process.env.MUND_HOST || '127.0.0.1',
    transport: (process.env.MUND_TRANSPORT as 'stdio' | 'http') || 'stdio',
    
    // Logging
    log_level: (process.env.MUND_LOG_LEVEL as MundConfig['log_level']) || 'info',
    
    // Storage
    storage_type: (process.env.MUND_STORAGE as MundConfig['storage_type']) || 'memory',
    database_url: process.env.MUND_DATABASE_URL,
    
    // Security
    block_mode: process.env.MUND_BLOCK_MODE === 'block',
    api_key: process.env.MUND_API_KEY,
    
    // Notifications
    notifications: {
      slack: process.env.MUND_SLACK_WEBHOOK ? {
        webhook_url: process.env.MUND_SLACK_WEBHOOK,
        channel: process.env.MUND_SLACK_CHANNEL,
        username: process.env.MUND_SLACK_USERNAME || 'Mund Guardian',
        icon_emoji: process.env.MUND_SLACK_EMOJI || ':eye:',
        min_severity: (process.env.MUND_SLACK_MIN_SEVERITY as MundConfig['notifications']['slack']?.['min_severity']) || 'high'
      } : undefined,
      
      teams: process.env.MUND_TEAMS_WEBHOOK ? {
        webhook_url: process.env.MUND_TEAMS_WEBHOOK,
        min_severity: (process.env.MUND_TEAMS_MIN_SEVERITY as MundConfig['notifications']['teams']?.['min_severity']) || 'high'
      } : undefined,
      
      email: process.env.MUND_EMAIL_SMTP_HOST ? {
        smtp_host: process.env.MUND_EMAIL_SMTP_HOST,
        smtp_port: parseInt(process.env.MUND_EMAIL_SMTP_PORT || '587'),
        smtp_secure: process.env.MUND_EMAIL_SMTP_SECURE === 'true',
        smtp_user: process.env.MUND_EMAIL_SMTP_USER,
        smtp_pass: process.env.MUND_EMAIL_SMTP_PASS,
        from_address: process.env.MUND_EMAIL_FROM || 'mund@localhost',
        to_addresses: (process.env.MUND_EMAIL_TO || '').split(',').filter(Boolean),
        min_severity: (process.env.MUND_EMAIL_MIN_SEVERITY as MundConfig['notifications']['email']?.['min_severity']) || 'high'
      } : undefined,
      
      webhooks: process.env.MUND_WEBHOOK_URL ? [{
        url: process.env.MUND_WEBHOOK_URL,
        method: 'POST' as const,
        headers: process.env.MUND_WEBHOOK_HEADERS ? JSON.parse(process.env.MUND_WEBHOOK_HEADERS) : undefined,
        min_severity: (process.env.MUND_WEBHOOK_MIN_SEVERITY as 'critical' | 'high' | 'medium' | 'low' | 'info') || 'high'
      }] : undefined
    }
  };

  return config;
}

// ============================================================================
// Server Initialization
// ============================================================================

async function createMundServer(config: MundConfig): Promise<McpServer> {
  // Create MCP server
  const server = new McpServer({
    name: 'mund-mcp-server',
    version: '0.1.0'
  });

  // Initialize storage
  const storage = createStorage(config);

  // Initialize analyzer engine
  const analyzer = new AnalyzerEngine();

  // Initialize notification hub
  const notificationHub = new NotificationHub(config);

  // Load rules (start with defaults, could be extended from file)
  const rules: DetectionRule[] = [...DEFAULT_RULES];

  // Load any saved custom rules from storage
  const savedRules = await storage.getRules();
  for (const rule of savedRules) {
    if (!rules.find(r => r.id === rule.id)) {
      rules.push(rule);
    }
  }

  // Register all tools
  registerAllTools(server, storage, rules, analyzer, notificationHub, config.block_mode);

  // Log startup info
  console.error(`Mund Guardian Protocol v0.1.0`);
  console.error(`- Transport: ${config.transport}`);
  console.error(`- Storage: ${config.storage_type}`);
  console.error(`- Block Mode: ${config.block_mode ? 'enabled' : 'disabled'}`);
  console.error(`- Rules Loaded: ${rules.filter(r => r.enabled).length}`);
  console.error(`- Notifiers: ${notificationHub.getNotifierNames().join(', ') || 'none'}`);

  return server;
}

// ============================================================================
// Transport Handlers
// ============================================================================

async function runStdio(config: MundConfig): Promise<void> {
  const server = await createMundServer(config);
  const transport = new StdioServerTransport();
  
  await server.connect(transport);
  console.error('Mund MCP server running on stdio');
}

async function runHTTP(config: MundConfig): Promise<void> {
  const server = await createMundServer(config);
  const app = express();
  
  app.use(express.json({ limit: '10mb' }));

  // Health check endpoint
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', version: '0.1.0' });
  });

  // MCP endpoint
  app.post('/mcp', async (req, res) => {
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true
    });

    res.on('close', () => transport.close());

    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  // Start server
  app.listen(config.port, config.host, () => {
    console.error(`Mund MCP server running on http://${config.host}:${config.port}/mcp`);
  });
}

// ============================================================================
// CLI and Main
// ============================================================================

function printHelp(): void {
  console.log(`
Mund - The Guardian Protocol
MCP-based security monitoring for agentic AI systems

Usage: mund-mcp [options]

Options:
  --help, -h          Show this help message
  --version, -v       Show version number
  --transport <type>  Transport type: stdio (default) or http
  --port <port>       HTTP port (default: 3000)
  --host <host>       HTTP host (default: 127.0.0.1)
  --block             Enable block mode (block dangerous content)

Environment Variables:
  MUND_PORT                   HTTP server port
  MUND_HOST                   HTTP server host
  MUND_TRANSPORT              Transport type (stdio or http)
  MUND_LOG_LEVEL              Log level (debug, info, warn, error)
  MUND_STORAGE                Storage type (memory, sqlite, postgres)
  MUND_DATABASE_URL           Database connection URL
  MUND_BLOCK_MODE             Set to 'block' to enable blocking
  MUND_API_KEY                API key for authentication
  
  MUND_SLACK_WEBHOOK          Slack webhook URL
  MUND_SLACK_CHANNEL          Slack channel override
  MUND_SLACK_MIN_SEVERITY     Minimum severity for Slack alerts
  
  MUND_TEAMS_WEBHOOK          Microsoft Teams webhook URL
  MUND_TEAMS_MIN_SEVERITY     Minimum severity for Teams alerts
  
  MUND_EMAIL_SMTP_HOST        SMTP server host
  MUND_EMAIL_SMTP_PORT        SMTP server port
  MUND_EMAIL_FROM             From address for emails
  MUND_EMAIL_TO               Comma-separated recipient addresses
  
  MUND_WEBHOOK_URL            Generic webhook URL
  MUND_WEBHOOK_HEADERS        JSON string of webhook headers

Examples:
  # Run as stdio server (for MCP clients)
  mund-mcp
  
  # Run as HTTP server
  mund-mcp --transport http --port 3000
  
  # Run with Slack notifications
  MUND_SLACK_WEBHOOK=https://hooks.slack.com/... mund-mcp
  
  # Run in block mode
  mund-mcp --block

For more information, visit: https://github.com/your-org/mund-mcp
`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  // Parse CLI arguments
  if (args.includes('--help') || args.includes('-h')) {
    printHelp();
    process.exit(0);
  }

  if (args.includes('--version') || args.includes('-v')) {
    console.log('0.1.0');
    process.exit(0);
  }

  // Load config
  const config = loadConfig();

  // Override from CLI
  const transportIndex = args.indexOf('--transport');
  if (transportIndex !== -1 && args[transportIndex + 1]) {
    config.transport = args[transportIndex + 1] as 'stdio' | 'http';
  }

  const portIndex = args.indexOf('--port');
  if (portIndex !== -1 && args[portIndex + 1]) {
    config.port = parseInt(args[portIndex + 1]);
  }

  const hostIndex = args.indexOf('--host');
  if (hostIndex !== -1 && args[hostIndex + 1]) {
    config.host = args[hostIndex + 1];
  }

  if (args.includes('--block')) {
    config.block_mode = true;
  }

  // Run appropriate transport
  try {
    if (config.transport === 'http') {
      await runHTTP(config);
    } else {
      await runStdio(config);
    }
  } catch (error) {
    console.error('Failed to start Mund server:', error);
    process.exit(1);
  }
}

// Run
main().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});
