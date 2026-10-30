#!/usr/bin/env node
/**
 * Hord - The Vault Protocol
 * Main Entry Point
 * 
 * Cryptographic containment and capability management for AI agents.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import express from 'express';

import type { HordConfig } from './types.js';
import { DEFAULT_CONFIG, SERVER_INFO } from './constants.js';
import { createStorage } from './storage/index.js';
import { VaultManager, keyStore } from './vault/index.js';
import { CapabilityManager } from './capability/index.js';
import { SandboxManager } from './sandbox/index.js';
import { RedactionEngine } from './redaction/index.js';
import { AttestationService } from './attestation/index.js';
import { registerAllTools } from './tools/index.js';

// ============================================================================
// Configuration
// ============================================================================

function loadConfig(): HordConfig {
  return {
    port: parseInt(process.env.HORD_PORT || String(DEFAULT_CONFIG.port)),
    host: process.env.HORD_HOST || DEFAULT_CONFIG.host,
    transport: (process.env.HORD_TRANSPORT as 'stdio' | 'http') || DEFAULT_CONFIG.transport,
    log_level: (process.env.HORD_LOG_LEVEL as HordConfig['log_level']) || DEFAULT_CONFIG.log_level,
    storage: (process.env.HORD_STORAGE as 'memory' | 'sqlite' | 'postgres') || DEFAULT_CONFIG.storage,
    database_url: process.env.HORD_DATABASE_URL,
    
    encryption: {
      master_key_file: process.env.HORD_MASTER_KEY_FILE,
      master_key: process.env.HORD_MASTER_KEY,
      key_rotation_days: parseInt(process.env.HORD_KEY_ROTATION_DAYS || '90'),
      use_hardware_key: process.env.HORD_USE_HARDWARE_KEY === 'true',
    },
    
    sandbox: {
      runtime: (process.env.HORD_SANDBOX_RUNTIME as 'process' | 'docker' | 'firecracker') || DEFAULT_CONFIG.sandbox.runtime,
      default_timeout_ms: parseInt(process.env.HORD_SANDBOX_TIMEOUT_MS || String(DEFAULT_CONFIG.sandbox.default_timeout_ms)),
      default_memory_mb: parseInt(process.env.HORD_SANDBOX_MEMORY_MB || String(DEFAULT_CONFIG.sandbox.default_memory_mb)),
      image: process.env.HORD_SANDBOX_IMAGE,
    },
    
    attestation: {
      key_file: process.env.HORD_ATTESTATION_KEY_FILE,
      cert_file: process.env.HORD_ATTESTATION_CERT_FILE,
      chain_attestations: process.env.HORD_CHAIN_ATTESTATIONS !== 'false',
    },
    
    integration: {
      mund_url: process.env.HORD_MUND_URL,
      mund_api_key: process.env.HORD_MUND_API_KEY,
    },
  };
}

// ============================================================================
// Server Setup
// ============================================================================

async function createServer(config: HordConfig) {
  // Initialize storage
  const storage = createStorage(config.storage);
  
  // Initialize key store
  const masterKey = config.encryption.master_key || 
    config.encryption.master_key_file ||
    'hord-default-master-key-change-in-production-' + Date.now();
  keyStore.initialize(masterKey);
  
  // Initialize managers
  const vaultManager = new VaultManager(storage);
  const capabilityManager = new CapabilityManager(storage);
  const sandboxManager = new SandboxManager(storage);
  const redactionEngine = new RedactionEngine(storage);
  const attestationService = new AttestationService(storage);
  
  // Create MCP server
  const server = new McpServer({
    name: SERVER_INFO.name,
    version: SERVER_INFO.version,
  });
  
  // Register all tools
  registerAllTools(
    server,
    vaultManager,
    capabilityManager,
    sandboxManager,
    redactionEngine,
    attestationService
  );
  
  return { server, config };
}

// ============================================================================
// Transport Setup
// ============================================================================

async function startStdioTransport(server: McpServer) {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`${SERVER_INFO.name} v${SERVER_INFO.version} running on stdio`);
}

async function startHttpTransport(server: McpServer, config: HordConfig) {
  const app = express();
  app.use(express.json());
  
  // Health check
  app.get('/health', (_req, res) => {
    res.json({ 
      status: 'healthy',
      name: SERVER_INFO.name,
      version: SERVER_INFO.version,
    });
  });
  
  // MCP endpoint
  app.all('/mcp', async (req, res) => {
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => `session-${Date.now()}`,
    });
    
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });
  
  // Status endpoint
  app.get('/status', (_req, res) => {
    res.json({
      name: SERVER_INFO.name,
      version: SERVER_INFO.version,
      uptime: process.uptime(),
      memory: process.memoryUsage(),
    });
  });
  
  app.listen(config.port, config.host, () => {
    console.error(`${SERVER_INFO.name} v${SERVER_INFO.version} running on http://${config.host}:${config.port}`);
  });
}

// ============================================================================
// Main
// ============================================================================

async function main() {
  const args = process.argv.slice(2);
  
  // Show help
  if (args.includes('--help') || args.includes('-h')) {
    console.error(`
${SERVER_INFO.name} v${SERVER_INFO.version}
${SERVER_INFO.description}

Usage: hord-mcp [options]

Options:
  --transport <stdio|http>   Transport type (default: stdio)
  --port <number>            HTTP port (default: 3001)
  --host <string>            HTTP host (default: 127.0.0.1)
  --storage <memory|sqlite>  Storage backend (default: memory)
  --help, -h                 Show this help

Environment Variables:
  HORD_PORT                  HTTP port
  HORD_HOST                  HTTP host
  HORD_TRANSPORT             Transport type
  HORD_STORAGE               Storage backend
  HORD_MASTER_KEY            Master encryption key
  HORD_SANDBOX_TIMEOUT_MS    Sandbox timeout
  HORD_MUND_URL              Mund server URL for integration

Examples:
  # Run with stdio transport (for Claude Desktop)
  hord-mcp

  # Run as HTTP server
  hord-mcp --transport http --port 3001

  # Run with custom master key
  HORD_MASTER_KEY=my-secure-key hord-mcp
`);
    process.exit(0);
  }
  
  // Parse CLI args
  const config = loadConfig();
  
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--transport':
        config.transport = args[++i] as 'stdio' | 'http';
        break;
      case '--port':
        config.port = parseInt(args[++i]);
        break;
      case '--host':
        config.host = args[++i];
        break;
      case '--storage':
        config.storage = args[++i] as 'memory' | 'sqlite' | 'postgres';
        break;
    }
  }
  
  // Create and start server
  const { server } = await createServer(config);
  
  if (config.transport === 'http') {
    await startHttpTransport(server, config);
  } else {
    await startStdioTransport(server);
  }
}

// Run
main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
