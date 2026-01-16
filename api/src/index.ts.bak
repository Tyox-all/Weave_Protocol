/**
 * Weave API - Universal REST Interface
 * Platform-agnostic security for AI agents
 * 
 * Works with: OpenAI, Gemini, LangChain, Grok, Copilot, Siri, or ANY HTTP client
 */

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

// Import routes
import { mundRoutes } from './routes/mund.js';
import { hordRoutes } from './routes/hord.js';
import { domereRoutes } from './routes/domere.js';
import { healthRoutes } from './routes/health.js';

// Import middleware
import { errorHandler } from './middleware/error.js';
import { requestLogger } from './middleware/logger.js';
import { apiKeyAuth } from './middleware/auth.js';

const app = express();
const PORT = process.env.WEAVE_PORT || 3000;

// =============================================================================
// Middleware
// =============================================================================

// Security
app.use(helmet());
app.use(cors({
  origin: process.env.WEAVE_CORS_ORIGIN || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: process.env.WEAVE_RATE_LIMIT ? parseInt(process.env.WEAVE_RATE_LIMIT) : 100,
  message: { error: 'Too many requests, please try again later' },
});
app.use(limiter);

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Logging
app.use(requestLogger);

// Optional API key authentication
if (process.env.WEAVE_API_KEY) {
  app.use('/api', apiKeyAuth);
}

// =============================================================================
// Routes
// =============================================================================

// Health check (no auth)
app.use('/health', healthRoutes);

// API routes
app.use('/api/v1/mund', mundRoutes);
app.use('/api/v1/hord', hordRoutes);
app.use('/api/v1/domere', domereRoutes);

// OpenAI-compatible function calling endpoint
app.post('/api/v1/functions/call', async (req: Request, res: Response) => {
  const { function: fn, arguments: args } = req.body;
  
  try {
    let result;
    
    // Route to appropriate service
    if (fn.startsWith('mund_')) {
      const { MundService } = await import('./services/mund.js');
      result = await new MundService().call(fn, args);
    } else if (fn.startsWith('hord_')) {
      const { HordService } = await import('./services/hord.js');
      result = await new HordService().call(fn, args);
    } else if (fn.startsWith('domere_')) {
      const { DomereService } = await import('./services/domere.js');
      result = await new DomereService().call(fn, args);
    } else {
      return res.status(400).json({ error: `Unknown function: ${fn}` });
    }
    
    res.json({ result });
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

// Get available functions (for OpenAI/Gemini function calling setup)
app.get('/api/v1/functions', (_req: Request, res: Response) => {
  res.json({
    functions: [
      ...getMundFunctions(),
      ...getHordFunctions(),
      ...getDomereFunctions(),
    ]
  });
});

// =============================================================================
// Function Definitions (OpenAI/Gemini compatible)
// =============================================================================

function getMundFunctions() {
  return [
    {
      name: 'mund_scan_content',
      description: 'Scan content for security threats (secrets, PII, injection, exfiltration)',
      parameters: {
        type: 'object',
        properties: {
          content: { type: 'string', description: 'Content to scan' },
          scan_types: { 
            type: 'array', 
            items: { type: 'string', enum: ['secrets', 'pii', 'injection', 'exfiltration', 'code'] },
            description: 'Types of scans to run (default: all)'
          }
        },
        required: ['content']
      }
    },
    {
      name: 'mund_scan_secrets',
      description: 'Scan specifically for secrets and credentials',
      parameters: {
        type: 'object',
        properties: {
          content: { type: 'string', description: 'Content to scan for secrets' }
        },
        required: ['content']
      }
    },
    {
      name: 'mund_scan_pii',
      description: 'Scan for personally identifiable information',
      parameters: {
        type: 'object',
        properties: {
          content: { type: 'string', description: 'Content to scan for PII' }
        },
        required: ['content']
      }
    },
    {
      name: 'mund_scan_injection',
      description: 'Detect prompt injection and jailbreak attempts',
      parameters: {
        type: 'object',
        properties: {
          content: { type: 'string', description: 'Content to check for injection' }
        },
        required: ['content']
      }
    }
  ];
}

function getHordFunctions() {
  return [
    {
      name: 'hord_create_vault',
      description: 'Create a secure vault for sensitive data',
      parameters: {
        type: 'object',
        properties: {
          name: { type: 'string', description: 'Vault name' },
          description: { type: 'string', description: 'Vault description' }
        },
        required: ['name']
      }
    },
    {
      name: 'hord_store_secret',
      description: 'Store a secret in a vault',
      parameters: {
        type: 'object',
        properties: {
          vault_id: { type: 'string', description: 'Vault ID' },
          key: { type: 'string', description: 'Secret key/name' },
          value: { type: 'string', description: 'Secret value' }
        },
        required: ['vault_id', 'key', 'value']
      }
    },
    {
      name: 'hord_redact',
      description: 'Redact sensitive information from content',
      parameters: {
        type: 'object',
        properties: {
          content: { type: 'string', description: 'Content to redact' },
          types: {
            type: 'array',
            items: { type: 'string', enum: ['pii', 'secrets', 'custom'] },
            description: 'Types of data to redact'
          }
        },
        required: ['content']
      }
    },
    {
      name: 'hord_sandbox_execute',
      description: 'Execute code in a secure sandbox',
      parameters: {
        type: 'object',
        properties: {
          code: { type: 'string', description: 'Code to execute' },
          language: { type: 'string', enum: ['javascript', 'python'], description: 'Language' },
          timeout: { type: 'number', description: 'Timeout in ms (default: 5000)' }
        },
        required: ['code', 'language']
      }
    }
  ];
}

function getDomereFunctions() {
  return [
    {
      name: 'domere_create_thread',
      description: 'Create a new intent thread for tracking agent actions',
      parameters: {
        type: 'object',
        properties: {
          origin_type: { type: 'string', enum: ['human', 'system', 'scheduled', 'delegated'] },
          origin_identity: { type: 'string', description: 'Identity of origin' },
          intent: { type: 'string', description: 'The intent/request to track' },
          constraints: { type: 'array', items: { type: 'string' }, description: 'Constraints' }
        },
        required: ['origin_type', 'origin_identity', 'intent']
      }
    },
    {
      name: 'domere_add_hop',
      description: 'Add an agent hop to a thread',
      parameters: {
        type: 'object',
        properties: {
          thread_id: { type: 'string', description: 'Thread ID' },
          agent_id: { type: 'string', description: 'Agent identifier' },
          agent_type: { type: 'string', description: 'Agent type (e.g., gpt, claude, gemini)' },
          received_intent: { type: 'string', description: 'How agent interpreted intent' },
          actions: { type: 'array', items: { type: 'object' }, description: 'Actions taken' }
        },
        required: ['thread_id', 'agent_id', 'agent_type', 'received_intent', 'actions']
      }
    },
    {
      name: 'domere_check_drift',
      description: 'Check if current intent has drifted from original',
      parameters: {
        type: 'object',
        properties: {
          original_intent: { type: 'string', description: 'Original intent' },
          current_intent: { type: 'string', description: 'Current interpretation' },
          constraints: { type: 'array', items: { type: 'string' }, description: 'Constraints to check' }
        },
        required: ['original_intent', 'current_intent']
      }
    },
    {
      name: 'domere_anchor',
      description: 'Anchor thread proof to blockchain (paid)',
      parameters: {
        type: 'object',
        properties: {
          thread_id: { type: 'string', description: 'Thread ID to anchor' },
          network: { type: 'string', enum: ['solana', 'ethereum'], description: 'Blockchain network' }
        },
        required: ['thread_id', 'network']
      }
    }
  ];
}

// =============================================================================
// Error Handling
// =============================================================================

app.use(errorHandler);

// 404 handler
app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: 'Not found' });
});

// =============================================================================
// Start Server
// =============================================================================

app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════════╗
║                     WEAVE SECURITY API                        ║
║                                                               ║
║  Endpoints:                                                   ║
║    POST /api/v1/mund/*     - Guardian Protocol (scanning)     ║
║    POST /api/v1/hord/*     - Vault Protocol (containment)     ║
║    POST /api/v1/domere/*   - Judge Protocol (verification)    ║
║                                                               ║
║  Universal:                                                   ║
║    POST /api/v1/functions/call  - OpenAI/Gemini compatible   ║
║    GET  /api/v1/functions       - List available functions    ║
║                                                               ║
║  Server running on port ${PORT}                                 ║
╚═══════════════════════════════════════════════════════════════╝
  `);
});

export { app };
