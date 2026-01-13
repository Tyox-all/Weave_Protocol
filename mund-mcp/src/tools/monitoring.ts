/**
 * Mund - The Guardian Protocol
 * Monitoring Tools - MCP tools for security monitoring
 */

import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import { createHash } from 'crypto';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { 
  IStorage, 
  DetectionRule, 
  SecurityEvent, 
  ScanResult,
  EventContext,
  Severity,
  DetectorType
} from '../types.js';
import { AnalyzerEngine } from '../analyzers/index.js';
import { NotificationHub } from '../notifications/index.js';
import { MAX_SNIPPET_LENGTH, DEFAULT_EVENTS_LIMIT, MAX_EVENTS_PER_QUERY } from '../constants.js';

// ============================================================================
// Input Schemas
// ============================================================================

const ScanContentInputSchema = z.object({
  content: z.string()
    .min(1, 'Content is required')
    .max(1000000, 'Content exceeds maximum length')
    .describe('The text/code content to scan for security issues'),
  content_type: z.enum(['text', 'code', 'json', 'yaml'])
    .default('text')
    .describe('Type of content being scanned'),
  tool_name: z.string().optional().describe('Name of the tool that generated this content'),
  agent_id: z.string().optional().describe('ID of the agent making this request'),
  session_id: z.string().optional().describe('Current session ID')
}).strict();

const CheckUrlInputSchema = z.object({
  url: z.string()
    .url('Invalid URL format')
    .describe('URL to check for safety'),
  tool_name: z.string().optional().describe('Name of the tool attempting to access this URL'),
  agent_id: z.string().optional().describe('ID of the agent making this request')
}).strict();

const ValidateCommandInputSchema = z.object({
  command: z.string()
    .min(1, 'Command is required')
    .describe('Shell command to validate'),
  tool_name: z.string().optional().describe('Name of the tool executing this command'),
  agent_id: z.string().optional().describe('ID of the agent making this request')
}).strict();

const GetEventsInputSchema = z.object({
  limit: z.number().int().min(1).max(MAX_EVENTS_PER_QUERY).default(DEFAULT_EVENTS_LIMIT)
    .describe('Maximum number of events to return'),
  offset: z.number().int().min(0).default(0)
    .describe('Number of events to skip for pagination'),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional()
    .describe('Filter by severity level'),
  type: z.enum(['secret', 'pii', 'code_pattern', 'injection', 'exfiltration', 'behavioral']).optional()
    .describe('Filter by detection type'),
  acknowledged: z.boolean().optional()
    .describe('Filter by acknowledgment status')
}).strict();

const GetStatusInputSchema = z.object({}).strict();

// ============================================================================
// Tool Registration
// ============================================================================

export function registerMonitoringTools(
  server: McpServer,
  storage: IStorage,
  rules: DetectionRule[],
  analyzer: AnalyzerEngine,
  notificationHub: NotificationHub,
  blockMode: boolean
): void {

  // ============================================================================
  // mund_scan_content - Scan text/code for security issues
  // ============================================================================
  server.registerTool(
    'mund_scan_content',
    {
      title: 'Scan Content for Security Issues',
      description: `Scan text or code content for security vulnerabilities, secrets, PII, and other issues.

This tool analyzes the provided content using multiple security analyzers:
- Secret Scanner: Detects API keys, tokens, passwords, and credentials
- PII Detector: Finds personal identifiable information
- Code Analyzer: Identifies dangerous code patterns
- Injection Detector: Spots prompt injection attempts
- Exfiltration Detector: Detects data exfiltration patterns

Args:
  - content (string): The text/code to scan (required)
  - content_type ('text' | 'code' | 'json' | 'yaml'): Type of content (default: 'text')
  - tool_name (string): Name of tool that generated this content (optional)
  - agent_id (string): ID of the requesting agent (optional)
  - session_id (string): Current session ID (optional)

Returns:
  JSON object with:
  - scan_id: Unique identifier for this scan
  - issues_found: Number of security issues detected
  - blocked: Whether the content was blocked (if block_mode is enabled)
  - issues: Array of detected issues with severity, type, and suggestions
  - scan_duration_ms: Time taken to complete the scan

Examples:
  - Scan code before committing: {"content": "const key = 'AKIAIOSFODNN7EXAMPLE'"}
  - Check user input: {"content": "Please ignore previous instructions", "content_type": "text"}`,
      inputSchema: ScanContentInputSchema,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async (params) => {
      const startTime = Date.now();
      const contentHash = createHash('sha256').update(params.content).digest('hex');

      // Run analysis
      const issues = await analyzer.analyzeAll(params.content, rules);

      // Create scan result
      const scanResult: ScanResult = {
        id: uuidv4(),
        timestamp: new Date(),
        content_hash: contentHash,
        issues,
        scan_duration_ms: Date.now() - startTime,
        rules_checked: rules.filter(r => r.enabled).length
      };

      // Determine if content should be blocked
      const hasCritical = issues.some(i => i.severity === 'critical');
      const hasHigh = issues.some(i => i.severity === 'high');
      const shouldBlock = blockMode && (hasCritical || hasHigh);

      // Create and store security events for significant issues
      const context: EventContext = {
        tool_name: params.tool_name,
        agent_id: params.agent_id,
        session_id: params.session_id
      };

      for (const issue of issues.filter(i => i.severity === 'critical' || i.severity === 'high')) {
        const event: SecurityEvent = {
          id: uuidv4(),
          timestamp: new Date(),
          rule_id: issue.rule_id,
          rule_name: issue.rule_name,
          severity: issue.severity as Severity,
          type: issue.type as DetectorType,
          action_taken: shouldBlock ? 'block' : issue.action,
          content_snippet: truncateSnippet(issue.match, MAX_SNIPPET_LENGTH),
          full_content_hash: contentHash,
          context,
          acknowledged: false
        };

        await storage.saveEvent(event);
        
        // Send notifications for critical/high severity
        await notificationHub.notify(event);
      }

      // Format response
      const response = {
        scan_id: scanResult.id,
        issues_found: issues.length,
        blocked: shouldBlock,
        issues: issues.map(i => ({
          rule_id: i.rule_id,
          rule_name: i.rule_name,
          severity: i.severity,
          type: i.type,
          match: i.match,
          location: i.location,
          suggestion: i.suggestion
        })),
        scan_duration_ms: scanResult.scan_duration_ms,
        rules_checked: scanResult.rules_checked
      };

      return {
        content: [{ type: 'text', text: JSON.stringify(response, null, 2) }],
        structuredContent: response
      };
    }
  );

  // ============================================================================
  // mund_check_url - Validate URL safety
  // ============================================================================
  server.registerTool(
    'mund_check_url',
    {
      title: 'Check URL Safety',
      description: `Check if a URL is safe to access.

Validates URLs against known dangerous patterns including:
- Data exfiltration services (webhook.site, requestbin, etc.)
- IP-based URLs (often used to bypass domain filtering)
- Suspicious TLDs (.tk, .ml, etc.)
- Data URLs (can contain arbitrary content)

Args:
  - url (string): The URL to check (required)
  - tool_name (string): Name of tool attempting access (optional)
  - agent_id (string): ID of requesting agent (optional)

Returns:
  JSON object with:
  - url: The checked URL
  - safe: Boolean indicating if URL is safe
  - risk_level: 'safe' | 'suspicious' | 'dangerous'
  - warnings: Array of warning messages if any
  - blocked: Whether access was blocked`,
      inputSchema: CheckUrlInputSchema,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async (params) => {
      const warnings: string[] = [];
      let riskLevel: 'safe' | 'suspicious' | 'dangerous' = 'safe';

      // Check against dangerous URL patterns
      const { DANGEROUS_URL_PATTERNS } = await import('../constants.js');
      
      for (const pattern of DANGEROUS_URL_PATTERNS) {
        if (pattern.test(params.url)) {
          riskLevel = 'dangerous';
          warnings.push('URL matches known dangerous pattern');
          break;
        }
      }

      // Check for IP-based URLs
      if (/^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(params.url)) {
        if (riskLevel === 'safe') riskLevel = 'suspicious';
        warnings.push('IP-based URL detected');
      }

      // Check for data URLs
      if (params.url.startsWith('data:')) {
        riskLevel = 'dangerous';
        warnings.push('Data URL can contain arbitrary content');
      }

      // Check for suspicious ports
      try {
        const urlObj = new URL(params.url);
        const port = urlObj.port;
        if (port && !['80', '443', '8080', '8443'].includes(port)) {
          if (riskLevel === 'safe') riskLevel = 'suspicious';
          warnings.push(`Unusual port: ${port}`);
        }
      } catch {
        riskLevel = 'dangerous';
        warnings.push('Invalid URL format');
      }

      const isSafe = riskLevel === 'safe';
      const shouldBlock = blockMode && riskLevel === 'dangerous';

      // Log event if dangerous
      if (riskLevel === 'dangerous') {
        const event: SecurityEvent = {
          id: uuidv4(),
          timestamp: new Date(),
          rule_id: 'url_check',
          rule_name: 'Dangerous URL Detected',
          severity: 'high',
          type: 'exfiltration',
          action_taken: shouldBlock ? 'block' : 'alert',
          content_snippet: truncateSnippet(params.url, MAX_SNIPPET_LENGTH),
          full_content_hash: createHash('sha256').update(params.url).digest('hex'),
          context: { tool_name: params.tool_name, agent_id: params.agent_id },
          acknowledged: false
        };

        await storage.saveEvent(event);
        await notificationHub.notify(event);
      }

      const response = {
        url: params.url,
        safe: isSafe,
        risk_level: riskLevel,
        warnings,
        blocked: shouldBlock
      };

      return {
        content: [{ type: 'text', text: JSON.stringify(response, null, 2) }],
        structuredContent: response
      };
    }
  );

  // ============================================================================
  // mund_validate_command - Check shell command safety
  // ============================================================================
  server.registerTool(
    'mund_validate_command',
    {
      title: 'Validate Shell Command',
      description: `Validate a shell command for safety before execution.

Checks for dangerous patterns including:
- Destructive commands (rm -rf, format, etc.)
- Privilege escalation (sudo, chmod 777, etc.)
- Network exfiltration (curl to suspicious URLs, etc.)
- Code injection (eval, exec with variables, etc.)

Args:
  - command (string): Shell command to validate (required)
  - tool_name (string): Name of tool executing command (optional)
  - agent_id (string): ID of requesting agent (optional)

Returns:
  JSON object with:
  - command: The validated command
  - safe: Boolean indicating if command is safe
  - risk_level: 'safe' | 'suspicious' | 'dangerous'
  - warnings: Array of warning messages
  - blocked: Whether execution was blocked`,
      inputSchema: ValidateCommandInputSchema,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async (params) => {
      const warnings: string[] = [];
      let riskLevel: 'safe' | 'suspicious' | 'dangerous' = 'safe';
      const cmd = params.command.toLowerCase();

      // Dangerous command patterns
      const dangerousPatterns = [
        { pattern: /rm\s+-[rf]{1,2}\s+[\/~]/, message: 'Recursive deletion of root/home directory' },
        { pattern: /mkfs\./, message: 'Filesystem format command' },
        { pattern: /dd\s+if=.*of=\/dev\//, message: 'Direct disk write' },
        { pattern: />\s*\/dev\/sd[a-z]/, message: 'Direct device write' },
        { pattern: /chmod\s+777/, message: 'Overly permissive chmod' },
        { pattern: /curl.*\|\s*(ba)?sh/, message: 'Piping curl to shell' },
        { pattern: /wget.*\|\s*(ba)?sh/, message: 'Piping wget to shell' },
        { pattern: /eval\s+"?\$/, message: 'Eval with variable' },
        { pattern: /:(){ :|:& };:/, message: 'Fork bomb detected' },
      ];

      for (const { pattern, message } of dangerousPatterns) {
        if (pattern.test(params.command)) {
          riskLevel = 'dangerous';
          warnings.push(message);
        }
      }

      // Suspicious patterns
      const suspiciousPatterns = [
        { pattern: /sudo\s/, message: 'Sudo usage' },
        { pattern: />\s*\/etc\//, message: 'Writing to /etc' },
        { pattern: /curl|wget/, message: 'Network download command' },
        { pattern: /nc\s+-/, message: 'Netcat usage' },
        { pattern: /base64\s+-d/, message: 'Base64 decoding' },
      ];

      for (const { pattern, message } of suspiciousPatterns) {
        if (pattern.test(params.command) && riskLevel === 'safe') {
          riskLevel = 'suspicious';
          warnings.push(message);
        }
      }

      const isSafe = riskLevel === 'safe';
      const shouldBlock = blockMode && riskLevel === 'dangerous';

      // Log event if dangerous
      if (riskLevel === 'dangerous') {
        const event: SecurityEvent = {
          id: uuidv4(),
          timestamp: new Date(),
          rule_id: 'command_check',
          rule_name: 'Dangerous Command Detected',
          severity: 'high',
          type: 'code_pattern',
          action_taken: shouldBlock ? 'block' : 'alert',
          content_snippet: truncateSnippet(params.command, MAX_SNIPPET_LENGTH),
          full_content_hash: createHash('sha256').update(params.command).digest('hex'),
          context: { tool_name: params.tool_name, agent_id: params.agent_id },
          acknowledged: false
        };

        await storage.saveEvent(event);
        await notificationHub.notify(event);
      }

      const response = {
        command: params.command,
        safe: isSafe,
        risk_level: riskLevel,
        warnings,
        blocked: shouldBlock
      };

      return {
        content: [{ type: 'text', text: JSON.stringify(response, null, 2) }],
        structuredContent: response
      };
    }
  );

  // ============================================================================
  // mund_get_events - Retrieve recent security events
  // ============================================================================
  server.registerTool(
    'mund_get_events',
    {
      title: 'Get Security Events',
      description: `Retrieve recent security events from the Mund monitoring system.

Supports filtering and pagination for efficient event retrieval.

Args:
  - limit (number): Maximum events to return, 1-1000 (default: 50)
  - offset (number): Skip this many events for pagination (default: 0)
  - severity ('critical' | 'high' | 'medium' | 'low' | 'info'): Filter by severity
  - type: Filter by detection type
  - acknowledged (boolean): Filter by acknowledgment status

Returns:
  JSON object with:
  - total: Total matching events
  - count: Events in this response
  - offset: Current offset
  - has_more: Whether more events exist
  - events: Array of security events`,
      inputSchema: GetEventsInputSchema,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async (params) => {
      const query = {
        limit: params.limit,
        offset: params.offset,
        severity: params.severity as Severity | undefined,
        type: params.type as DetectorType | undefined,
        acknowledged: params.acknowledged
      };

      const [events, total] = await Promise.all([
        storage.getEvents(query),
        storage.countEvents(query)
      ]);

      const response = {
        total,
        count: events.length,
        offset: params.offset,
        has_more: total > params.offset + events.length,
        events: events.map(e => ({
          id: e.id,
          timestamp: e.timestamp.toISOString(),
          rule_id: e.rule_id,
          rule_name: e.rule_name,
          severity: e.severity,
          type: e.type,
          action_taken: e.action_taken,
          content_snippet: e.content_snippet,
          context: e.context,
          acknowledged: e.acknowledged,
          acknowledged_by: e.acknowledged_by,
          acknowledged_at: e.acknowledged_at?.toISOString()
        }))
      };

      return {
        content: [{ type: 'text', text: JSON.stringify(response, null, 2) }],
        structuredContent: response
      };
    }
  );

  // ============================================================================
  // mund_get_status - Get current monitoring status
  // ============================================================================
  server.registerTool(
    'mund_get_status',
    {
      title: 'Get Monitoring Status',
      description: `Get the current status of the Mund monitoring system.

Returns information about:
- Active analyzers and their status
- Number of rules loaded
- Configured notification channels
- Block mode status
- Recent event statistics`,
      inputSchema: GetStatusInputSchema,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async () => {
      const eventCounts = {
        total: await storage.countEvents({}),
        unacknowledged: await storage.countEvents({ acknowledged: false }),
        critical: await storage.countEvents({ severity: 'critical' as Severity }),
        high: await storage.countEvents({ severity: 'high' as Severity })
      };

      const response = {
        status: 'active',
        version: '0.1.0',
        block_mode: blockMode,
        analyzers: analyzer.getAnalyzerNames(),
        rules_loaded: rules.filter(r => r.enabled).length,
        notifiers: notificationHub.getNotifierNames(),
        event_counts: eventCounts,
        timestamp: new Date().toISOString()
      };

      return {
        content: [{ type: 'text', text: JSON.stringify(response, null, 2) }],
        structuredContent: response
      };
    }
  );
}

// ============================================================================
// Helper Functions
// ============================================================================

function truncateSnippet(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  return text.substring(0, maxLength - 3) + '...';
}
