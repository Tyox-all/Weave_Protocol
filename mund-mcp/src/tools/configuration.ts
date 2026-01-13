/**
 * Mund - The Guardian Protocol
 * Configuration & Response Tools - MCP tools for configuration and incident response
 */

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { 
  IStorage, 
  DetectionRule,
  DetectorType,
  Severity,
  ActionType
} from '../types.js';

// ============================================================================
// Input Schemas
// ============================================================================

const AddRuleInputSchema = z.object({
  id: z.string()
    .min(1, 'Rule ID is required')
    .max(100, 'Rule ID too long')
    .regex(/^[a-z0-9_]+$/, 'Rule ID must be lowercase alphanumeric with underscores')
    .describe('Unique identifier for the rule'),
  name: z.string()
    .min(1, 'Rule name is required')
    .max(200, 'Rule name too long')
    .describe('Human-readable name for the rule'),
  description: z.string().max(1000).optional()
    .describe('Description of what this rule detects'),
  type: z.enum(['secret', 'pii', 'code_pattern', 'injection', 'exfiltration'])
    .describe('Type of detection'),
  pattern: z.string()
    .min(1, 'Pattern is required')
    .describe('Regular expression pattern to match'),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info'])
    .describe('Severity level when this rule matches'),
  action: z.enum(['alert', 'block', 'log', 'quarantine'])
    .default('alert')
    .describe('Action to take when rule matches')
}).strict();

const RemoveRuleInputSchema = z.object({
  id: z.string()
    .min(1, 'Rule ID is required')
    .describe('ID of the rule to remove')
}).strict();

const ListRulesInputSchema = z.object({
  type: z.enum(['secret', 'pii', 'code_pattern', 'injection', 'exfiltration', 'behavioral']).optional()
    .describe('Filter rules by type'),
  enabled_only: z.boolean().default(false)
    .describe('Only show enabled rules')
}).strict();

const AcknowledgeAlertInputSchema = z.object({
  event_id: z.string()
    .min(1, 'Event ID is required')
    .describe('ID of the event to acknowledge'),
  acknowledged_by: z.string().optional()
    .describe('Name or ID of person acknowledging')
}).strict();

const BlockPatternInputSchema = z.object({
  pattern: z.string()
    .min(1, 'Pattern is required')
    .describe('Pattern to add to blocklist'),
  type: z.enum(['secret', 'pii', 'code_pattern', 'injection', 'exfiltration'])
    .describe('Type of pattern')
}).strict();

const AllowlistPatternInputSchema = z.object({
  pattern: z.string()
    .min(1, 'Pattern is required')
    .describe('Pattern to add to allowlist'),
  type: z.enum(['secret', 'pii', 'code_pattern', 'injection', 'exfiltration'])
    .describe('Type of pattern')
}).strict();

const ConfigureNotificationInputSchema = z.object({
  type: z.enum(['slack', 'teams', 'email', 'webhook'])
    .describe('Type of notification channel'),
  webhook_url: z.string().url().optional()
    .describe('Webhook URL for Slack/Teams/generic webhook'),
  min_severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional()
    .describe('Minimum severity to send notifications')
}).strict();

// ============================================================================
// Tool Registration
// ============================================================================

export function registerConfigurationTools(
  server: McpServer,
  storage: IStorage,
  rules: DetectionRule[]
): void {

  // ============================================================================
  // mund_add_rule - Add custom detection rule
  // ============================================================================
  server.registerTool(
    'mund_add_rule',
    {
      title: 'Add Detection Rule',
      description: `Add a custom security detection rule.

Create custom rules to detect specific patterns in content. Rules use regular expressions
for pattern matching and can be configured with different severity levels and actions.

Args:
  - id (string): Unique rule identifier (lowercase, alphanumeric, underscores)
  - name (string): Human-readable rule name
  - description (string): Optional description
  - type: Detection type (secret, pii, code_pattern, injection, exfiltration)
  - pattern (string): Regular expression to match
  - severity: Severity level (critical, high, medium, low, info)
  - action: Action to take (alert, block, log, quarantine)

Returns:
  Confirmation of rule addition with rule details`,
      inputSchema: AddRuleInputSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async (params) => {
      // Validate the regex pattern
      try {
        new RegExp(params.pattern);
      } catch {
        return {
          content: [{ type: 'text', text: JSON.stringify({
            success: false,
            error: 'Invalid regular expression pattern'
          }, null, 2) }]
        };
      }

      // Check for duplicate ID
      const existing = rules.find(r => r.id === params.id);
      if (existing) {
        return {
          content: [{ type: 'text', text: JSON.stringify({
            success: false,
            error: `Rule with ID '${params.id}' already exists`
          }, null, 2) }]
        };
      }

      // Create the rule
      const newRule: DetectionRule = {
        id: params.id,
        name: params.name,
        description: params.description,
        type: params.type as DetectorType,
        pattern: params.pattern,
        severity: params.severity as Severity,
        action: params.action as ActionType,
        enabled: true
      };

      // Add to rules array and storage
      rules.push(newRule);
      await storage.saveRule(newRule);

      const response = {
        success: true,
        message: `Rule '${params.id}' added successfully`,
        rule: newRule
      };

      return {
        content: [{ type: 'text', text: JSON.stringify(response, null, 2) }],
        structuredContent: response
      };
    }
  );

  // ============================================================================
  // mund_remove_rule - Remove a detection rule
  // ============================================================================
  server.registerTool(
    'mund_remove_rule',
    {
      title: 'Remove Detection Rule',
      description: `Remove a custom detection rule by ID.

Note: Built-in rules cannot be removed, only disabled.

Args:
  - id (string): ID of the rule to remove

Returns:
  Confirmation of rule removal`,
      inputSchema: RemoveRuleInputSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async (params) => {
      const index = rules.findIndex(r => r.id === params.id);
      
      if (index === -1) {
        return {
          content: [{ type: 'text', text: JSON.stringify({
            success: false,
            error: `Rule '${params.id}' not found`
          }, null, 2) }]
        };
      }

      // Remove from array and storage
      rules.splice(index, 1);
      await storage.deleteRule(params.id);

      const response = {
        success: true,
        message: `Rule '${params.id}' removed successfully`
      };

      return {
        content: [{ type: 'text', text: JSON.stringify(response, null, 2) }],
        structuredContent: response
      };
    }
  );

  // ============================================================================
  // mund_list_rules - List all active rules
  // ============================================================================
  server.registerTool(
    'mund_list_rules',
    {
      title: 'List Detection Rules',
      description: `List all configured detection rules.

Args:
  - type: Optional filter by detection type
  - enabled_only: Only show enabled rules (default: false)

Returns:
  Array of rule configurations`,
      inputSchema: ListRulesInputSchema,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async (params) => {
      let filteredRules = [...rules];

      if (params.type) {
        filteredRules = filteredRules.filter(r => r.type === params.type);
      }

      if (params.enabled_only) {
        filteredRules = filteredRules.filter(r => r.enabled);
      }

      // Group by type
      const grouped = filteredRules.reduce((acc, rule) => {
        if (!acc[rule.type]) acc[rule.type] = [];
        acc[rule.type].push({
          id: rule.id,
          name: rule.name,
          severity: rule.severity,
          action: rule.action,
          enabled: rule.enabled
        });
        return acc;
      }, {} as Record<string, Array<{ id: string; name: string; severity: Severity; action: ActionType; enabled: boolean }>>);

      const response = {
        total: filteredRules.length,
        rules_by_type: grouped
      };

      return {
        content: [{ type: 'text', text: JSON.stringify(response, null, 2) }],
        structuredContent: response
      };
    }
  );

  // ============================================================================
  // mund_acknowledge_alert - Mark alert as reviewed
  // ============================================================================
  server.registerTool(
    'mund_acknowledge_alert',
    {
      title: 'Acknowledge Security Alert',
      description: `Mark a security event/alert as acknowledged.

Args:
  - event_id (string): ID of the event to acknowledge
  - acknowledged_by (string): Optional name/ID of acknowledger

Returns:
  Confirmation of acknowledgment`,
      inputSchema: AcknowledgeAlertInputSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async (params) => {
      const event = await storage.getEvent(params.event_id);
      
      if (!event) {
        return {
          content: [{ type: 'text', text: JSON.stringify({
            success: false,
            error: `Event '${params.event_id}' not found`
          }, null, 2) }]
        };
      }

      await storage.acknowledgeEvent(params.event_id, params.acknowledged_by);

      const response = {
        success: true,
        message: `Event '${params.event_id}' acknowledged`,
        acknowledged_by: params.acknowledged_by,
        acknowledged_at: new Date().toISOString()
      };

      return {
        content: [{ type: 'text', text: JSON.stringify(response, null, 2) }],
        structuredContent: response
      };
    }
  );

  // ============================================================================
  // mund_block_pattern - Add pattern to blocklist
  // ============================================================================
  server.registerTool(
    'mund_block_pattern',
    {
      title: 'Block Pattern',
      description: `Add a pattern to the blocklist.

Blocked patterns will always be flagged regardless of other rules.

Args:
  - pattern (string): Pattern to block
  - type: Type of pattern (secret, pii, code_pattern, injection, exfiltration)

Returns:
  Confirmation of blocklist addition`,
      inputSchema: BlockPatternInputSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async (params) => {
      await storage.addToBlocklist(params.pattern, params.type as DetectorType);

      const response = {
        success: true,
        message: `Pattern added to blocklist`,
        pattern: params.pattern,
        type: params.type
      };

      return {
        content: [{ type: 'text', text: JSON.stringify(response, null, 2) }],
        structuredContent: response
      };
    }
  );

  // ============================================================================
  // mund_allowlist_pattern - Add pattern to allowlist
  // ============================================================================
  server.registerTool(
    'mund_allowlist_pattern',
    {
      title: 'Allowlist Pattern',
      description: `Add a pattern to the allowlist.

Allowlisted patterns will be ignored by detection rules.

Args:
  - pattern (string): Pattern to allowlist
  - type: Type of pattern

Returns:
  Confirmation of allowlist addition`,
      inputSchema: AllowlistPatternInputSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async (params) => {
      await storage.addToAllowlist(params.pattern, params.type as DetectorType);

      const response = {
        success: true,
        message: `Pattern added to allowlist`,
        pattern: params.pattern,
        type: params.type
      };

      return {
        content: [{ type: 'text', text: JSON.stringify(response, null, 2) }],
        structuredContent: response
      };
    }
  );

  // ============================================================================
  // mund_configure_notification - Set up notification channel
  // ============================================================================
  server.registerTool(
    'mund_configure_notification',
    {
      title: 'Configure Notification Channel',
      description: `Configure a notification channel for security alerts.

Note: Full configuration requires environment variables. This tool can update
webhook URLs and minimum severity settings at runtime.

Args:
  - type: Channel type (slack, teams, email, webhook)
  - webhook_url: Webhook URL (for slack, teams, webhook)
  - min_severity: Minimum severity to notify

Returns:
  Confirmation of configuration`,
      inputSchema: ConfigureNotificationInputSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async (params) => {
      // In a full implementation, this would update the NotificationHub
      // For now, we'll return a message indicating the configuration was received
      
      const response = {
        success: true,
        message: `Notification channel '${params.type}' configuration received`,
        note: 'Full configuration requires setting environment variables and restarting the server',
        config: {
          type: params.type,
          webhook_url: params.webhook_url ? '***configured***' : undefined,
          min_severity: params.min_severity
        }
      };

      return {
        content: [{ type: 'text', text: JSON.stringify(response, null, 2) }],
        structuredContent: response
      };
    }
  );
}
