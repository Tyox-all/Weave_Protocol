/**
 * Threat Intelligence MCP Tools
 * @weave_protocol/mund
 */

import { z } from 'zod';
import type { ThreatIntelManager } from './threat-intel-manager.js';
import type { IntelCategory, IntelSourceType } from './threat-intel-types.js';

// ============================================================================
// Zod Schemas for Tool Inputs
// ============================================================================

export const UpdateThreatIntelSchema = {
  source_id: z.string().optional().describe('Specific source to update (omit for all)'),
  force: z.boolean().default(false).describe('Force update even if not due'),
};

export const ListIntelSourcesSchema = {
  enabled_only: z.boolean().default(false).describe('Only show enabled sources'),
};

export const IntelStatusSchema = {
  include_patterns: z.boolean().default(false).describe('Include pattern details'),
};

export const AddIntelSourceSchema = {
  id: z.string().describe('Unique source identifier'),
  name: z.string().describe('Human-readable name'),
  type: z.enum(['mitre_attack', 'community_blocklist', 'custom', 'weave_official']).describe('Source type'),
  url: z.string().optional().describe('URL for remote sources'),
  description: z.string().describe('Source description'),
  auto_update: z.boolean().default(true).describe('Enable auto-updates'),
  update_interval_hours: z.number().default(24).describe('Update interval in hours'),
};

export const RemoveIntelSourceSchema = {
  source_id: z.string().describe('Source ID to remove'),
};

export const ThreatScanSchema = {
  content: z.string().describe('Content to scan'),
  categories: z.array(z.enum([
    'prompt_injection', 'jailbreak', 'data_exfiltration',
    'privilege_escalation', 'social_engineering', 'malicious_code',
    'pii_extraction', 'system_prompt_leak', 'dos_attack', 'mcp_exploit'
  ])).optional().describe('Filter by categories'),
  min_severity: z.enum(['critical', 'high', 'medium', 'low']).optional().describe('Minimum severity'),
  min_confidence: z.number().min(0).max(1).optional().describe('Minimum confidence (0-1)'),
};

export const ListPatternsSchema = {
  source_id: z.string().optional().describe('Filter by source'),
  category: z.enum([
    'prompt_injection', 'jailbreak', 'data_exfiltration',
    'privilege_escalation', 'social_engineering', 'malicious_code',
    'pii_extraction', 'system_prompt_leak', 'dos_attack', 'mcp_exploit'
  ]).optional().describe('Filter by category'),
  enabled_only: z.boolean().default(true).describe('Only show enabled patterns'),
};

export const TogglePatternSchema = {
  pattern_id: z.string().describe('Pattern ID to toggle'),
  enabled: z.boolean().describe('Enable or disable'),
};

// ============================================================================
// Tool Definitions (exported as threatIntelTools)
// ============================================================================

export const threatIntelTools = [
  {
    name: 'mund_update_threat_intel',
    description: 'Pull latest threat patterns from configured intelligence feeds. Updates MITRE ATT&CK mappings and community blocklists.',
    schema: UpdateThreatIntelSchema,
  },
  {
    name: 'mund_list_intel_sources',
    description: 'List all configured threat intelligence sources with their status, update intervals, and pattern counts.',
    schema: ListIntelSourcesSchema,
  },
  {
    name: 'mund_intel_status',
    description: 'Get threat intelligence health status including source coverage, pattern counts by category, and MITRE ATT&CK technique coverage.',
    schema: IntelStatusSchema,
  },
  {
    name: 'mund_add_intel_source',
    description: 'Add a custom threat intelligence feed. Supports URL, file, and API sources.',
    schema: AddIntelSourceSchema,
  },
  {
    name: 'mund_remove_intel_source',
    description: 'Remove a custom threat intelligence source and all its patterns.',
    schema: RemoveIntelSourceSchema,
  },
  {
    name: 'mund_threat_scan',
    description: 'Scan content using threat intelligence patterns. Returns findings with MITRE ATT&CK technique mappings.',
    schema: ThreatScanSchema,
  },
  {
    name: 'mund_list_patterns',
    description: 'Browse threat detection patterns by source, category, or enabled status.',
    schema: ListPatternsSchema,
  },
  {
    name: 'mund_toggle_pattern',
    description: 'Enable or disable a specific threat detection pattern.',
    schema: TogglePatternSchema,
  },
];

// ============================================================================
// Tool Handlers
// ============================================================================

export function createThreatIntelToolHandlers(manager: ThreatIntelManager) {
  return {
    mund_update_threat_intel: async (args: { source_id?: string; force?: boolean }) => {
      if (args.source_id) {
        return await manager.updateSource(args.source_id, args.force || false);
      }
      return await manager.updateAllSources(args.force || false);
    },

    mund_list_intel_sources: (args: { enabled_only?: boolean }) => {
      let sources = manager.getSources();
      if (args.enabled_only) {
        sources = sources.filter(s => s.enabled);
      }
      return {
        sources: sources.map(s => ({
          id: s.id,
          name: s.name,
          type: s.type,
          enabled: s.enabled,
          autoUpdate: s.autoUpdate,
          patternCount: s.patternCount,
          version: s.version,
          lastUpdated: s.lastUpdated,
          updateIntervalHours: s.updateIntervalHours,
          lastError: s.lastError,
        })),
      };
    },

    mund_intel_status: (args: { include_patterns?: boolean }) => {
      const status = manager.getStatus();
      if (args.include_patterns) {
        return {
          ...status,
          patterns_detail: manager.getPatterns({ enabledOnly: true }).map(p => ({
            id: p.id,
            name: p.name,
            category: p.category,
            severity: p.severity,
            sourceId: p.sourceId,
            mitreId: p.mitreId,
          })),
        };
      }
      return status;
    },

    mund_add_intel_source: (args: {
      id: string;
      name: string;
      type: IntelSourceType;
      url?: string;
      description: string;
      auto_update?: boolean;
      update_interval_hours?: number;
    }) => {
      return manager.addSource({
        id: args.id,
        name: args.name,
        type: args.type,
        url: args.url,
        description: args.description,
        autoUpdate: args.auto_update ?? true,
        updateIntervalHours: args.update_interval_hours ?? 24,
      });
    },

    mund_remove_intel_source: (args: { source_id: string }) => {
      return manager.removeSource(args.source_id);
    },

    mund_threat_scan: (args: {
      content: string;
      categories?: IntelCategory[];
      min_severity?: 'critical' | 'high' | 'medium' | 'low';
      min_confidence?: number;
    }) => {
      return manager.scan(args.content, {
        categories: args.categories,
        minSeverity: args.min_severity,
        minConfidence: args.min_confidence,
      });
    },

    mund_list_patterns: (args: {
      source_id?: string;
      category?: IntelCategory;
      enabled_only?: boolean;
    }) => {
      const patterns = manager.getPatterns({
        sourceId: args.source_id,
        category: args.category,
        enabledOnly: args.enabled_only ?? true,
      });
      return {
        count: patterns.length,
        patterns: patterns.map(p => ({
          id: p.id,
          name: p.name,
          category: p.category,
          severity: p.severity,
          confidence: p.confidence,
          mitreId: p.mitreId,
          mitreTactic: p.mitreTactic,
          sourceId: p.sourceId,
          enabled: p.enabled,
        })),
      };
    },

    mund_toggle_pattern: (args: { pattern_id: string; enabled: boolean }) => {
      return manager.togglePattern(args.pattern_id, args.enabled);
    },
  };
}
