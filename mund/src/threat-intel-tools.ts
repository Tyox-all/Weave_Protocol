/**
 * Threat Intelligence MCP Tools
 * 
 * MCP tool definitions and handlers for threat intelligence.
 * Uses Zod schemas as required by the MCP SDK.
 */

import { z } from 'zod';
import type { ThreatIntelManager } from './threat-intel-manager.js';
import type { ThreatCategory, IntelSourceType } from './threat-intel-types.js';

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
  type: z.enum(['url', 'file', 'api']).describe('Source type'),
  url: z.string().optional().describe('URL for remote sources'),
  auto_update: z.boolean().default(true).describe('Enable auto-updates'),
  update_interval: z.number().default(86400000).describe('Update interval in ms'),
};

export const RemoveIntelSourceSchema = {
  source_id: z.string().describe('Source ID to remove'),
};

export const ThreatScanSchema = {
  content: z.string().describe('Content to scan'),
  categories: z.array(z.enum([
    'prompt_injection', 'jailbreak', 'data_exfiltration',
    'system_prompt_leak', 'pii_extraction', 'mcp_exploit',
    'dos_attack', 'other'
  ])).optional().describe('Filter by categories'),
  min_severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional().describe('Minimum severity'),
};

export const ListPatternsSchema = {
  source: z.string().optional().describe('Filter by source'),
  category: z.enum([
    'prompt_injection', 'jailbreak', 'data_exfiltration',
    'system_prompt_leak', 'pii_extraction', 'mcp_exploit',
    'dos_attack', 'other'
  ]).optional().describe('Filter by category'),
  enabled_only: z.boolean().default(true).describe('Only show enabled patterns'),
};

export const TogglePatternSchema = {
  pattern_id: z.string().describe('Pattern ID to toggle'),
  enabled: z.boolean().describe('Enable or disable'),
};

// ============================================================================
// Tool Definitions
// ============================================================================

export const threatIntelToolDefs = [
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
      const results = await manager.updateAllSources(args.force || false);
      return {
        success: true,
        sources_updated: results.length,
        results,
      };
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
          auto_update: s.auto_update,
          patterns_count: s.patterns_count,
          version: s.version,
          last_update: s.last_update,
          update_interval: s.update_interval,
        })),
      };
    },

    mund_intel_status: (args: { include_patterns?: boolean }) => {
      const status = manager.getStatus();
      if (args.include_patterns) {
        return {
          ...status,
          patterns_detail: manager.getPatterns({ enabled_only: true }).map(p => ({
            id: p.id,
            name: p.name,
            category: p.category,
            severity: p.severity,
            source: p.source,
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
      auto_update?: boolean;
      update_interval?: number;
    }) => {
      return manager.addSource({
        id: args.id,
        name: args.name,
        type: args.type,
        url: args.url,
        enabled: true,
        auto_update: args.auto_update ?? true,
        update_interval: args.update_interval ?? 86400000,
        version: '0.0.0',
      });
    },

    mund_remove_intel_source: (args: { source_id: string }) => {
      return manager.removeSource(args.source_id);
    },

    mund_threat_scan: (args: {
      content: string;
      categories?: ThreatCategory[];
      min_severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
    }) => {
      return manager.scan(args.content, {
        categories: args.categories,
        min_severity: args.min_severity,
      });
    },

    mund_list_patterns: (args: {
      source?: string;
      category?: ThreatCategory;
      enabled_only?: boolean;
    }) => {
      const patterns = manager.getPatterns({
        source: args.source,
        category: args.category,
        enabled_only: args.enabled_only ?? true,
      });
      return {
        count: patterns.length,
        patterns: patterns.map(p => ({
          id: p.id,
          name: p.name,
          category: p.category,
          severity: p.severity,
          mitre_techniques: p.mitre_techniques,
          source: p.source,
          enabled: p.enabled,
        })),
      };
    },

    mund_toggle_pattern: (args: { pattern_id: string; enabled: boolean }) => {
      return manager.togglePattern(args.pattern_id, args.enabled);
    },
  };
}
