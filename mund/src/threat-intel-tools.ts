/**
 * Threat Intelligence MCP Tools
 * @weave_protocol/mund
 */

import { ThreatIntelManager, threatIntel } from './threat-intel-manager.js';
import type { IntelCategory, Severity } from './threat-intel-types.js';

// ============================================================================
// Tool Definitions
// ============================================================================

export const threatIntelTools = [
  // === UPDATE INTEL ===
  {
    name: 'mund_update_threat_intel',
    description: 'Pull latest threat patterns from configured intel sources. Updates detection patterns for prompt injection, jailbreaks, data exfiltration, and other AI-specific threats. Sources include MITRE ATT&CK patterns and community blocklists.',
    inputSchema: {
      type: 'object',
      properties: {
        source_id: {
          type: 'string',
          description: 'Specific source to update (optional, updates all if not specified)',
        },
        force: {
          type: 'boolean',
          description: 'Force update even if recently updated',
          default: false,
        },
      },
    },
  },

  // === LIST SOURCES ===
  {
    name: 'mund_list_intel_sources',
    description: 'Show all configured threat intelligence feeds including MITRE ATT&CK, community blocklists, and custom sources. Shows status, pattern counts, and last update time for each source.',
    inputSchema: {
      type: 'object',
      properties: {
        enabled_only: {
          type: 'boolean',
          description: 'Only show enabled sources',
          default: false,
        },
        include_patterns: {
          type: 'boolean',
          description: 'Include sample patterns from each source',
          default: false,
        },
      },
    },
  },

  // === INTEL STATUS ===
  {
    name: 'mund_intel_status',
    description: 'Get threat intelligence status including last update time, total pattern count, coverage by category, MITRE ATT&CK coverage, and health status of all sources.',
    inputSchema: {
      type: 'object',
      properties: {
        detailed: {
          type: 'boolean',
          description: 'Include detailed breakdown by category and severity',
          default: true,
        },
      },
    },
  },

  // === ADD SOURCE ===
  {
    name: 'mund_add_intel_source',
    description: 'Add a custom threat intelligence source. Supports JSON feeds with pattern definitions.',
    inputSchema: {
      type: 'object',
      properties: {
        id: {
          type: 'string',
          description: 'Unique identifier for the source',
        },
        name: {
          type: 'string',
          description: 'Human-readable name',
        },
        url: {
          type: 'string',
          description: 'URL to fetch patterns from (JSON format)',
        },
        description: {
          type: 'string',
          description: 'Description of the source',
        },
        auto_update: {
          type: 'boolean',
          description: 'Enable automatic updates',
          default: true,
        },
        update_interval_hours: {
          type: 'number',
          description: 'Hours between updates',
          default: 24,
        },
        categories: {
          type: 'array',
          items: { type: 'string' },
          description: 'Categories this source covers',
        },
      },
      required: ['id', 'name', 'url'],
    },
  },

  // === REMOVE SOURCE ===
  {
    name: 'mund_remove_intel_source',
    description: 'Remove a custom threat intelligence source. Cannot remove built-in Weave sources.',
    inputSchema: {
      type: 'object',
      properties: {
        source_id: {
          type: 'string',
          description: 'ID of source to remove',
        },
      },
      required: ['source_id'],
    },
  },

  // === SCAN WITH INTEL ===
  {
    name: 'mund_threat_scan',
    description: 'Scan content using threat intelligence patterns. Detects prompt injection, jailbreaks, data exfiltration attempts, and other AI-specific threats. Returns matches with severity, MITRE ATT&CK mapping, and recommendations.',
    inputSchema: {
      type: 'object',
      properties: {
        content: {
          type: 'string',
          description: 'Content to scan for threats',
        },
        categories: {
          type: 'array',
          items: { type: 'string' },
          description: 'Limit scan to specific categories (prompt_injection, jailbreak, data_exfiltration, etc.)',
        },
        min_severity: {
          type: 'string',
          enum: ['low', 'medium', 'high', 'critical'],
          description: 'Minimum severity to report',
        },
        min_confidence: {
          type: 'number',
          description: 'Minimum confidence score (0-1)',
          minimum: 0,
          maximum: 1,
        },
        include_mitre: {
          type: 'boolean',
          description: 'Include MITRE ATT&CK mappings',
          default: true,
        },
      },
      required: ['content'],
    },
  },

  // === LIST PATTERNS ===
  {
    name: 'mund_list_patterns',
    description: 'List threat detection patterns. Can filter by source and category.',
    inputSchema: {
      type: 'object',
      properties: {
        source_id: {
          type: 'string',
          description: 'Filter by source ID',
        },
        category: {
          type: 'string',
          description: 'Filter by category',
        },
        limit: {
          type: 'number',
          description: 'Maximum patterns to return',
          default: 50,
        },
      },
    },
  },

  // === ENABLE/DISABLE PATTERN ===
  {
    name: 'mund_toggle_pattern',
    description: 'Enable or disable a specific threat pattern.',
    inputSchema: {
      type: 'object',
      properties: {
        pattern_id: {
          type: 'string',
          description: 'Pattern ID to toggle',
        },
        enabled: {
          type: 'boolean',
          description: 'Enable or disable the pattern',
        },
      },
      required: ['pattern_id', 'enabled'],
    },
  },
];

// ============================================================================
// Tool Handlers
// ============================================================================

export function createThreatIntelToolHandlers(manager: ThreatIntelManager = threatIntel) {
  return {
    // === UPDATE INTEL ===
    mund_update_threat_intel: async (args: { source_id?: string; force?: boolean }) => {
      if (args.source_id) {
        const result = await manager.updateSource(args.source_id);
        return {
          success: result.success,
          source: result.sourceName,
          previous_version: result.previousVersion,
          new_version: result.newVersion,
          patterns_added: result.patternsAdded,
          patterns_updated: result.patternsUpdated,
          patterns_removed: result.patternsRemoved,
          total_patterns: result.totalPatterns,
          duration_ms: result.duration_ms,
          error: result.error,
          timestamp: result.timestamp,
        };
      } else {
        const result = await manager.updateAllSources();
        return {
          success: result.failedUpdates === 0,
          sources_updated: result.successfulUpdates,
          sources_failed: result.failedUpdates,
          total_patterns_added: result.totalPatternsAdded,
          total_patterns_updated: result.totalPatternsUpdated,
          total_patterns_removed: result.totalPatternsRemoved,
          duration_ms: result.duration_ms,
          results: result.results.map(r => ({
            source: r.sourceName,
            success: r.success,
            patterns: r.totalPatterns,
            error: r.error,
          })),
          timestamp: result.timestamp,
        };
      }
    },

    // === LIST SOURCES ===
    mund_list_intel_sources: async (args: { enabled_only?: boolean; include_patterns?: boolean }) => {
      const sources = manager.listSources();
      const filtered = args.enabled_only ? sources.filter(s => s.enabled) : sources;

      return {
        total: filtered.length,
        sources: filtered.map(s => {
          const base: any = {
            id: s.id,
            name: s.name,
            type: s.type,
            description: s.description,
            enabled: s.enabled,
            auto_update: s.autoUpdate,
            update_interval_hours: s.updateIntervalHours,
            pattern_count: s.patternCount,
            version: s.version,
            categories: s.categories,
            last_updated: s.lastUpdated,
            last_error: s.lastError,
            url: s.url,
          };

          if (args.include_patterns) {
            const patterns = manager.listPatterns(s.id);
            base.sample_patterns = patterns.slice(0, 3).map(p => ({
              name: p.name,
              category: p.category,
              severity: p.severity,
            }));
          }

          return base;
        }),
      };
    },

    // === INTEL STATUS ===
    mund_intel_status: async (args: { detailed?: boolean }) => {
      const status = manager.getStatus();

      const response: any = {
        initialized: status.initialized,
        health: status.health.status,
        last_global_update: status.lastGlobalUpdate,
        sources: {
          total: status.sources.total,
          enabled: status.sources.enabled,
          auto_update: status.sources.autoUpdate,
        },
        patterns: {
          total: status.patterns.total,
        },
        mitre_coverage: {
          tactics: status.coverage.mitreAttack.tactics,
          techniques: status.coverage.mitreAttack.techniques,
        },
        categories_covered: status.coverage.categories,
      };

      if (args.detailed !== false) {
        response.patterns.by_category = status.patterns.byCategory;
        response.patterns.by_severity = status.patterns.bySeverity;
        response.patterns.by_source = status.patterns.bySource;
        response.health_details = {
          oldest_update: status.health.oldestUpdate,
          stale_sources: status.health.staleSources,
          failed_sources: status.health.failedSources,
        };
      }

      if (status.health.status !== 'healthy') {
        response.warnings = [];
        if (status.health.staleSources.length > 0) {
          response.warnings.push(`${status.health.staleSources.length} source(s) have stale data`);
        }
        if (status.health.failedSources.length > 0) {
          response.warnings.push(`${status.health.failedSources.length} source(s) failed to update`);
        }
      }

      return response;
    },

    // === ADD SOURCE ===
    mund_add_intel_source: async (args: {
      id: string;
      name: string;
      url: string;
      description?: string;
      auto_update?: boolean;
      update_interval_hours?: number;
      categories?: string[];
    }) => {
      const source = manager.addSource({
        id: args.id,
        name: args.name,
        type: 'custom',
        url: args.url,
        description: args.description || `Custom intel source: ${args.name}`,
        enabled: true,
        autoUpdate: args.auto_update ?? true,
        updateIntervalHours: args.update_interval_hours ?? 24,
        categories: args.categories as IntelCategory[] || [],
      });

      // Immediately try to fetch patterns
      const updateResult = await manager.updateSource(args.id);

      return {
        success: true,
        source_id: source.id,
        name: source.name,
        initial_fetch: {
          success: updateResult.success,
          patterns_loaded: updateResult.totalPatterns,
          error: updateResult.error,
        },
        message: updateResult.success 
          ? `Added source "${args.name}" with ${updateResult.totalPatterns} patterns`
          : `Added source "${args.name}" but initial fetch failed: ${updateResult.error}`,
      };
    },

    // === REMOVE SOURCE ===
    mund_remove_intel_source: async (args: { source_id: string }) => {
      if (args.source_id === 'weave_builtin') {
        return {
          success: false,
          error: 'Cannot remove built-in Weave patterns',
        };
      }

      const source = manager.getSource(args.source_id);
      if (!source) {
        return {
          success: false,
          error: `Source not found: ${args.source_id}`,
        };
      }

      const removed = manager.removeSource(args.source_id);

      return {
        success: removed,
        source_id: args.source_id,
        name: source.name,
        message: removed ? `Removed source "${source.name}" and its patterns` : 'Failed to remove source',
      };
    },

    // === THREAT SCAN ===
    mund_threat_scan: async (args: {
      content: string;
      categories?: string[];
      min_severity?: string;
      min_confidence?: number;
      include_mitre?: boolean;
    }) => {
      const result = manager.scan(args.content, {
        categories: args.categories as IntelCategory[],
        minSeverity: args.min_severity as Severity,
        minConfidence: args.min_confidence,
        includeMitre: args.include_mitre,
      });

      return {
        threat_detected: result.matches.length > 0,
        highest_severity: result.summary.highest_severity,
        total_matches: result.summary.total_matches,
        by_severity: result.summary.by_severity,
        by_category: result.summary.by_category,
        mitre_techniques: result.summary.mitre_techniques,
        matches: result.matches.slice(0, 20).map(m => ({
          pattern: m.patternName,
          category: m.category,
          severity: m.severity,
          confidence: m.confidence,
          matched_text: m.matchedText,
          position: m.position,
          mitre_id: m.mitreId,
          mitre_tactic: m.mitreTactic,
          recommendation: m.recommendation,
        })),
        recommendations: result.recommendations,
        scan_duration_ms: result.scan_duration_ms,
      };
    },

    // === LIST PATTERNS ===
    mund_list_patterns: async (args: { source_id?: string; category?: string; limit?: number }) => {
      const patterns = manager.listPatterns(args.source_id, args.category as IntelCategory);
      const limit = args.limit ?? 50;

      return {
        total: patterns.length,
        showing: Math.min(limit, patterns.length),
        patterns: patterns.slice(0, limit).map(p => ({
          id: p.id,
          name: p.name,
          source: p.sourceId,
          category: p.category,
          severity: p.severity,
          confidence: p.confidence,
          mitre_id: p.mitreId,
          mitre_tactic: p.mitreTactic,
          enabled: p.enabled,
          version: p.version,
          tags: p.tags,
        })),
      };
    },

    // === TOGGLE PATTERN ===
    mund_toggle_pattern: async (args: { pattern_id: string; enabled: boolean }) => {
      const pattern = manager.getPattern(args.pattern_id);
      if (!pattern) {
        return {
          success: false,
          error: `Pattern not found: ${args.pattern_id}`,
        };
      }

      const result = manager.enablePattern(args.pattern_id, args.enabled);

      return {
        success: result,
        pattern_id: args.pattern_id,
        name: pattern.name,
        enabled: args.enabled,
        message: `Pattern "${pattern.name}" ${args.enabled ? 'enabled' : 'disabled'}`,
      };
    },
  };
}
