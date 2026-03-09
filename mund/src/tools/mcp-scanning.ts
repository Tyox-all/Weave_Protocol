/**
 * Mund - The Guardian Protocol
 * MCP Scanning Tools - Tools for scanning MCP servers before installation
 * 
 * Tools:
 * - mund_scan_mcp_server: Full security scan of a server manifest
 * - mund_check_typosquatting: Check if a name is typosquatting a known server
 * - mund_audit_mcp_permissions: Audit the permission scope of server tools
 */

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { 
  McpServerAnalyzer, 
  type McpServerManifest, 
  type McpCapabilities,
  type McpScanResult 
} from '../analyzers/mcp-server-analyzer.js';
import type { SecurityIssue } from '../types.js';

// ============================================================================
// Tool Schemas
// ============================================================================

const ScanMcpServerSchema = z.object({
  manifest: z.string().describe('JSON content of server.json manifest to scan'),
  source: z.string().optional().describe('Source URL, registry name, or file path for context')
});

const CheckTyposquattingSchema = z.object({
  name: z.string().describe('MCP server name to check for typosquatting')
});

const AuditPermissionsSchema = z.object({
  manifest: z.string().describe('JSON content of server.json manifest to audit')
});

// ============================================================================
// Tool Registration
// ============================================================================

/**
 * Register all MCP scanning tools
 */
export function registerMcpScanningTools(server: McpServer): void {
  const analyzer = new McpServerAnalyzer();

  // -------------------------------------------------------------------------
  // Tool: mund_scan_mcp_server
  // -------------------------------------------------------------------------
  server.tool(
    'mund_scan_mcp_server',
    'Scan an MCP server manifest (server.json) for security issues before installation. Detects prompt injection in tool descriptions, typosquatting, embedded secrets, and dangerous permissions.',
    ScanMcpServerSchema.shape,
    async ({ manifest, source }): Promise<{ content: Array<{ type: 'text'; text: string }> }> => {
      try {
        // Parse manifest
        const parsed = McpServerAnalyzer.parseManifest(manifest);
        if (!parsed) {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                error: 'Invalid manifest',
                message: 'Could not parse the provided content as a valid MCP server manifest. Ensure it is valid JSON with name, tools, or resources fields.',
                recommendation: 'CANNOT_ANALYZE'
              }, null, 2)
            }]
          };
        }

        // Run full analysis
        const issues = await analyzer.analyze(manifest, []);
        
        // Analyze capabilities
        const capabilities = McpServerAnalyzer.analyzeCapabilities(parsed);
        const riskLevel = McpServerAnalyzer.getRiskLevel(capabilities);

        // Count by severity
        const bySeverity = {
          critical: issues.filter(i => i.severity === 'critical').length,
          high: issues.filter(i => i.severity === 'high').length,
          medium: issues.filter(i => i.severity === 'medium').length,
          low: issues.filter(i => i.severity === 'low').length,
          info: issues.filter(i => i.severity === 'info').length
        };

        // Determine recommendation
        let recommendation: McpScanResult['recommendation'];
        if (bySeverity.critical > 0) {
          recommendation = 'DO_NOT_INSTALL';
        } else if (bySeverity.high > 0) {
          recommendation = 'REVIEW_CAREFULLY';
        } else if (bySeverity.medium > 0 || riskLevel === 'HIGH') {
          recommendation = 'CAUTION';
        } else {
          recommendation = 'APPEARS_SAFE';
        }

        const result: McpScanResult = {
          server_name: parsed.name || 'unknown',
          version: parsed.version || 'unknown',
          scanned_at: new Date().toISOString(),
          source,
          issue_count: issues.length,
          by_severity: bySeverity,
          recommendation,
          capabilities,
          issues: issues.map(formatIssue)
        };

        return {
          content: [{
            type: 'text',
            text: JSON.stringify(result, null, 2)
          }]
        };
      } catch (error) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              error: 'Scan failed',
              message: error instanceof Error ? error.message : 'Unknown error occurred',
              recommendation: 'CANNOT_ANALYZE'
            }, null, 2)
          }]
        };
      }
    }
  );

  // -------------------------------------------------------------------------
  // Tool: mund_check_typosquatting
  // -------------------------------------------------------------------------
  server.tool(
    'mund_check_typosquatting',
    'Check if an MCP server name is potentially typosquatting a known legitimate server. Compares against a list of official and common MCP servers.',
    CheckTyposquattingSchema.shape,
    async ({ name }): Promise<{ content: Array<{ type: 'text'; text: string }> }> => {
      try {
        // Create a minimal manifest for the check
        const fakeManifest: McpServerManifest = { name, version: '0.0.0' };
        const issues = analyzer.checkTyposquatting(fakeManifest);

        const similarTo = issues.map(i => {
          // Extract the legitimate name from the match string
          const match = i.match?.match(/"([^"]+)"$/);
          return match ? match[1] : i.match;
        });

        const result = {
          name,
          checked_at: new Date().toISOString(),
          is_suspicious: issues.length > 0,
          risk_level: issues.length > 0 ? 'HIGH' : 'NONE',
          similar_to: similarTo,
          details: issues.map(i => ({
            pattern: i.rule_name,
            match: i.match,
            suggestion: i.suggestion
          })),
          recommendation: issues.length > 0 
            ? 'This name is suspiciously similar to a known legitimate server. Verify you have the correct server from a trusted source before installing.'
            : 'No typosquatting patterns detected. This does not guarantee the server is safe - always verify the source.'
        };

        return {
          content: [{
            type: 'text',
            text: JSON.stringify(result, null, 2)
          }]
        };
      } catch (error) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              error: 'Check failed',
              message: error instanceof Error ? error.message : 'Unknown error occurred'
            }, null, 2)
          }]
        };
      }
    }
  );

  // -------------------------------------------------------------------------
  // Tool: mund_audit_mcp_permissions
  // -------------------------------------------------------------------------
  server.tool(
    'mund_audit_mcp_permissions',
    'Analyze the permission scope and capabilities of an MCP server\'s tools. Identifies network access, filesystem operations, command execution, and other potentially dangerous capabilities.',
    AuditPermissionsSchema.shape,
    async ({ manifest }): Promise<{ content: Array<{ type: 'text'; text: string }> }> => {
      try {
        // Parse manifest
        const parsed = McpServerAnalyzer.parseManifest(manifest);
        if (!parsed) {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                error: 'Invalid manifest',
                message: 'Could not parse as MCP server manifest'
              }, null, 2)
            }]
          };
        }

        // Get capabilities
        const capabilities = McpServerAnalyzer.analyzeCapabilities(parsed);
        const riskLevel = McpServerAnalyzer.getRiskLevel(capabilities);

        // Get permission-related issues
        const allIssues = await analyzer.analyze(manifest, []);
        const permissionIssues = allIssues.filter(i => 
          i.rule_id.startsWith('mcp_capability_') || 
          i.rule_id === 'mcp_execution_warning' ||
          i.rule_id === 'mcp_excessive_tools'
        );

        // Analyze each tool
        const toolAnalysis = (parsed.tools || []).map(tool => {
          const combined = `${tool.name} ${tool.description || ''}`.toLowerCase();
          const permissions: string[] = [];

          if (/\b(fetch|request|http|https|curl|wget|axios|socket|websocket)\b/i.test(combined)) {
            permissions.push('network');
          }
          if (/\b(file|read|write|path|directory|fs|fopen)\b/i.test(combined)) {
            permissions.push('filesystem');
          }
          if (/\b(exec|execute|shell|command|bash|spawn|eval)\b/i.test(combined)) {
            permissions.push('execution');
          }
          if (/\b(env|environment|process\.env|secret|credential)\b/i.test(combined)) {
            permissions.push('environment');
          }
          if (/\b(sql|query|database|db|postgres|mysql|mongo|redis)\b/i.test(combined)) {
            permissions.push('database');
          }
          if (/\b(crypto|encrypt|decrypt|hash|sign)\b/i.test(combined)) {
            permissions.push('crypto');
          }

          return {
            name: tool.name,
            description: truncate(tool.description || '', 100),
            detected_permissions: permissions,
            risk: permissions.includes('execution') ? 'HIGH' : 
                  permissions.length > 1 ? 'MEDIUM' : 
                  permissions.length > 0 ? 'LOW' : 'NONE'
          };
        });

        const result = {
          server_name: parsed.name || 'unknown',
          version: parsed.version || 'unknown',
          audited_at: new Date().toISOString(),
          tool_count: parsed.tools?.length || 0,
          resource_count: parsed.resources?.length || 0,
          prompt_count: parsed.prompts?.length || 0,
          overall_risk_level: riskLevel,
          capabilities,
          capability_summary: formatCapabilitySummary(capabilities),
          tools: toolAnalysis,
          permission_issues: permissionIssues.map(formatIssue),
          recommendations: generatePermissionRecommendations(capabilities, parsed.tools?.length || 0)
        };

        return {
          content: [{
            type: 'text',
            text: JSON.stringify(result, null, 2)
          }]
        };
      } catch (error) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              error: 'Audit failed',
              message: error instanceof Error ? error.message : 'Unknown error occurred'
            }, null, 2)
          }]
        };
      }
    }
  );
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Format a security issue for JSON output
 */
function formatIssue(issue: SecurityIssue): SecurityIssue {
  return {
    rule_id: issue.rule_id,
    rule_name: issue.rule_name,
    type: issue.type,
    severity: issue.severity,
    action: issue.action,
    match: issue.match,
    suggestion: issue.suggestion,
    location: issue.location
  };
}

/**
 * Truncate a string
 */
function truncate(str: string, maxLength: number): string {
  if (str.length <= maxLength) return str;
  return str.substring(0, maxLength) + '...';
}

/**
 * Format capabilities into a human-readable summary
 */
function formatCapabilitySummary(capabilities: McpCapabilities): string[] {
  const summary: string[] = [];
  
  if (capabilities.execution) {
    summary.push('⚠️  Can execute commands/code on your system');
  }
  if (capabilities.filesystem) {
    summary.push('📁 Can read/write files');
  }
  if (capabilities.network) {
    summary.push('🌐 Can make network requests');
  }
  if (capabilities.environment) {
    summary.push('🔑 Can access environment variables/secrets');
  }
  if (capabilities.database) {
    summary.push('🗄️  Can access databases');
  }
  if (capabilities.crypto) {
    summary.push('🔐 Uses cryptographic operations');
  }
  
  if (summary.length === 0) {
    summary.push('✅ No dangerous capabilities detected');
  }
  
  return summary;
}

/**
 * Generate permission-based recommendations
 */
function generatePermissionRecommendations(capabilities: McpCapabilities, toolCount: number): string[] {
  const recommendations: string[] = [];

  if (capabilities.execution) {
    recommendations.push('CRITICAL: This server can execute arbitrary commands. Only install if you fully trust the source and understand what commands it will run.');
  }

  if (capabilities.filesystem && capabilities.network) {
    recommendations.push('HIGH RISK: This server can both access files and make network requests. This combination could be used to exfiltrate data.');
  }

  if (capabilities.environment) {
    recommendations.push('This server can access environment variables, which may include API keys and secrets. Ensure you trust the source.');
  }

  if (toolCount > 20) {
    recommendations.push(`This server has ${toolCount} tools, which is a large attack surface. Consider whether you need all of them.`);
  }

  if (recommendations.length === 0) {
    recommendations.push('This server has a relatively low-risk permission profile, but always verify the source before installing.');
  }

  return recommendations;
}

export default registerMcpScanningTools;
