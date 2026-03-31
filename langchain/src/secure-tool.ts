/**
 * Secure Tool Wrapper
 * Wraps LangChain tools with security scanning
 * @weave_protocol/langchain
 */

import { DynamicTool, DynamicStructuredTool } from '@langchain/core/tools';
import type { ToolParams } from '@langchain/core/tools';
import type { z } from 'zod';

import type { SecureToolConfig, SecurityConfig, ThreatMatch } from './types.js';
import { DEFAULT_CONFIG } from './types.js';
import { createScanner, type Scanner } from './scanner.js';

// ============================================================================
// Secure Tool Wrapper
// ============================================================================

export interface SecureToolOptions extends SecureToolConfig {
  /** Scanner instance (uses local if not provided) */
  scanner?: Scanner;
  
  /** Callback when threat is detected */
  onThreat?: (threats: ThreatMatch[], input: string) => void | Promise<void>;
  
  /** Callback for approval (if requireApproval is true) */
  onApprovalRequired?: (input: string) => Promise<boolean>;
}

/**
 * Wraps a DynamicTool with security scanning
 */
export function createSecureTool(
  tool: DynamicTool,
  options: SecureToolOptions
): DynamicTool {
  const scanner = options.scanner || createScanner();
  const config: SecurityConfig = { ...DEFAULT_CONFIG, ...options.security };

  const originalFunc = tool.func.bind(tool);

  const secureFunc = async (input: string): Promise<string> => {
    // Check input length
    if (options.maxInputLength && input.length > options.maxInputLength) {
      throw new Error(
        `[SecureTool:${options.name}] Input exceeds maximum length of ${options.maxInputLength}`
      );
    }

    // Check blocked patterns
    if (options.blockedInputPatterns) {
      for (const pattern of options.blockedInputPatterns) {
        if (new RegExp(pattern, 'i').test(input)) {
          throw new Error(
            `[SecureTool:${options.name}] Input matches blocked pattern`
          );
        }
      }
    }

    // Check allowed patterns (if specified, input must match at least one)
    if (options.allowedInputPatterns && options.allowedInputPatterns.length > 0) {
      const matches = options.allowedInputPatterns.some(p => 
        new RegExp(p, 'i').test(input)
      );
      if (!matches) {
        throw new Error(
          `[SecureTool:${options.name}] Input does not match any allowed pattern`
        );
      }
    }

    // Scan input for threats
    const scanResult = await scanner.scan(input, {
      categories: config.categories,
      minSeverity: config.minSeverity,
    });

    if (scanResult.threats.length > 0) {
      // Emit threat callback
      if (options.onThreat) {
        await options.onThreat(scanResult.threats, input);
      }

      // Block if configured
      if (config.action === 'block') {
        throw new Error(
          `[SecureTool:${options.name}] Blocked: ${scanResult.threats.length} threat(s) detected. ` +
          `Highest severity: ${scanResult.highestSeverity}`
        );
      }
    }

    // Check for approval requirement
    if (options.requireApproval) {
      if (!options.onApprovalRequired) {
        throw new Error(
          `[SecureTool:${options.name}] Approval required but no approval callback provided`
        );
      }

      const approved = await options.onApprovalRequired(input);
      if (!approved) {
        throw new Error(
          `[SecureTool:${options.name}] Tool execution not approved`
        );
      }
    }

    // Execute original tool
    const output = await originalFunc(input);

    // Scan output
    if (config.scanTarget === 'both' || config.scanTarget === 'output') {
      const outputScan = await scanner.scan(output, {
        categories: config.categories,
        minSeverity: config.minSeverity,
      });

      if (outputScan.threats.length > 0) {
        if (options.onThreat) {
          await options.onThreat(outputScan.threats, output);
        }

        if (config.action === 'block') {
          throw new Error(
            `[SecureTool:${options.name}] Blocked: Threat detected in output`
          );
        }
      }
    }

    return output;
  };

  return new DynamicTool({
    name: tool.name,
    description: tool.description,
    func: secureFunc,
  });
}

/**
 * Wraps a DynamicStructuredTool with security scanning
 * Note: Due to LangChain's complex generics, this returns a new tool
 * that scans inputs/outputs for threats
 */
export function createSecureStructuredTool<T extends z.ZodObject<any>>(
  tool: DynamicStructuredTool<T>,
  options: SecureToolOptions
): DynamicStructuredTool<T> {
  const scanner = options.scanner || createScanner();
  const config: SecurityConfig = { ...DEFAULT_CONFIG, ...options.security };

  // Create a wrapper that scans before/after the original function
  const secureFunc = async (input: Record<string, any>): Promise<string> => {
    const inputStr = JSON.stringify(input);

    // Check input length
    if (options.maxInputLength && inputStr.length > options.maxInputLength) {
      throw new Error(
        `[SecureTool:${options.name}] Input exceeds maximum length of ${options.maxInputLength}`
      );
    }

    // Scan input
    const scanResult = await scanner.scan(inputStr, {
      categories: config.categories,
      minSeverity: config.minSeverity,
    });

    if (scanResult.threats.length > 0) {
      if (options.onThreat) {
        await options.onThreat(scanResult.threats, inputStr);
      }

      if (config.action === 'block') {
        throw new Error(
          `[SecureTool:${options.name}] Blocked: ${scanResult.threats.length} threat(s) detected`
        );
      }
    }

    // Check approval
    if (options.requireApproval) {
      if (!options.onApprovalRequired) {
        throw new Error(
          `[SecureTool:${options.name}] Approval required but no callback provided`
        );
      }

      const approved = await options.onApprovalRequired(inputStr);
      if (!approved) {
        throw new Error(`[SecureTool:${options.name}] Execution not approved`);
      }
    }

    // Execute original - cast to any to handle complex generics
    const output = await (tool.func as any)(input);

    // Scan output
    if (config.scanTarget === 'both' || config.scanTarget === 'output') {
      const outputScan = await scanner.scan(output, {
        categories: config.categories,
        minSeverity: config.minSeverity,
      });

      if (outputScan.threats.length > 0 && config.action === 'block') {
        throw new Error(
          `[SecureTool:${options.name}] Blocked: Threat in output`
        );
      }
    }

    return output;
  };

  return new DynamicStructuredTool<T>({
    name: tool.name,
    description: tool.description,
    schema: tool.schema as T,
    func: secureFunc as any,
  });
}

// ============================================================================
// High-Risk Tool Wrapper
// ============================================================================

/**
 * Creates a tool that always requires approval
 * Useful for dangerous operations like file system access, shell commands, etc.
 */
export function createHighRiskTool(
  tool: DynamicTool,
  approvalCallback: (input: string, toolName: string) => Promise<boolean>,
  options?: Partial<SecureToolOptions>
): DynamicTool {
  return createSecureTool(tool, {
    name: options?.name || tool.name,
    requireApproval: true,
    onApprovalRequired: (input) => approvalCallback(input, tool.name),
    security: {
      action: 'block',
      minSeverity: 'low',
      ...options?.security,
    },
    ...options,
  });
}
