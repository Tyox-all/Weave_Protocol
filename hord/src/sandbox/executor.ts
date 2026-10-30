/**
 * Hord - The Vault Protocol
 * Sandbox Executor
 * 
 * Isolated execution environment for testing agent outputs before promotion.
 */

import { spawn, ChildProcess } from 'child_process';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import type {
  Sandbox,
  SandboxConfig,
  SandboxExecutionRequest,
  SandboxResult,
  ResourceUsage,
  SyscallTrace,
  NetworkActivity,
  FilesystemChange,
  SecurityEvent,
  IHordStorage,
  PromotionRecommendation,
} from '../types.js';
import { SandboxError, PromotionRecommendation as PR, IsolationLevel } from '../types.js';
import { SANDBOX } from '../constants.js';
import { generateId } from '../vault/encryption.js';
import { planLaunch, missingForStrict, startMemoryWatchdog, type IsolationReport } from './isolation.js';
import { constants as osConstants } from 'os';

interface ProcessOutcome {
  stdout: string;
  stderr: string;
  exitCode: number;
  timeout: boolean;
  signal?: string;
  memoryExceeded: boolean;
  peak_memory_mb: number;
  isolation: IsolationReport;
}

// ============================================================================
// Sandbox Manager
// ============================================================================

export class SandboxManager {
  private storage: IHordStorage;
  private activeSandboxes: Map<string, { sandbox: Sandbox; process?: ChildProcess; workdir?: string }> = new Map();
  
  constructor(storage: IHordStorage) {
    this.storage = storage;
  }
  
  /**
   * Create a new sandbox
   */
  async createSandbox(config: SandboxConfig): Promise<Sandbox> {
    const sandboxId = config.id || generateId('sandbox_');
    
    // Apply defaults
    const fullConfig: SandboxConfig = {
      ...config,
      resource_limits: {
        ...SANDBOX.DEFAULT_LIMITS,
        ...config.resource_limits,
      },
      network_policy: {
        ...SANDBOX.DEFAULT_NETWORK_POLICY,
        ...config.network_policy,
      },
      filesystem_policy: {
        ...SANDBOX.DEFAULT_FILESYSTEM_POLICY,
        ...config.filesystem_policy,
      },
      timeout_ms: config.timeout_ms || SANDBOX.DEFAULT_LIMITS.cpu_seconds * 1000,
    };
    
    // Create working directory
    const workdir = await fs.mkdtemp(path.join(os.tmpdir(), `hord-sandbox-${sandboxId}-`));
    
    const sandbox: Sandbox = {
      id: sandboxId,
      config: fullConfig,
      status: 'created',
      created_at: new Date(),
    };
    
    await this.storage.saveSandbox(sandbox);
    this.activeSandboxes.set(sandboxId, { sandbox, workdir });
    
    return sandbox;
  }
  
  /**
   * Execute code/command in a sandbox
   */
  async execute(request: SandboxExecutionRequest): Promise<SandboxResult> {
    const sandboxData = this.activeSandboxes.get(request.sandbox_id);
    if (!sandboxData) {
      throw new SandboxError('Sandbox not found or not active', { sandbox_id: request.sandbox_id });
    }
    
    const { sandbox, workdir } = sandboxData;
    
    if (!workdir) {
      throw new SandboxError('Sandbox working directory not initialized');
    }
    
    // Strict sandboxes refuse to run without real isolation.
    const probe = planLaunch('true', [], {
      workdir,
      limits: sandbox.config.resource_limits,
      network: sandbox.config.network_policy,
      filesystem: sandbox.config.filesystem_policy,
    }).report;
    const missing = missingForStrict(probe, sandbox.config.network_policy);
    if (sandbox.config.enforcement === 'strict' && missing.length > 0) {
      throw new SandboxError(
        `Strict sandbox cannot run on this host: missing ${missing.join(', ')} (isolation available: ${probe.mechanism})`,
        { sandbox_id: sandbox.id, missing },
      );
    }

    // Update status
    sandbox.status = 'running';
    sandbox.started_at = new Date();
    await this.storage.updateSandboxStatus(sandbox.id, 'running');
    
    const startTime = Date.now();
    const securityEvents: SecurityEvent[] = [];
    const filesystemChanges: FilesystemChange[] = [];
    const networkActivity: NetworkActivity[] = [];
    const syscalls: SyscallTrace[] = [];
    
    let stdout = '';
    let stderr = '';
    let exitCode: number | undefined;
    let status: SandboxResult['status'] = 'success';
    let isolation: IsolationReport | undefined;
    let peakMemoryMb = 0;

    // Fold one process outcome into the result.
    const absorb = (result: ProcessOutcome) => {
      stdout = result.stdout;
      stderr = result.stderr;
      exitCode = result.exitCode;
      isolation = result.isolation;
      peakMemoryMb = result.peak_memory_mb;
      if (result.memoryExceeded) {
        status = 'violation';
        securityEvents.push({
          timestamp: new Date(),
          severity: 'critical',
          type: 'resource_limit_exceeded',
          description: `Memory limit exceeded (${sandbox.config.resource_limits.memory_mb} MB); process group killed`,
          details: { peak_memory_mb: result.peak_memory_mb },
        });
      } else if (result.timeout) {
        status = 'timeout';
      } else if (exitCode !== 0) {
        status = 'failure';
      }
      for (const gap of missingForStrict(result.isolation, sandbox.config.network_policy)) {
        securityEvents.push({
          timestamp: new Date(),
          severity: 'warning',
          type: 'isolation_unavailable',
          description: `Ran without ${gap}: the host provides "${result.isolation.mechanism}" isolation`,
          details: { isolation: result.isolation },
        });
      }
    };
    
    try {
      // Check for suspicious patterns before execution
      const patternCheck = this.checkSuspiciousPatterns(request.content);
      if (patternCheck.length > 0) {
        securityEvents.push(...patternCheck);
      }
      
      // Prepare execution based on type
      if (request.type === 'code') {
        const result = await this.executeCode(
          request.content,
          request.language || 'javascript',
          workdir,
          sandbox.config,
          request.inputs
        );
        absorb(result);
        
        // Check for security violations in output
        const outputCheck = this.checkOutputForViolations(stdout + stderr);
        securityEvents.push(...outputCheck);
        
      } else if (request.type === 'command') {
        const result = await this.executeCommand(
          request.content,
          workdir,
          sandbox.config
        );
        absorb(result);
      }
      
      // Check filesystem changes
      const fsChanges = await this.detectFilesystemChanges(workdir);
      filesystemChanges.push(...fsChanges);
      
    } catch (error) {
      status = 'error';
      stderr = error instanceof Error ? error.message : String(error);
      securityEvents.push({
        timestamp: new Date(),
        severity: 'critical',
        type: 'execution_error',
        description: 'Sandbox execution failed with error',
        details: { error: stderr },
      });
    }
    
    const endTime = Date.now();
    const duration_ms = endTime - startTime;
    
    // Calculate resource usage (simplified)
    const resourceUsage: ResourceUsage = {
      cpu_seconds_used: duration_ms / 1000,
      memory_peak_mb: peakMemoryMb,
      disk_written_mb: filesystemChanges.reduce((sum, c) => sum + (c.size_bytes || 0), 0) / (1024 * 1024),
      network_bytes_sent: 0,
      network_bytes_received: 0,
      processes_spawned: 1,
    };
    
    // Determine promotion recommendation
    const { recommendation, reasons } = this.calculatePromotionRecommendation(
      status,
      securityEvents,
      filesystemChanges,
      networkActivity,
      request.declared_intent
    );
    
    // Update sandbox status
    sandbox.status = status === 'success' ? 'completed' : 'failed';
    sandbox.completed_at = new Date();
    await this.storage.updateSandboxStatus(sandbox.id, sandbox.status);
    
    const result: SandboxResult = {
      id: generateId('result_'),
      sandbox_id: request.sandbox_id,
      status,
      exit_code: exitCode,
      stdout,
      stderr,
      duration_ms,
      resource_usage: resourceUsage,
      syscalls,
      network_activity: networkActivity,
      filesystem_changes: filesystemChanges,
      security_events: securityEvents,
      promotion_recommendation: recommendation,
      recommendation_reasons: reasons,
      isolation,
    };
    
    await this.storage.saveSandboxResult(result);
    
    return result;
  }
  
  /**
   * Promote sandbox result (mark as safe for real execution)
   */
  async promote(sandboxId: string, resultId: string): Promise<{ promoted: boolean; reason?: string }> {
    const result = await this.storage.getSandboxResult(resultId);
    if (!result) {
      return { promoted: false, reason: 'Result not found' };
    }
    
    if (result.sandbox_id !== sandboxId) {
      return { promoted: false, reason: 'Result does not belong to this sandbox' };
    }
    
    if (result.promotion_recommendation === PR.BLOCK) {
      return { 
        promoted: false, 
        reason: `Promotion blocked: ${result.recommendation_reasons.join(', ')}` 
      };
    }
    
    if (result.promotion_recommendation === PR.REVIEW) {
      return {
        promoted: false,
        reason: `Manual review required: ${result.recommendation_reasons.join(', ')}`,
      };
    }
    
    // Log promotion
    await this.storage.logAccess({
      id: generateId('log_'),
      timestamp: new Date(),
      agent_id: 'system',
      action: 'promote_sandbox_result',
      resource: `sandbox:${sandboxId}/result:${resultId}`,
      success: true,
    });
    
    return { promoted: true };
  }
  
  /**
   * Destroy a sandbox
   */
  async destroy(sandboxId: string): Promise<void> {
    const sandboxData = this.activeSandboxes.get(sandboxId);
    if (!sandboxData) {
      return;
    }
    
    // Kill any running process
    if (sandboxData.process && !sandboxData.process.killed) {
      sandboxData.process.kill('SIGKILL');
    }
    
    // Clean up working directory
    if (sandboxData.workdir) {
      try {
        await fs.rm(sandboxData.workdir, { recursive: true, force: true });
      } catch {
        // Ignore cleanup errors
      }
    }
    
    // Update status
    await this.storage.updateSandboxStatus(sandboxId, 'destroyed');
    
    this.activeSandboxes.delete(sandboxId);
  }
  
  /**
   * Get sandbox info
   */
  async getSandbox(sandboxId: string): Promise<Sandbox | null> {
    return this.storage.getSandbox(sandboxId);
  }
  
  /**
   * Get sandbox results
   */
  async getResults(sandboxId: string): Promise<SandboxResult[]> {
    return this.storage.getSandboxResults(sandboxId);
  }
  
  // ============================================================================
  // Private Methods
  // ============================================================================
  
  private async executeCode(
    code: string,
    language: string,
    workdir: string,
    config: SandboxConfig,
    inputs?: Record<string, unknown>
  ): Promise<ProcessOutcome> {
    let command: string;
    let args: string[];
    let filename: string;
    
    switch (language.toLowerCase()) {
      case 'javascript':
      case 'js':
        filename = 'script.js';
        // Wrap with input handling
        const jsCode = inputs 
          ? `const __inputs = ${JSON.stringify(inputs)};\n${code}`
          : code;
        await fs.writeFile(path.join(workdir, filename), jsCode);
        command = 'node';
        args = [filename];
        break;
        
      case 'python':
      case 'py':
        filename = 'script.py';
        const pyCode = inputs
          ? `__inputs = ${JSON.stringify(inputs)}\n${code}`
          : code;
        await fs.writeFile(path.join(workdir, filename), pyCode);
        command = 'python3';
        args = [filename];
        break;
        
      case 'bash':
      case 'sh':
        filename = 'script.sh';
        await fs.writeFile(path.join(workdir, filename), code);
        command = 'bash';
        args = [filename];
        break;
        
      default:
        throw new SandboxError(`Unsupported language: ${language}`);
    }
    
    return this.runProcess(command, args, workdir, config);
  }
  
  private async executeCommand(
    command: string,
    workdir: string,
    config: SandboxConfig
  ): Promise<ProcessOutcome> {
    // Parse command
    const parts = command.split(/\s+/);
    const cmd = parts[0];
    const args = parts.slice(1);
    
    return this.runProcess(cmd, args, workdir, config);
  }
  
  private runProcess(
    command: string,
    args: string[],
    workdir: string,
    config: SandboxConfig
  ): Promise<ProcessOutcome> {
    const plan = planLaunch(command, args, {
      workdir,
      limits: config.resource_limits,
      network: config.network_policy,
      filesystem: config.filesystem_policy,
      environment: config.environment,
    });

    return new Promise((resolve) => {
      const timeout = config.timeout_ms || SANDBOX.DEFAULT_LIMITS.cpu_seconds * 1000;
      let stdout = '';
      let stderr = '';
      let timedOut = false;
      let memoryExceeded = false;
      let settled = false;

      const proc = spawn(plan.command, plan.args, {
        cwd: workdir,
        env: plan.env,
        detached: plan.detached, // own process group, so we can kill the whole tree
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      const killGroup = () => {
        try {
          if (plan.detached && proc.pid) process.kill(-proc.pid, 'SIGKILL');
          else proc.kill('SIGKILL');
        } catch {
          /* already gone */
        }
      };

      const stopWatchdog = proc.pid && plan.detached
        ? startMemoryWatchdog(proc.pid, config.resource_limits.memory_mb, () => {
            memoryExceeded = true;
            killGroup();
          })
        : () => 0;

      const timeoutId = setTimeout(() => {
        timedOut = true;
        killGroup();
      }, timeout);

      proc.stdout?.on('data', (data) => {
        stdout += data.toString();
        if (stdout.length > 1024 * 1024) killGroup();
      });
      proc.stderr?.on('data', (data) => {
        stderr += data.toString();
        if (stderr.length > 1024 * 1024) killGroup();
      });

      const finish = (outcome: Omit<ProcessOutcome, 'peak_memory_mb' | 'isolation'>) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeoutId);
        resolve({ ...outcome, peak_memory_mb: stopWatchdog(), isolation: plan.report });
      };

      proc.on('close', (code, signal) => {
        // A process killed by a signal has no exit code; report 128 + signo
        // (shell convention) instead of the old "code || 0", which made a
        // killed run look successful.
        const signo = signal ? (osConstants.signals as Record<string, number>)[signal] ?? 0 : 0;
        finish({
          stdout: stdout.slice(0, 100000),
          stderr: stderr.slice(0, 100000),
          exitCode: code ?? (signal ? 128 + signo : 1),
          timeout: timedOut,
          signal: signal ?? undefined,
          memoryExceeded,
        });
      });

      proc.on('error', (err) => {
        finish({ stdout, stderr: err.message, exitCode: 1, timeout: false, memoryExceeded: false });
      });
    });
  }

  
  private checkSuspiciousPatterns(content: string): SecurityEvent[] {
    const events: SecurityEvent[] = [];
    
    for (const pattern of SANDBOX.SUSPICIOUS_CODE_PATTERNS) {
      if (pattern.test(content)) {
        events.push({
          timestamp: new Date(),
          severity: 'warning',
          type: 'suspicious_pattern',
          description: `Suspicious code pattern detected: ${pattern.source}`,
          details: { pattern: pattern.source },
        });
      }
    }
    
    return events;
  }
  
  private checkOutputForViolations(output: string): SecurityEvent[] {
    const events: SecurityEvent[] = [];
    
    // Check for common error patterns that might indicate security issues
    const errorPatterns = [
      { pattern: /permission denied/i, type: 'permission_violation' },
      { pattern: /access denied/i, type: 'access_violation' },
      { pattern: /EACCES/i, type: 'permission_error' },
      { pattern: /segmentation fault/i, type: 'memory_violation' },
      { pattern: /stack smashing/i, type: 'buffer_overflow' },
    ];
    
    for (const { pattern, type } of errorPatterns) {
      if (pattern.test(output)) {
        events.push({
          timestamp: new Date(),
          severity: 'warning',
          type,
          description: `Potential security issue in output: ${type}`,
          details: { matched: pattern.source },
        });
      }
    }
    
    return events;
  }
  
  private async detectFilesystemChanges(workdir: string): Promise<FilesystemChange[]> {
    const changes: FilesystemChange[] = [];
    
    try {
      const files = await fs.readdir(workdir, { withFileTypes: true });
      
      for (const file of files) {
        const filePath = path.join(workdir, file.name);
        const stats = await fs.stat(filePath);
        
        changes.push({
          timestamp: new Date(),
          operation: 'create',
          path: file.name,
          size_bytes: stats.size,
          flagged: false,
        });
      }
    } catch {
      // Ignore errors
    }
    
    return changes;
  }
  
  private calculatePromotionRecommendation(
    status: SandboxResult['status'],
    securityEvents: SecurityEvent[],
    filesystemChanges: FilesystemChange[],
    networkActivity: NetworkActivity[],
    declaredIntent: string
  ): { recommendation: PromotionRecommendation; reasons: string[] } {
    const reasons: string[] = [];
    
    // Check for critical security events
    const criticalEvents = securityEvents.filter(e => e.severity === 'critical');
    if (criticalEvents.length > 0) {
      reasons.push(`${criticalEvents.length} critical security event(s) detected`);
      return { recommendation: PR.BLOCK, reasons };
    }
    
    // Check execution status
    if (status === 'timeout') {
      reasons.push('Execution timed out');
      return { recommendation: PR.BLOCK, reasons };
    }
    
    if (status === 'violation') {
      reasons.push('Security violation detected');
      return { recommendation: PR.BLOCK, reasons };
    }
    
    if (status === 'error') {
      reasons.push('Execution error occurred');
      return { recommendation: PR.REVIEW, reasons };
    }

    // A run without full isolation can't be promoted as safe, however clean it looked.
    const gaps = securityEvents.filter(e => e.type === 'isolation_unavailable');
    if (gaps.length > 0) {
      reasons.push(`Ran without full isolation: ${gaps.map(g => g.description).join('; ')}`);
      return { recommendation: PR.REVIEW, reasons };
    }
    
    // Check for warning events
    const warningEvents = securityEvents.filter(e => e.severity === 'warning');
    if (warningEvents.length > 2) {
      reasons.push(`Multiple warning events (${warningEvents.length})`);
      return { recommendation: PR.REVIEW, reasons };
    }
    
    // Check for blocked network activity
    const blockedNetwork = networkActivity.filter(n => n.blocked);
    if (blockedNetwork.length > 0) {
      reasons.push('Attempted blocked network access');
      return { recommendation: PR.REVIEW, reasons };
    }
    
    // Check for flagged filesystem changes
    const flaggedChanges = filesystemChanges.filter(c => c.flagged);
    if (flaggedChanges.length > 0) {
      reasons.push('Suspicious filesystem changes detected');
      return { recommendation: PR.REVIEW, reasons };
    }
    
    // If we got here with warnings, require review
    if (warningEvents.length > 0) {
      reasons.push('Warning events present');
      return { recommendation: PR.REVIEW, reasons };
    }
    
    // All clear
    reasons.push('No security issues detected');
    return { recommendation: PR.SAFE, reasons };
  }
}
