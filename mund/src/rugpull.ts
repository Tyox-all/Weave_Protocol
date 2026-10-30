/**
 * Mund - The Guardian Protocol
 * MCP Rug-Pull Detection (OWASP ASI04)
 *
 * A rug pull is an MCP server that passes review at install time and
 * then changes what its tools say or do. Static scanning can't see that,
 * so Mund records a fingerprint of every tool when a server is first
 * approved (the baseline) and diffs later manifests against it.
 *
 *   tool description changed  -> high   (the classic rug pull)
 *   tool input schema changed -> medium
 *   tool added                -> medium
 *   tool removed              -> low
 *   server name changed       -> high
 *
 * Any changed or added tool is re-scanned with the MCP analyzer; if it
 * now trips a high/critical finding, or newly gains execution
 * capability, the change is escalated to critical.
 */

import { createHash } from 'crypto';
import { readFile, writeFile, mkdir, rename } from 'fs/promises';
import { homedir } from 'os';
import { dirname, join } from 'path';
import type { IAnalyzer, SecurityIssue, Severity } from './types.js';
import { McpServerAnalyzer, type McpServerManifest, type McpToolDefinition } from './analyzers/mcp-server-analyzer.js';

export type ToolChangeKind = 'description_changed' | 'schema_changed' | 'tool_added' | 'tool_removed' | 'server_renamed';

export interface ToolFingerprint {
  descriptionHash: string;
  schemaHash: string;
  /** Kept so a diff can show what the description used to say. */
  description: string;
}

export interface ManifestBaseline {
  serverId: string;
  serverName: string;
  recordedAt: string;
  tools: Record<string, ToolFingerprint>;
}

export interface ToolChange {
  kind: ToolChangeKind;
  tool: string;
  severity: Severity;
  detail: string;
  /** Set when the changed tool now trips the MCP analyzer or gains execution capability. */
  escalated?: string;
}

export interface RugPullResult {
  serverId: string;
  status: 'baseline_created' | 'unchanged' | 'changed';
  changes: ToolChange[];
  baselineRecordedAt?: string;
}

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function defaultBaselinePath(): string {
  if (process.env.MUND_BASELINE_PATH) return process.env.MUND_BASELINE_PATH;
  const base = process.env.XDG_CONFIG_HOME || join(homedir(), '.config');
  return join(base, 'mund', 'mcp-baselines.json');
}

/** Stable JSON: object keys sorted so equivalent schemas hash the same. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(',')}}`;
  }
  return JSON.stringify(value ?? null);
}

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

export function fingerprintManifest(serverId: string, manifest: McpServerManifest): ManifestBaseline {
  const tools: Record<string, ToolFingerprint> = {};
  for (const tool of manifest.tools ?? []) {
    tools[tool.name] = {
      descriptionHash: sha256(tool.description ?? ''),
      schemaHash: sha256(canonical(tool.inputSchema ?? {})),
      description: (tool.description ?? '').slice(0, 2000),
    };
  }
  return { serverId, serverName: manifest.name ?? serverId, recordedAt: new Date().toISOString(), tools };
}

/** Compare a manifest against its baseline. Pure: no I/O. */
export async function diffManifest(
  baseline: ManifestBaseline,
  manifest: McpServerManifest,
  analyzer: IAnalyzer = new McpServerAnalyzer(),
): Promise<ToolChange[]> {
  const current = fingerprintManifest(baseline.serverId, manifest);
  const byName = new Map((manifest.tools ?? []).map(t => [t.name, t]));
  const changes: ToolChange[] = [];

  if (current.serverName !== baseline.serverName) {
    changes.push({
      kind: 'server_renamed', tool: '*', severity: 'high',
      detail: `Server name changed from "${baseline.serverName}" to "${current.serverName}"`,
    });
  }

  for (const [name, now] of Object.entries(current.tools)) {
    const before = baseline.tools[name];
    if (!before) {
      changes.push({ kind: 'tool_added', tool: name, severity: 'medium', detail: `New tool "${name}" not present at baseline` });
      continue;
    }
    if (now.descriptionHash !== before.descriptionHash) {
      changes.push({
        kind: 'description_changed', tool: name, severity: 'high',
        detail: `Description of "${name}" changed after approval`,
      });
    }
    if (now.schemaHash !== before.schemaHash) {
      changes.push({ kind: 'schema_changed', tool: name, severity: 'medium', detail: `Input schema of "${name}" changed after approval` });
    }
  }

  for (const name of Object.keys(baseline.tools)) {
    if (!current.tools[name]) {
      changes.push({ kind: 'tool_removed', tool: name, severity: 'low', detail: `Tool "${name}" removed since baseline` });
    }
  }

  // Escalate changed/added tools that now look dangerous.
  for (const change of changes) {
    if (change.kind === 'tool_removed' || change.kind === 'server_renamed') continue;
    const tool = byName.get(change.tool);
    if (!tool) continue;
    const reason = await escalationReason(tool, baseline.tools[change.tool], analyzer);
    if (reason) {
      change.severity = 'critical';
      change.escalated = reason;
    }
  }

  return changes.sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
}

async function escalationReason(
  tool: McpToolDefinition,
  before: ToolFingerprint | undefined,
  analyzer: IAnalyzer,
): Promise<string | undefined> {
  const single = JSON.stringify({ name: 'rugpull-check', tools: [tool] });
  const findings = await analyzer.analyze(single, []);
  const serious = findings.find(f => f.severity === 'critical' || f.severity === 'high');
  if (serious) return `Changed tool now triggers "${serious.rule_name}"`;

  const nowExec = McpServerAnalyzer.analyzeCapabilities({ name: 'x', version: '0', tools: [tool] }).execution;
  const wasExec = before
    ? McpServerAnalyzer.analyzeCapabilities({ name: 'x', version: '0', tools: [{ name: tool.name, description: before.description }] }).execution
    : false;
  if (nowExec && !wasExec) return 'Tool newly requests command-execution capability';
  return undefined;
}

/** Persisted baselines, keyed by server id. */
export class BaselineStore {
  constructor(private path: string = defaultBaselinePath()) {}

  async load(): Promise<Record<string, ManifestBaseline>> {
    try {
      const data = JSON.parse(await readFile(this.path, 'utf8'));
      return data && typeof data === 'object' && data.version === 1 ? data.baselines : {};
    } catch {
      return {};
    }
  }

  async get(serverId: string): Promise<ManifestBaseline | undefined> {
    return (await this.load())[serverId];
  }

  /**
   * Read-modify-write, serialized per file within the process (parallel
   * audits of several servers used to overwrite each other's baselines),
   * and written atomically via rename so a crash can't truncate the file.
   */
  async put(baseline: ManifestBaseline): Promise<void> {
    const prev = BaselineStore.queues.get(this.path) ?? Promise.resolve();
    const next = prev.catch(() => {}).then(async () => {
      const all = await this.load();
      all[baseline.serverId] = baseline;
      await mkdir(dirname(this.path), { recursive: true });
      const tmp = `${this.path}.${process.pid}.${Date.now()}.tmp`;
      await writeFile(tmp, JSON.stringify({ version: 1, baselines: all }, null, 2));
      await rename(tmp, this.path);
    });
    BaselineStore.queues.set(this.path, next);
    return next;
  }

  private static queues = new Map<string, Promise<void>>();
}

/**
 * Check a manifest against its stored baseline. The first check for a
 * server records the baseline. Pass acceptChanges to re-baseline after
 * a human has reviewed the changes.
 */
export async function checkRugPull(
  serverId: string,
  manifest: McpServerManifest,
  opts: { store?: BaselineStore; analyzer?: IAnalyzer; acceptChanges?: boolean } = {},
): Promise<RugPullResult> {
  const store = opts.store ?? new BaselineStore();
  const baseline = await store.get(serverId);

  if (!baseline) {
    await store.put(fingerprintManifest(serverId, manifest));
    return { serverId, status: 'baseline_created', changes: [] };
  }

  const changes = await diffManifest(baseline, manifest, opts.analyzer);
  if (opts.acceptChanges && changes.length > 0) {
    await store.put(fingerprintManifest(serverId, manifest));
  }
  return {
    serverId,
    status: changes.length > 0 ? 'changed' : 'unchanged',
    changes,
    baselineRecordedAt: baseline.recordedAt,
  };
}

/** Express rug-pull changes as standard SecurityIssues (for scoring / SARIF). */
export function changesToIssues(result: RugPullResult): SecurityIssue[] {
  return result.changes.map(c => ({
    rule_id: `mcp_rugpull_${c.kind}`,
    rule_name: `MCP rug pull: ${c.detail}`,
    type: 'mcp_rugpull',
    severity: c.severity,
    action: c.severity === 'critical' || c.severity === 'high' ? 'block' : 'alert',
    match: `${result.serverId}:${c.tool}`,
    suggestion: c.escalated
      ? `${c.escalated}. Do not use this server until the change is reviewed.`
      : 'Review the change before continuing to use this server; accept it to update the baseline.',
  }));
}
