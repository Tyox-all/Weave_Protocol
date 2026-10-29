/**
 * Mund - The Guardian Protocol
 * Agent audit: pre-install checks for skills and MCP servers
 *
 * Backs the "pre-install" hooks in the Weave Protocol harness adapters:
 *
 *   - Skills: scan SKILL.md and every text file in a skill directory for
 *     prompt injection, exfiltration, dangerous code, secrets and hidden
 *     Unicode (invisible "tag" characters can smuggle instructions that a
 *     human reviewer never sees).
 *   - MCP servers: static checks on how each configured server is launched
 *     (package typosquats, unpinned packages, insecure or exfil URLs, inline
 *     secrets), plus an optional live check that connects, lists the tools,
 *     scans their descriptions, and compares them with the rug-pull baseline.
 *
 * SAFETY: the live check starts server processes. It only does that for
 * servers the user configured themselves (user/local scope) or explicitly
 * approved for this project. Project `.mcp.json` servers that Claude Code
 * would still ask about are checked statically only, so opening a
 * malicious repository never runs its servers through Mund.
 */

import { createHash } from 'crypto';
import { existsSync, readFileSync, readdirSync, statSync } from 'fs';
import { mkdir, writeFile } from 'fs/promises';
import { homedir } from 'os';
import { dirname, join, resolve } from 'path';
import type { SecurityIssue, Severity } from './types.js';
import { DEFAULT_RULES, DANGEROUS_URL_PATTERNS } from './constants.js';
import { AnalyzerEngine } from './analyzers/index.js';
import { SecretScanner } from './analyzers/secret-scanner.js';
import { McpServerAnalyzer, type McpServerManifest } from './analyzers/mcp-server-analyzer.js';
import { computeRiskScore, type RiskScore } from './scoring.js';
import { BaselineStore, checkRugPull, changesToIssues, type RugPullResult } from './rugpull.js';
import { getVersion } from './version.js';

export type Verdict = 'allow' | 'warn' | 'block';

/** Which agent harness's config layout to audit. */
export type Harness = 'claude' | 'antigravity';

export interface SkillAudit {
  name: string;
  path: string;
  scope: 'project' | 'user' | 'workspace' | 'global' | 'plugin';
  verdict: Verdict;
  risk: RiskScore;
  issues: SecurityIssue[];
}

export interface McpServerConfig {
  type?: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  /** Antigravity spelling of url */
  serverUrl?: string;
  headers?: Record<string, string>;
  disabled?: boolean;
}

export interface McpServerAudit {
  name: string;
  scope: 'project' | 'local' | 'user' | 'desktop' | 'workspace' | 'global';
  transport: 'stdio' | 'http' | 'sse' | 'unknown';
  target: string;
  verdict: Verdict;
  risk: RiskScore;
  issues: SecurityIssue[];
  live: { status: 'ok' | 'error' | 'skipped'; reason?: string; tools?: number; rugpull?: RugPullResult['status'] };
}

export interface AgentAuditReport {
  version: 1;
  tool: { name: 'mund'; version: string };
  generatedAt: string;
  cwd: string;
  servers: McpServerAudit[];
  skills: SkillAudit[];
  summary: Record<Verdict, number>;
}

// mcp_rugpull is deliberately absent: a plain change (reworded description,
// new optional parameter) warns until accepted; only escalated changes
// (now malicious-looking or newly executing commands) are critical → block.
const BLOCK_TYPES = new Set(['injection', 'exfiltration', 'hidden_unicode']);
const MAX_FILE = 512 * 1024;

/**
 * critical → block; high in a blocking category (injection, exfiltration,
 * hidden Unicode) → block; other high/medium → warn; else allow.
 */
export function verdictFor(issues: Array<Pick<SecurityIssue, 'severity' | 'type'>>): Verdict {
  let verdict: Verdict = 'allow';
  for (const i of issues) {
    if (i.severity === 'critical' || (i.severity === 'high' && BLOCK_TYPES.has(i.type))) return 'block';
    if (i.severity === 'high' || i.severity === 'medium') verdict = 'warn';
  }
  return verdict;
}

// ============================================================================
// Skills
// ============================================================================

const engine = new AnalyzerEngine();

/** Invisible characters used to hide instructions from human reviewers. */
const HIDDEN_CHARS: Array<{ re: RegExp; name: string; severity: Severity }> = [
  { re: /[\u{E0000}-\u{E007F}]/u, name: 'Unicode tag characters (invisible ASCII smuggling)', severity: 'critical' },
  { re: /[‪-‮⁦-⁩]/, name: 'bidirectional override characters', severity: 'high' },
  { re: /[​-‍⁠﻿]{3,}/, name: 'runs of zero-width characters', severity: 'high' },
];

function hiddenUnicode(content: string): SecurityIssue[] {
  const issues: SecurityIssue[] = [];
  for (const h of HIDDEN_CHARS) {
    const m = h.re.exec(content);
    if (!m) continue;
    const before = content.slice(0, m.index).split('\n');
    issues.push({
      rule_id: 'hidden_unicode',
      rule_name: `Hidden text: ${h.name}`,
      type: 'hidden_unicode',
      severity: h.severity,
      action: 'block',
      match: `U+${m[0].codePointAt(0)!.toString(16).toUpperCase()}`,
      location: { start: m.index, end: m.index + m[0].length, line: before.length, column: before[before.length - 1].length + 1 },
      suggestion: 'Text that is invisible to reviewers but readable by the model. Remove it or reject this skill.',
    });
  }
  return issues;
}

/** Scan one piece of skill content (a SKILL.md or a file shipped with the skill). */
export async function scanSkillContent(content: string): Promise<SecurityIssue[]> {
  return [...hiddenUnicode(content), ...(await engine.analyzeAll(content, DEFAULT_RULES))];
}

function textFiles(dir: string, out: string[] = [], depth = 0): string[] {
  if (depth > 4) return out;
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name === '.git') continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) textFiles(p, out, depth + 1);
    else if (e.isFile() && statSync(p).size <= MAX_FILE) out.push(p);
  }
  return out;
}

export async function scanSkillDir(dir: string, scope: SkillAudit['scope'] = 'project'): Promise<SkillAudit> {
  const issues: SecurityIssue[] = [];
  for (const file of textFiles(dir)) {
    const buf = readFileSync(file);
    if (buf.subarray(0, 4096).includes(0)) continue; // binary
    for (const issue of await scanSkillContent(buf.toString('utf8'))) {
      issues.push({ ...issue, rule_name: `${issue.rule_name} (${file.slice(dir.length + 1)})` });
    }
  }
  return { name: dir.split(/[\\/]/).pop()!, path: dir, scope, verdict: verdictFor(issues), risk: computeRiskScore(issues), issues };
}

export function skillRoots(cwd: string, home = homedir(), harness: Harness = 'claude'): Array<[string, SkillAudit['scope']]> {
  if (harness === 'antigravity') {
    const roots: Array<[string, SkillAudit['scope']]> = [
      [join(cwd, '.agents', 'skills'), 'workspace'],
      [join(cwd, '.agent', 'skills'), 'workspace'],
      [join(home, '.gemini', 'config', 'skills'), 'global'],
      [join(home, '.gemini', 'antigravity-cli', 'skills'), 'global'],
      [join(home, '.gemini', 'antigravity', 'skills'), 'global'],
    ];
    const plugins = join(home, '.gemini', 'antigravity-cli', 'plugins');
    if (existsSync(plugins)) {
      for (const p of readdirSync(plugins, { withFileTypes: true })) if (p.isDirectory()) roots.push([join(plugins, p.name, 'skills'), 'plugin']);
    }
    return roots;
  }
  return [[join(cwd, '.claude', 'skills'), 'project'], [join(home, '.claude', 'skills'), 'user']];
}

export function discoverSkillDirs(cwd: string, home = homedir(), harness: Harness = 'claude'): Array<{ dir: string; scope: SkillAudit['scope'] }> {
  const roots = skillRoots(cwd, home, harness);
  const out: Array<{ dir: string; scope: SkillAudit['scope'] }> = [];
  for (const [root, scope] of roots) {
    if (!existsSync(root)) continue;
    for (const e of readdirSync(root, { withFileTypes: true })) {
      if (e.isDirectory() && existsSync(join(root, e.name, 'SKILL.md'))) out.push({ dir: join(root, e.name), scope });
    }
  }
  return out;
}

// ============================================================================
// MCP servers
// ============================================================================

interface DiscoveredServer {
  name: string;
  scope: McpServerAudit['scope'];
  config: McpServerConfig;
  /** Started by the user's own configuration or explicitly approved; safe to start for a live check. */
  approved: boolean;
}

function readJson(path: string): Record<string, any> | null {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return null;
  }
}

/** Claude Desktop's config, which also supplies MCP servers to its Code tab. */
export function claudeDesktopConfigPath(home = homedir()): string {
  if (process.platform === 'win32') return join(process.env.APPDATA ?? join(home, 'AppData', 'Roaming'), 'Claude', 'claude_desktop_config.json');
  if (process.platform === 'darwin') return join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
  return join(home, '.config', 'Claude', 'claude_desktop_config.json');
}

/**
 * Claude Code MCP config: <cwd>/.mcp.json (project), ~/.claude.json (user +
 * per-project local), and Claude Desktop's claude_desktop_config.json.
 */
export function discoverMcpServers(cwd: string, home = homedir()): DiscoveredServer[] {
  const out: DiscoveredServer[] = [];
  const claudeJson = readJson(join(home, '.claude.json')) ?? {};
  const projectEntry = claudeJson.projects?.[cwd] ?? {};
  const settings = [join(cwd, '.claude', 'settings.json'), join(cwd, '.claude', 'settings.local.json'), join(home, '.claude', 'settings.json')]
    .map(readJson)
    .filter(Boolean) as Array<Record<string, any>>;
  const enableAll = settings.some((s) => s.enableAllProjectMcpServers === true) || projectEntry.enableAllProjectMcpServers === true;
  const enabled = new Set<string>([
    ...(projectEntry.enabledMcpjsonServers ?? []),
    ...settings.flatMap((s) => s.enabledMcpjsonServers ?? []),
  ]);
  const disabled = new Set<string>([...(projectEntry.disabledMcpjsonServers ?? []), ...settings.flatMap((s) => s.disabledMcpjsonServers ?? [])]);

  for (const [name, config] of Object.entries<McpServerConfig>(readJson(join(cwd, '.mcp.json'))?.mcpServers ?? {})) {
    out.push({ name, scope: 'project', config, approved: !disabled.has(name) && (enableAll || enabled.has(name)) });
  }
  for (const [name, config] of Object.entries<McpServerConfig>(projectEntry.mcpServers ?? {})) {
    out.push({ name, scope: 'local', config, approved: true });
  }
  for (const [name, config] of Object.entries<McpServerConfig>(claudeJson.mcpServers ?? {})) {
    out.push({ name, scope: 'user', config, approved: true });
  }
  const seen = new Set(out.map((s) => s.name));
  for (const [name, config] of Object.entries<McpServerConfig>(readJson(claudeDesktopConfigPath(home))?.mcpServers ?? {})) {
    if (!seen.has(name)) out.push({ name, scope: 'desktop', config, approved: true });
  }
  return out;
}

/**
 * Antigravity MCP config: <workspace>/.agents/mcp_config.json and
 * ~/.gemini/config/mcp_config.json. Workspace servers are checked
 * statically only (same consent rule as Claude Code project servers);
 * servers marked "disabled" are never started.
 */
export function discoverAntigravityMcpServers(cwd: string, home = homedir()): DiscoveredServer[] {
  const out: DiscoveredServer[] = [];
  const add = (path: string, scope: McpServerAudit['scope'], approved: boolean) => {
    for (const [name, raw] of Object.entries<McpServerConfig>(readJson(path)?.mcpServers ?? {})) {
      const config = { ...raw, url: raw.url ?? raw.serverUrl };
      out.push({ name, scope, config, approved: approved && !raw.disabled });
    }
  };
  add(join(cwd, '.agents', 'mcp_config.json'), 'workspace', false);
  add(join(home, '.gemini', 'config', 'mcp_config.json'), 'global', true);
  return out;
}

/** Expand ${VAR} and ${VAR:-default} the way Claude Code does in .mcp.json. */
function expand(value: string, env: NodeJS.ProcessEnv = process.env): string {
  return value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}/g, (_, k, d) => env[k] ?? d ?? '');
}

const PACKAGE_RUNNERS = new Set(['npx', 'bunx', 'uvx', 'pipx', 'pnpx']);
const OFFICIAL_SCOPE = 'modelcontextprotocol';

function lev(a: string, b: string): number {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return d[a.length][b.length];
}

/** The package a launcher like `npx -y pkg@1.2.3` runs, if any. */
export function launchedPackage(config: McpServerConfig): { name: string; version?: string } | null {
  const cmd = (config.command ?? '').split(/[\\/]/).pop() ?? '';
  let args = config.args ?? [];
  if (cmd === 'pnpm' || cmd === 'yarn') args = args[0] === 'dlx' ? args.slice(1) : [];
  else if (cmd === 'pipx') args = args[0] === 'run' ? args.slice(1) : [];
  else if (!PACKAGE_RUNNERS.has(cmd)) return null;
  const spec = args.find((a) => !a.startsWith('-'));
  if (!spec) return null;
  const at = spec.lastIndexOf('@');
  return at > 0 ? { name: spec.slice(0, at), version: spec.slice(at + 1) } : { name: spec };
}

const finding = (rule_id: string, rule_name: string, severity: Severity, type: string, match: string, suggestion: string): SecurityIssue => ({
  rule_id, rule_name, severity, type, action: severity === 'critical' ? 'block' : 'alert', match, suggestion,
});

/** Static checks on how a server is launched. No processes are started. */
export async function checkMcpServerConfig(name: string, config: McpServerConfig): Promise<SecurityIssue[]> {
  const issues: SecurityIssue[] = [];

  // Inline secrets in args, env, headers or URL
  const secrets = await new SecretScanner().analyze(
    [...(config.args ?? []), ...Object.values(config.env ?? {}), ...Object.values(config.headers ?? {}), config.url ?? ''].filter((v) => !/^\$\{[^}]+\}$/.test(v)).join('\n'),
    DEFAULT_RULES,
  );
  for (const s of secrets) {
    issues.push(finding('mcp_config_inline_secret', `Secret written into MCP config: ${s.rule_name}`, 'high', 'secret', s.match,
      'Reference it as ${ENV_VAR} instead; config files get committed and shared.'));
  }

  // Package typosquats and unpinned packages
  const pkg = launchedPackage(config);
  if (pkg) {
    const scope = pkg.name.startsWith('@') ? pkg.name.slice(1).split('/')[0] : null;
    if (scope && scope !== OFFICIAL_SCOPE && lev(scope, OFFICIAL_SCOPE) <= 3) {
      issues.push(finding('mcp_package_scope_typosquat', `Package scope "@${scope}" imitates the official "@${OFFICIAL_SCOPE}"`, 'critical', 'supply_chain', pkg.name,
        'Do not run this server. Check the package name character by character.'));
    }
    const short = pkg.name.split('/').pop()!.replace(/^(mcp-server-|server-|mcp-)|(-mcp-server|-mcp|-server)$/g, '');
    for (const t of new McpServerAnalyzer().checkTyposquatting({ name: short, version: '0' } as McpServerManifest)) {
      issues.push({ ...t, type: 'supply_chain', rule_name: `${t.rule_name} (package ${pkg.name})` });
    }
    if (!pkg.version || pkg.version === 'latest') {
      issues.push(finding('mcp_unpinned_package', `Package ${pkg.name} is not pinned to a version`, 'low', 'supply_chain', pkg.name,
        `Pin it (e.g. ${pkg.name}@1.2.3) so an upstream update can't change the server under you.`));
    }
  }

  // Remote URL checks
  if (config.url) {
    const url = expand(config.url);
    for (const p of DANGEROUS_URL_PATTERNS) {
      if (p.test(url)) issues.push(finding('mcp_dangerous_url', 'MCP server URL points at a data-collection service', 'critical', 'exfiltration', url, 'Remove this server.'));
    }
    try {
      const u = new URL(url);
      const local = ['localhost', '127.0.0.1', '::1', '[::1]'].includes(u.hostname);
      if (u.protocol === 'http:' && !local) {
        issues.push(finding('mcp_insecure_transport', 'Remote MCP server over plain HTTP', 'medium', 'transport', url, 'Use https:// so tool traffic and tokens are encrypted.'));
      }
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(u.hostname) && !local) {
        issues.push(finding('mcp_ip_url', 'Remote MCP server addressed by raw IP', 'medium', 'transport', url, 'Prefer a named, TLS-verified host.'));
      }
    } catch {
      issues.push(finding('mcp_bad_url', 'MCP server URL does not parse', 'medium', 'transport', url, 'Fix the URL.'));
    }
  }

  // Dangerous launch commands (e.g. sh -c "curl … | bash")
  const launch = [config.command ?? '', ...(config.args ?? [])].join(' ');
  for (const i of await engine.analyzeAll(launch, DEFAULT_RULES.filter((r) => r.type === 'code_pattern'))) {
    issues.push({ ...i, rule_name: `Launch command: ${i.rule_name}` });
  }

  void name;
  return issues;
}

/** Connect to a server, list its tools, and return them as a manifest. */
export async function fetchLiveManifest(name: string, config: McpServerConfig, timeoutMs = 8000): Promise<McpServerManifest> {
  const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
  const client = new Client({ name: 'mund-agent-audit', version: getVersion() });
  let transport: any;
  if (config.url) {
    if (config.type === 'sse') throw new Error('SSE transport not checked live (deprecated); static checks only');
    const { StreamableHTTPClientTransport } = await import('@modelcontextprotocol/sdk/client/streamableHttp.js');
    const headers = Object.fromEntries(Object.entries(config.headers ?? {}).map(([k, v]) => [k, expand(v)]));
    transport = new StreamableHTTPClientTransport(new URL(expand(config.url)), { requestInit: { headers } });
  } else if (config.command) {
    const { StdioClientTransport } = await import('@modelcontextprotocol/sdk/client/stdio.js');
    transport = new StdioClientTransport({
      command: expand(config.command),
      args: (config.args ?? []).map((a) => expand(a)),
      env: { ...(process.env as Record<string, string>), ...Object.fromEntries(Object.entries(config.env ?? {}).map(([k, v]) => [k, expand(v)])) },
      stderr: 'ignore',
    });
  } else {
    throw new Error('no command or url');
  }

  const timeout = new Promise<never>((_, rej) => setTimeout(() => rej(new Error(`timed out after ${timeoutMs}ms`)), timeoutMs).unref());
  try {
    await Promise.race([client.connect(transport), timeout]);
    const tools: McpServerManifest['tools'] = [];
    let cursor: string | undefined;
    do {
      const page: any = await Promise.race([client.listTools(cursor ? { cursor } : undefined), timeout]);
      for (const t of page.tools) tools.push({ name: t.name, description: t.description, inputSchema: t.inputSchema });
      cursor = page.nextCursor;
    } while (cursor && tools.length < 2000);
    const info = client.getServerVersion();
    return { name: info?.name ?? name, version: info?.version ?? '0', tools };
  } finally {
    await client.close().catch(() => {});
  }
}

/**
 * Live manifest findings, calibrated for a pre-install verdict:
 *  - typosquat rules are dropped: a server's self-reported name proves
 *    nothing, and the launch package is already checked statically;
 *  - capability findings ("can run commands", "touches files", many tools)
 *    describe what a server does, not that it's malicious, so they're kept
 *    as info. A server that newly GAINS execution is still escalated by
 *    rug-pull detection.
 */
const DROP_LIVE = new Set(['mcp_typosquatting', 'mcp_typosquatting_pattern', 'mcp_missing_version']);
const DESCRIPTIVE_LIVE = /^mcp_capability_|^mcp_execution_warning$|^mcp_excessive_tools$/;
export function calibrateLiveFindings(issues: SecurityIssue[]): SecurityIssue[] {
  return issues
    .filter((i) => !DROP_LIVE.has(i.rule_id))
    .map((i) => (DESCRIPTIVE_LIVE.test(i.rule_id) ? { ...i, severity: 'info' as Severity, action: 'log' as const } : i));
}

export async function auditMcpServer(
  server: DiscoveredServer,
  opts: { live?: boolean; store?: BaselineStore; timeoutMs?: number; accept?: string[]; harness?: Harness } = {},
): Promise<McpServerAudit> {
  const { name, scope, config } = server;
  const issues = await checkMcpServerConfig(name, config);
  const transport: McpServerAudit['transport'] = config.url ? (config.type === 'sse' ? 'sse' : 'http') : config.command ? 'stdio' : 'unknown';
  let live: McpServerAudit['live'] = { status: 'skipped', reason: 'live checks disabled' };

  // Never launch a server the static checks already distrust: a typosquat
  // package or an exfil URL must not be started "to have a look".
  const distrusted = verdictFor(issues) === 'block' ||
    issues.some((i) => (i.severity === 'critical' || i.severity === 'high') && (i.type === 'supply_chain' || i.type === 'exfiltration'));

  if (opts.live) {
    if (!server.approved) {
      live = { status: 'skipped', reason: server.config.disabled ? 'server is disabled in config' : 'workspace/project server not approved for automatic start; static checks only' };
    } else if (distrusted) {
      live = { status: 'skipped', reason: 'not started: static checks already flag its package or URL' };
    } else {
      try {
        const manifest = await fetchLiveManifest(name, config, opts.timeoutMs);
        issues.push(...calibrateLiveFindings(await new McpServerAnalyzer().analyze(JSON.stringify(manifest), [])));
        const accept = !!opts.accept?.some((a) => a === 'all' || a === name);
        const rug = await checkRugPull(`${opts.harness ?? 'claude'}:${scope}:${name}`, manifest, { store: opts.store, acceptChanges: accept });
        issues.push(...changesToIssues(rug));
        live = { status: 'ok', tools: manifest.tools?.length ?? 0, rugpull: rug.status };
      } catch (err) {
        live = { status: 'error', reason: (err as Error).message };
      }
    }
  }

  return {
    name,
    scope,
    transport,
    target: config.url ?? [config.command, ...(config.args ?? [])].filter(Boolean).join(' '),
    verdict: verdictFor(issues),
    risk: computeRiskScore(issues),
    issues,
    live,
  };
}

// ============================================================================
// Full audit + cache
// ============================================================================

/** Cache key: sha256(resolved cwd), plus the harness for non-Claude layouts. */
export function auditCachePath(cwd: string, harness: Harness = 'claude'): string {
  const base = process.env.MUND_AUDIT_CACHE_DIR || join(process.env.XDG_CACHE_HOME || join(homedir(), '.cache'), 'mund', 'agent-audit');
  const key = createHash('sha256').update(resolve(cwd)).digest('hex').slice(0, 16);
  return join(base, harness === 'claude' ? `${key}.json` : `${key}.${harness}.json`);
}

export async function runAgentAudit(opts: { cwd?: string; live?: boolean; home?: string; store?: BaselineStore; timeoutMs?: number; writeCache?: boolean; accept?: string[]; harness?: Harness } = {}): Promise<AgentAuditReport> {
  const cwd = resolve(opts.cwd ?? process.cwd());
  const home = opts.home ?? homedir();
  const [servers, skills] = await Promise.all([
    Promise.all((opts.harness === 'antigravity' ? discoverAntigravityMcpServers(cwd, home) : discoverMcpServers(cwd, home)).map((s) => auditMcpServer(s, opts))),
    Promise.all(discoverSkillDirs(cwd, home, opts.harness).map(({ dir, scope }) => scanSkillDir(dir, scope))),
  ]);
  const summary: Record<Verdict, number> = { allow: 0, warn: 0, block: 0 };
  for (const x of [...servers, ...skills]) summary[x.verdict]++;
  const report: AgentAuditReport = { version: 1, tool: { name: 'mund', version: getVersion() }, generatedAt: new Date().toISOString(), cwd, servers, skills, summary };

  if (opts.writeCache !== false) {
    const path = auditCachePath(cwd, opts.harness);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, JSON.stringify(report, null, 2));
  }
  return report;
}
