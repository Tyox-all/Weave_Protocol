/**
 * Tool-call evaluation shared by every harness adapter.
 *
 * An adapter hands over a tool name and its arguments; this decides allow,
 * deny or require_approval by checking the capability, every path and URL
 * argument (not just one well-known field), and every URL and path in a
 * shell command. Before Ward 0.2.0 each adapter carried its own copy of this
 * logic, and all of them checked only one field per tool and the first URL
 * of a shell command (WARD-2026-001).
 *
 * No Node built-ins: Ward also runs in browsers.
 */

import type { FilesystemOp, HttpMethod, WardPolicy } from "../types.js";
import {
  checkCapability,
  checkFilesystem,
  checkNetwork,
  normalizePath,
  type CheckResult,
  type Decision,
} from "./index.js";
import { checkOutboundData, destinationsOf, type DataClassifier } from "./egress.js";
import { detectPayment, explicitlyAllowed, type PaymentCall } from "./limits.js";

/** How a harness's tool maps onto WARD concepts. */
export interface ToolMapping {
  /** WARD capability name (e.g. "shell_exec", "file_write") */
  capability: string;
  /** Argument holding the main path, checked with fsOp */
  pathField?: string;
  fsOp?: FilesystemOp;
  /** Argument holding the main URL */
  urlField?: string;
  /** Argument holding a shell command */
  commandField?: string;
}

export interface ToolCallCheck extends CheckResult {
  type: "capability" | "filesystem" | "network" | "command" | "egress" | "payment" | "limits";
  /** The argument or command token this check covered */
  subject?: string;
}

export interface ToolCallEvaluation {
  decision: Decision;
  /** Reasons for every non-allow check, strictest first */
  reasons: string[];
  checks: ToolCallCheck[];
  /** Set when the call moves money (0.3.6) */
  payment?: PaymentCall;
  /** Hosts the call contacts (0.3.6) */
  hosts?: string[];
}

export interface EvaluateOptions {
  /** Harness-specific mappings, keyed by tool name */
  mappings?: Record<string, ToolMapping>;
  /** Working directory used to resolve relative paths */
  cwd?: string;
  /** Extra data classifier for outbound payloads (e.g. Mund), added to Ward's built-in one */
  classify?: DataClassifier;
}

/**
 * Decide a tool call. The strictest check wins: deny over require_approval
 * over allow.
 */
export function evaluateToolCall(
  policy: WardPolicy,
  toolName: string,
  args: Record<string, unknown> | undefined,
  opts: EvaluateOptions = {},
): ToolCallEvaluation {
  const mapping: ToolMapping = opts.mappings?.[toolName] ?? { capability: toolName };
  const checks: ToolCallCheck[] = [];
  const input = args && typeof args === "object" ? args : {};

  // 1. Capability: the mapped name or the raw tool name; an explicit rule
  //    for either beats a policy default.
  checks.push({ type: "capability", ...mergeCapability(checkCapability(policy, mapping.capability), checkCapability(policy, toolName)) });

  // 2. Every path argument
  const defaultOp = mapping.fsOp ?? inferFsOp(`${mapping.capability} ${toolName}`);
  for (const { key, value } of pathArgs(input, mapping)) {
    const op: FilesystemOp =
      key === mapping.pathField ? defaultOp : DEST_KEY.test(key) ? "write" : SOURCE_KEY.test(key) ? "read" : defaultOp;
    const path = resolvePath(value, opts.cwd);
    checks.push({ type: "filesystem", subject: `${key}=${value}`, ...checkFilesystem(policy, op, path) });
    const guard = selfProtect(policy, op, path);
    if (guard) checks.push({ type: "filesystem", subject: `${key}=${value}`, ...guard });
  }

  // 3. Every URL argument
  const method = String(input.method ?? "GET").toUpperCase() as HttpMethod;
  for (const { key, value } of urlArgs(input, mapping)) {
    checks.push({ type: "network", subject: `${key}=${value}`, ...checkNetwork(policy, value, method) });
  }

  // 4. Shell commands: every URL and path token
  for (const command of commandArgs(input, mapping)) {
    checks.push(...scanCommand(policy, command, opts.cwd));
  }

  // 5. What the call sends: secrets and personal data in URLs, bodies,
  //    messages and network commands, against WARD.md's Data Boundaries
  checks.push(...checkOutboundData(policy, toolName, input, {
    cwd: opts.cwd, classify: opts.classify, commandField: mapping.commandField, urlField: mapping.urlField,
  }));

  // 6. Payments: moving money needs a person unless WARD.md allows this
  //    capability by name (a default allow or a wildcard doesn't count)
  const command = commandArgs(input, mapping).join("\n") || undefined;
  const payment = detectPayment(toolName, mapping.capability, input, command) ?? undefined;
  // A payment CLI inside a shell command isn't lifted by allowing shell_exec
  const lifted = payment && (payment.viaCommand ? explicitlyAllowed(policy, "payments") : explicitlyAllowed(policy, "payments", toolName, mapping.capability));
  if (payment && !lifted) {
    checks.push({
      type: "payment",
      subject: payment.stated ? `${toolName} ${payment.stated}` : toolName,
      decision: "require_approval",
      severity: "critical",
      reason: `Moving money requires human approval (Ward payment guard; allow ${payment.viaCommand ? "'payments'" : `'${mapping.capability}' or 'payments'`} by name in WARD.md Capabilities to lift this)`,
    });
  }

  const hosts = destinationsOf(toolName, input, mapping.commandField, mapping.urlField);
  return { ...aggregate(checks), ...(payment ? { payment } : {}), ...(hosts.length ? { hosts } : {}) };
}

// ─────────────────────────────────────────────────────────
// Argument discovery
// ─────────────────────────────────────────────────────────

/** snake_case a key so "outputPath", "output-path" and "output_path" match alike. */
const snake = (key: string) => key.replace(/([a-z0-9])([A-Z])/g, "$1_$2").replace(/-/g, "_").toLowerCase();

const PATH_KEY = /(^|_)(path|paths|file|files|filepath|filename|dir|dirs|directory|dest|destination|src|source|target|output|out)$/;
const URL_KEY = /(^|_)(url|urls|uri|uris|endpoint|href|link)$/;
const COMMAND_KEY = /^(command|cmd|script|shell)$/;
const DEST_KEY = /(^|_)(dest|destination|target|output|out)$/;
const SOURCE_KEY = /(^|_)(src|source)$/;

const looksLikeUrl = (v: string) => /^[a-z][a-z0-9+.-]*:\/\//i.test(v);

function strings(v: unknown): string[] {
  if (typeof v === "string") return [v];
  if (Array.isArray(v)) return v.filter((x): x is string => typeof x === "string");
  return [];
}

function* entries(input: Record<string, unknown>, test: (key: string) => boolean, extra?: string) {
  for (const [key, raw] of Object.entries(input)) {
    if (key !== extra && !test(snake(key))) continue;
    for (const value of strings(raw)) yield { key, value };
  }
}

function pathArgs(input: Record<string, unknown>, m: ToolMapping) {
  return [...entries(input, (k) => PATH_KEY.test(k), m.pathField)].filter((e) => e.value !== "" && !looksLikeUrl(e.value));
}

function urlArgs(input: Record<string, unknown>, m: ToolMapping) {
  const urls = [...entries(input, (k) => URL_KEY.test(k), m.urlField)].filter((e) => e.value !== "");
  // A URL passed in a path-named argument is still a network call
  const fromPaths = [...entries(input, (k) => PATH_KEY.test(k), m.pathField)].filter((e) => looksLikeUrl(e.value));
  return [...urls, ...fromPaths];
}

function commandArgs(input: Record<string, unknown>, m: ToolMapping): string[] {
  return [...entries(input, (k) => COMMAND_KEY.test(k), m.commandField)].map((e) => e.value);
}

// ─────────────────────────────────────────────────────────
// Shell command scanning (best effort; gate shell_exec itself for a hard line)
// ─────────────────────────────────────────────────────────

const URL_IN_TEXT = /[a-z][a-z0-9+.-]*:\/\/[^\s'"`<>|;&()]+/gi;
// Path-like tokens: absolute, home, ./ or ../, or a relative path containing "/"
const PATH_TOKEN = /(?<=^|[\s'"`=<>|;&(])(~(?=\/)|\.{1,2}(?=\/)|\/|[\w.@-]+\/)[^\s'"`<>|;&()]*/g;
const REDIRECT = /(?:>>?|\btee(?:\s+-a)?)\s*(['"]?)([^\s'"`<>|;&()]+)\1/g;

function scanCommand(policy: WardPolicy, command: string, cwd?: string): ToolCallCheck[] {
  const checks: ToolCallCheck[] = [];

  const urls = command.match(URL_IN_TEXT) ?? [];
  for (const url of urls) {
    checks.push({ type: "command", subject: url, ...checkNetwork(policy, url.replace(/[.,]+$/, ""), "GET") });
  }

  const withoutUrls = command.replace(URL_IN_TEXT, " ");
  const writes = new Set([...withoutUrls.matchAll(REDIRECT)].map((m) => m[2]));
  const deletes = /(?:^|[\s;|&(])(rm|rmdir|unlink|shred)\s/.test(withoutUrls);
  const copies = /(?:^|[\s;|&(])(cp|mv|install|rsync|ln)\s/.test(withoutUrls) || /\bsed\s+-i/.test(withoutUrls);
  // Bare names like "WARD.md" or "opencode.json" have no "/", so add any word
  // that names a protected file, and every redirect target.
  const bare = (withoutUrls.match(/[^\s'"`<>|;&()]+/g) ?? []).filter((w) => protectedConfig(resolvePath(w, cwd)));
  const pathTokens = withoutUrls.match(PATH_TOKEN) ?? [];
  const tokens = [...new Set([...pathTokens, ...writes, ...bare])];
  const last = pathTokens[pathTokens.length - 1] ?? bare[bare.length - 1];

  for (const token of tokens) {
    const ops = new Set<FilesystemOp>(["read"]);
    if (writes.has(token) || (copies && token === last)) ops.add("write");
    if (deletes) ops.add("delete");
    const explicitPath = token.startsWith("/") || token.startsWith("~");
    const path = resolvePath(token, cwd);
    for (const op of ops) {
      const guard = selfProtect(policy, op, path);
      if (guard) checks.push({ type: "command", subject: `${op} ${token}`, ...guard });
      const result = checkFilesystem(policy, op, path);
      // Relative tokens are often not paths at all (a commit message, a
      // regex), so they only trip explicit rules, not the policy default.
      if (!explicitPath && !result.matchedRule) continue;
      checks.push({ type: "command", subject: `${op} ${token}`, ...result });
    }
  }
  return checks;
}

// ─────────────────────────────────────────────────────────
// Self-protection (Ward 0.3.3)
// ─────────────────────────────────────────────────────────

/**
 * Files that change what an agent may do or that run code on their own: the
 * WARD policy itself, harness hook and settings files, MCP server lists and
 * git hooks. An agent that can rewrite them can turn its own guardrails off
 * or plant a command that runs later (Cursor CVE-2025-54135 "CurXecute",
 * where injected content rewrote mcp.json). Writing or deleting one needs
 * human approval even when a broad rule like `write: /repo/**` covers it.
 */
const PROTECTED: { label: string; test: RegExp }[] = [
  { label: "the WARD policy", test: /(^|\/)ward\.md$/i },
  { label: "Claude Code settings", test: /(^|\/)\.claude\/settings(\.local)?\.json$/ },
  { label: "Cursor hooks", test: /(^|\/)\.cursor\/hooks\.json$/ },
  { label: "Codex config", test: /(^|\/)\.codex\/(hooks\.json|config\.toml)$/ },
  { label: "Gemini settings", test: /(^|\/)\.gemini\/(settings\.json|config\/hooks\.json)$/ },
  { label: "OpenCode config", test: /(^|\/)(opencode\.jsonc?|\.opencode\/plugins?\/.*)$/ },
  { label: "an MCP server list", test: /(^|\/)(\.?mcp\.json|claude_desktop_config\.json)$/ },
  { label: "a git hook", test: /(^|\/)\.git\/hooks\/.+/ },
];

/** Which protected file a path is, if any. */
export function protectedConfig(path: string): string | undefined {
  const normalized = normalizePath(path);
  return PROTECTED.find((p) => p.test.test(normalized))?.label;
}

/**
 * An approval check for a write or delete of a protected file. A WARD allow
 * rule naming the exact file (no wildcard) lifts it.
 */
function selfProtect(policy: WardPolicy, op: FilesystemOp, path: string): CheckResult | undefined {
  if (op !== "write" && op !== "delete") return undefined;
  const label = protectedConfig(path);
  if (!label) return undefined;
  const target = normalizePath(path);
  const named = (policy.filesystem?.allow ?? []).some((r) => r.op === op && normalizePath(r.path) === target);
  if (named) return undefined;
  return {
    decision: "require_approval",
    reason: `Changing ${label} requires human approval (Ward self-protection; allow the exact file in WARD.md to lift this)`,
    severity: "high",
  };
}

// ─────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────

function resolvePath(path: string, cwd?: string): string {
  if (!cwd || path.startsWith("/") || path.startsWith("~")) return path;
  return `${cwd.replace(/\/+$/, "")}/${path}`;
}

/** Infer the filesystem op from words in the capability and tool name. */
function inferFsOp(name: string): FilesystemOp {
  const words = new Set(snake(name).split(/[^a-z0-9]+/));
  const has = (...w: string[]) => w.some((x) => words.has(x));
  if (has("delete", "remove", "rm", "unlink", "rmdir")) return "delete";
  if (has("write", "create", "save", "edit", "append", "put", "upload", "move", "mv", "copy", "cp", "rename")) return "write";
  if (has("execute", "exec", "run", "spawn")) return "execute";
  if (has("list", "ls", "readdir", "glob")) return "list";
  return "read";
}

function isExplicit(r: CheckResult): boolean {
  return /is in the allow list|is in the deny list|requires human approval/.test(r.reason);
}

/** Explicit rules beat defaults; otherwise the stricter result wins. */
function mergeCapability(a: CheckResult, b: CheckResult): CheckResult {
  if (isExplicit(a) !== isExplicit(b)) return isExplicit(a) ? a : b;
  return RANK[b.decision] > RANK[a.decision] ? b : a;
}

const RANK: Record<Decision, number> = { allow: 0, require_approval: 1, deny: 2 };

/** Combine checks: the strictest decision wins; reasons strictest first. */
export function aggregate(checks: ToolCallCheck[]): ToolCallEvaluation {
  let decision: Decision = "allow";
  for (const c of checks) if (RANK[c.decision] > RANK[decision]) decision = c.decision;
  const reasons = checks
    .filter((c) => c.decision !== "allow")
    .sort((x, y) => RANK[y.decision] - RANK[x.decision])
    .map((c) => (c.subject && c.type !== "capability" ? `${c.reason} (${c.subject})` : c.reason));
  return { decision, reasons, checks };
}
