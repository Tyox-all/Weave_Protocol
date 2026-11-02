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
  type: "capability" | "filesystem" | "network" | "command";
  /** The argument or command token this check covered */
  subject?: string;
}

export interface ToolCallEvaluation {
  decision: Decision;
  /** Reasons for every non-allow check, strictest first */
  reasons: string[];
  checks: ToolCallCheck[];
}

export interface EvaluateOptions {
  /** Harness-specific mappings, keyed by tool name */
  mappings?: Record<string, ToolMapping>;
  /** Working directory used to resolve relative paths */
  cwd?: string;
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
    checks.push({ type: "filesystem", subject: `${key}=${value}`, ...checkFilesystem(policy, op, resolvePath(value, opts.cwd)) });
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

  return aggregate(checks);
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
  const tokens = [...new Set(withoutUrls.match(PATH_TOKEN) ?? [])];
  const last = tokens[tokens.length - 1];

  for (const token of tokens) {
    const ops = new Set<FilesystemOp>(["read"]);
    if (writes.has(token) || (copies && token === last)) ops.add("write");
    if (deletes) ops.add("delete");
    const explicitPath = token.startsWith("/") || token.startsWith("~");
    const path = resolvePath(token, cwd);
    for (const op of ops) {
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

function aggregate(checks: ToolCallCheck[]): ToolCallEvaluation {
  let decision: Decision = "allow";
  for (const c of checks) if (RANK[c.decision] > RANK[decision]) decision = c.decision;
  const reasons = checks
    .filter((c) => c.decision !== "allow")
    .sort((x, y) => RANK[y.decision] - RANK[x.decision])
    .map((c) => (c.subject && c.type !== "capability" ? `${c.reason} (${c.subject})` : c.reason));
  return { decision, reasons, checks };
}
