/**
 * Outbound data checks (Ward 0.3.5).
 *
 * The network check asks "may the agent talk to this host?". This asks "what
 * is it sending?". A secret sent to an allowed domain is still a leak (the
 * pattern behind Claude Code CVE-2026-54316, exfiltration through a
 * pre-approved domain). For every tool call that sends something (a URL, a
 * network command, a send/post/upload tool) the outgoing parts are classified
 * and checked against the WARD.md Data Boundaries section:
 *
 *   - a class in egressDeny, or missing from a non-empty egressAllow: deny;
 *   - a credential sent anywhere but its issuer: approval, by default;
 *   - secrets or personal data sent to a model API that WARD.md doesn't name
 *     in an explicit Network allow rule: approval (the model-endpoint guardrail).
 *
 * Only what can be seen is classified: literal values, plus, in shell
 * commands, references to secret variables and files. Unclassified data is
 * not assumed to be public. No Node built-ins: Ward also runs in browsers.
 */

import type { DataClassification, WardPolicy } from "../types.js";
import type { CheckResult } from "./index.js";

/** One piece of sensitive data found in an outbound payload. */
export interface DataFinding {
  /** WARD classifications this data falls under (a credential is also a secret) */
  classifications: DataClassification[];
  /** What was found, e.g. "OpenAI API key", "email address", "$AWS_SECRET_ACCESS_KEY" */
  kind: string;
  /** Hosts this credential legitimately goes to (its issuer) */
  issuers?: string[];
}

/** Extra classifier, e.g. Mund's scan(), run alongside the built-in one. */
export type DataClassifier = (text: string) => DataFinding[];

export interface OutboundOptions {
  /** Working directory (unused today; kept for parity with evaluateToolCall) */
  cwd?: string;
  /** Additional classifier whose findings are added to the built-in ones */
  classify?: DataClassifier;
}

export interface OutboundCheck extends CheckResult {
  type: "egress";
  subject: string;
}

// ─────────────────────────────────────────────────────────
// Classification
// ─────────────────────────────────────────────────────────

const CRED: DataClassification[] = ["credentials", "secret"];

const CREDENTIAL_PATTERNS: Array<{ kind: string; re: RegExp; issuers?: string[] }> = [
  { kind: "Anthropic API key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g, issuers: ["anthropic.com"] },
  { kind: "OpenAI API key", re: /\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/g, issuers: ["openai.com"] },
  { kind: "GitHub token", re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})/g, issuers: ["github.com", "githubusercontent.com"] },
  { kind: "AWS access key", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, issuers: ["amazonaws.com"] },
  { kind: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g, issuers: ["googleapis.com", "google.com"] },
  { kind: "Slack token", re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g, issuers: ["slack.com"] },
  { kind: "Stripe live key", re: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}/g, issuers: ["stripe.com"] },
  { kind: "npm token", re: /\bnpm_[A-Za-z0-9]{36}\b/g, issuers: ["npmjs.org", "npmjs.com"] },
  { kind: "private key", re: /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----/g },
  { kind: "JWT", re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
];

// password=..., "api_key": "...", client_secret: ...; placeholders don't count
const ASSIGNED_SECRET = /\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)["']?\s*[:=]\s*["']?([^\s"'&,;}]{8,})/gi;
const PLACEHOLDER = /^(?:\$|\{|<|%|\*+$|x{4,}|your|example|changeme|placeholder|redacted|\[)/i;

const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b(?!:)/g;
const SSN = /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g;
const CARD = /\b\d(?:[ -]?\d){12,18}\b/g;

function luhn(digits: string): boolean {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
  }
  return sum % 10 === 0;
}

/** Literal sensitive values in text: credentials, card numbers, emails, SSNs. */
export function classifyData(text: string): DataFinding[] {
  const out: DataFinding[] = [];
  for (const p of CREDENTIAL_PATTERNS) {
    if (new RegExp(p.re.source, p.re.flags).test(text)) out.push({ classifications: CRED, kind: p.kind, issuers: p.issuers });
  }
  for (const m of text.matchAll(ASSIGNED_SECRET)) {
    if (!PLACEHOLDER.test(m[1])) { out.push({ classifications: CRED, kind: "assigned secret" }); break; }
  }
  for (const m of text.matchAll(CARD)) {
    const digits = m[0].replace(/\D/g, "");
    if (digits.length >= 13 && !/^(\d)\1+$/.test(digits) && luhn(digits)) { out.push({ classifications: ["pci"], kind: "card number" }); break; }
  }
  if (SSN.test(text)) out.push({ classifications: ["pii"], kind: "US SSN" });
  SSN.lastIndex = 0;
  for (const m of text.matchAll(EMAIL)) {
    if (!/^(?:git|noreply|no-reply)@/i.test(m[0])) { out.push({ classifications: ["pii"], kind: "email address" }); break; }
  }
  return out;
}

// Secret references in shell commands: the forms an agent actually leaks with,
// since it rarely has the literal value in hand.
const SECRET_VAR = /\$\{?([A-Z][A-Z0-9_]*?(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?|AUTH)[A-Z0-9_]*)\}?/g;
const SECRET_FILE = /(?:^|[\s@<'"=(`:])((?:~\/|\.{1,2}\/|\/)?[\w./-]*?(?:\.env(?:\.[\w-]+)?|\.aws\/credentials|\.ssh\/id_\w+|\.netrc|\.npmrc|\.pypirc|\.pgpass|\.kube\/config|\.docker\/config\.json|\.git-credentials|credentials\.json|[\w-]+\.pem|[\w-]+\.p12|id_rsa|id_ed25519))(?=$|[\s'"`);|&>])/g;
const ENV_DUMP = /(?:^|[\s;|&(`$])(?:printenv|env|set)(?=\s*(?:$|[|;&)`]))/;

const VAR_ISSUERS: Array<[RegExp, string[]]> = [
  [/^ANTHROPIC/, ["anthropic.com"]],
  [/^OPENAI/, ["openai.com"]],
  [/^(?:GITHUB|GH)_/, ["github.com", "githubusercontent.com"]],
  [/^AWS_/, ["amazonaws.com"]],
  [/^(?:GOOGLE|GEMINI|GCP)_/, ["googleapis.com", "google.com"]],
  [/^SLACK_/, ["slack.com"]],
  [/^STRIPE_/, ["stripe.com"]],
  [/^NPM_/, ["npmjs.org", "npmjs.com"]],
  [/^(?:HF|HUGGINGFACE)_/, ["huggingface.co"]],
];

/** References to secrets in a shell command: $SECRET_VARS, secret files, env dumps. */
export function classifyCommandReferences(command: string): DataFinding[] {
  const out: DataFinding[] = [];
  for (const m of command.matchAll(SECRET_VAR)) {
    const name = m[1];
    out.push({ classifications: CRED, kind: `$${name}`, issuers: VAR_ISSUERS.find(([re]) => re.test(name))?.[1] });
  }
  for (const m of command.matchAll(SECRET_FILE)) {
    // A plain ".env.example" is a template, not secrets
    if (/\.env\.(?:example|sample|template|dist)$/.test(m[1])) continue;
    out.push({ classifications: CRED, kind: `secret file ${m[1]}` });
  }
  if (ENV_DUMP.test(command)) out.push({ classifications: CRED, kind: "environment dump" });
  return out;
}

// ─────────────────────────────────────────────────────────
// Destinations
// ─────────────────────────────────────────────────────────

/** Hosts of LLM APIs. Data sent here goes into someone's model. */
const MODEL_HOSTS = [
  "api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com", "aiplatform.googleapis.com",
  "api.deepseek.com", "api.moonshot.ai", "api.moonshot.cn", "dashscope.aliyuncs.com", "dashscope-intl.aliyuncs.com",
  "open.bigmodel.cn", "api.z.ai", "openrouter.ai", "api.groq.com", "api.together.xyz", "api.mistral.ai",
  "api.cohere.com", "api.cohere.ai", "api.fireworks.ai", "api.perplexity.ai", "api.x.ai", "api.cerebras.ai",
  "inference.huggingface.co", "api-inference.huggingface.co", "api.replicate.com",
];
const MODEL_HOST_SUFFIXES = [".openai.azure.com", ".services.ai.azure.com", ".cognitiveservices.azure.com"];

export function isModelEndpoint(host: string): boolean {
  host = host.toLowerCase();
  if (MODEL_HOSTS.includes(host) || MODEL_HOST_SUFFIXES.some((s) => host.endsWith(s))) return true;
  return /^bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com$/.test(host);
}

const hostOf = (url: string): string | undefined => {
  try { return new URL(url).hostname.toLowerCase(); } catch { return undefined; }
};

const isUnder = (host: string, domain: string) => host === domain || host.endsWith(`.${domain}`);

/** Does an explicit Network allow rule name this host (no wildcard in the host)? */
function namedInPolicy(policy: WardPolicy, host: string): boolean {
  for (const rule of policy.network?.allow ?? []) {
    const m = /^[a-z][a-z0-9+.-]*:\/\/([^/:?#*]+)(?:[:/?#]|$)/i.exec(rule.url.trim());
    if (m && m[1].toLowerCase() === host) return true;
  }
  return false;
}

// ─────────────────────────────────────────────────────────
// What a tool call sends
// ─────────────────────────────────────────────────────────

const snake = (key: string) => key.replace(/([a-z0-9])([A-Z])/g, "$1_$2").replace(/-/g, "_").toLowerCase();
const URL_KEY = /(^|_)(url|urls|uri|uris|endpoint|href|link|webhook)$/;
const PATH_KEY = /(^|_)(path|paths|file|files|filepath|filename|dir|dirs|directory|cwd|workdir)$/;
const COMMAND_KEY = /^(command|cmd|script|shell)$/;
// Arguments that describe the call to the harness rather than travel with it
const META_KEY = /^(prompt|description|reason|justification|explanation|timeout|method|cwd)$/;
// Who a message goes to is its destination, not data it carries
const RECIPIENT_KEY = /^(to|cc|bcc|from|sender|recipients?|reply_to|channel|channel_id|chat_id|user_id)$/;
const looksLikeUrl = (v: string) => /^[a-z][a-z0-9+.-]*:\/\//i.test(v);

const SENDING_TOOL = /(?:^|[_\W])(send|post|email|mail|message|publish|upload|webhook|tweet|comment|reply|notify|share|http|request|fetch|slack|discord|telegram|sms|submit|webfetch|curl)(?:$|[_\W])/i;

const URL_IN_TEXT = /[a-z][a-z0-9+.-]*:\/\/[^\s'"`<>|;&()]+/gi;
// Network commands that send without a URL argument (ssh host, scp f host:, nc host port)
const NET_BINARY = /(?:^|[\s;|&(`])(curl|wget|nc|ncat|netcat|ssh|scp|sftp|rsync|ftp|telnet|socat|http|https|xh|aria2c|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)(?=\s)/i;

interface Outbound {
  /** Where it goes: hostnames, or "an unknown host" */
  hosts: string[];
  texts: string[];
  /** Shell command text, scanned for secret references too */
  commands: string[];
}

function stringValues(v: unknown, depth = 0): string[] {
  if (depth > 4) return [];
  if (typeof v === "string") return [v];
  if (typeof v === "number" || typeof v === "boolean") return [String(v)];
  if (Array.isArray(v)) return v.flatMap((x) => stringValues(x, depth + 1));
  if (v && typeof v === "object") {
    return Object.entries(v as Record<string, unknown>).flatMap(([k, x]) => [`${k}=`, ...stringValues(x, depth + 1)]);
  }
  return [];
}

function urlPayload(url: string): string {
  try {
    const u = new URL(url);
    const parts = [u.username, u.password, u.pathname, u.search, u.hash].filter(Boolean).join(" ");
    try { return decodeURIComponent(parts.replace(/\+/g, " ")); } catch { return parts; }
  } catch {
    return url;
  }
}

function outboundOf(toolName: string, input: Record<string, unknown>, commandField?: string, urlField?: string): Outbound | null {
  const hosts = new Set<string>();
  const texts: string[] = [];
  const commands: string[] = [];
  let sends = SENDING_TOOL.test(toolName);

  for (const [key, raw] of Object.entries(input)) {
    const k = snake(key);
    const values = stringValues(raw);
    if (key === commandField || COMMAND_KEY.test(k)) {
      for (const c of values) {
        const urls = c.match(URL_IN_TEXT) ?? [];
        if (urls.length || NET_BINARY.test(c)) {
          sends = true;
          commands.push(c);
          for (const u of urls) hosts.add(hostOf(u) ?? "an unknown host");
          if (!urls.length) hosts.add("an unknown host");
        }
      }
      continue;
    }
    if (key === urlField || URL_KEY.test(k) || values.some(looksLikeUrl)) {
      for (const v of values.filter(looksLikeUrl)) {
        sends = true;
        hosts.add(hostOf(v) ?? "an unknown host");
        texts.push(urlPayload(v));
      }
      if (URL_KEY.test(k) || key === urlField) continue;
    }
    if (META_KEY.test(k) || PATH_KEY.test(k) || RECIPIENT_KEY.test(k)) continue;
    texts.push(...values.filter((v) => !looksLikeUrl(v)));
  }

  if (!sends) return null;
  if (!hosts.size) hosts.add("an unknown host");
  return { hosts: [...hosts], texts, commands };
}

// ─────────────────────────────────────────────────────────
// The check
// ─────────────────────────────────────────────────────────

const SENSITIVE: DataClassification[] = ["credentials", "secret", "pii", "pci", "phi"];

/**
 * Checks for the sensitive data a tool call would send. Returns nothing for
 * calls that don't send anything.
 */
export function checkOutboundData(
  policy: WardPolicy,
  toolName: string,
  args: Record<string, unknown> | undefined,
  opts: OutboundOptions & { commandField?: string; urlField?: string } = {},
): OutboundCheck[] {
  const input = args && typeof args === "object" ? args : {};
  const out = outboundOf(toolName, input, opts.commandField, opts.urlField);
  if (!out) return [];

  const findings: DataFinding[] = [];
  // In ssh/scp/rsync commands, "user@host" is a login, not an email address
  const asText = (c: string) => (/(?:^|[\s;|&(`])(?:ssh|scp|sftp|rsync|mosh)\s/.test(c) ? c.replace(/\b[\w.-]+@(?=[\w-]+(?:\.[\w-]+)+)/g, "") : c);
  for (const t of [...out.texts, ...out.commands.map(asText)]) {
    findings.push(...classifyData(t));
    if (opts.classify) findings.push(...opts.classify(t));
  }
  for (const c of out.commands) findings.push(...classifyCommandReferences(c));
  if (!findings.length) return [];

  const db = policy.dataBoundaries;
  const deny = new Set(db?.egressDeny ?? []);
  const allow = new Set(db?.egressAllow ?? []);
  const where = out.hosts.join(", ");
  const checks: OutboundCheck[] = [];
  const seen = new Set<string>();

  for (const f of findings) {
    if (seen.has(f.kind)) continue;
    seen.add(f.kind);
    // A credential going only to its issuer is how that API is used
    const issuerOnly = !!f.issuers?.length && out.hosts.every((h) => f.issuers!.some((d) => isUnder(h, d)));
    if (issuerOnly) continue;

    const subject = `${f.kind} to ${where}`;
    const denied = f.classifications.find((c) => deny.has(c));
    if (denied) {
      checks.push({ type: "egress", subject, decision: "deny", severity: denied === "credentials" || denied === "secret" ? "critical" : "high", matchedRule: denied, reason: `Outbound data contains ${f.kind} ('${denied}'), which WARD.md denies egress` });
      continue;
    }
    if (allow.size && !f.classifications.some((c) => allow.has(c))) {
      checks.push({ type: "egress", subject, decision: "deny", severity: "high", reason: `Outbound data contains ${f.kind} ('${f.classifications[0]}'), which is not in WARD.md's egressAllow list` });
      continue;
    }
    const allowedExplicitly = f.classifications.some((c) => allow.has(c));
    if (!allowedExplicitly && f.classifications.includes("credentials")) {
      checks.push({ type: "egress", subject, decision: "require_approval", severity: "high", reason: `Sending ${f.kind} anywhere but its issuer requires human approval (Ward egress guard; allow 'credentials' in egressAllow to lift this)` });
      continue;
    }
    const modelHosts = out.hosts.filter((h) => isModelEndpoint(h) && !namedInPolicy(policy, h));
    if (!allowedExplicitly && modelHosts.length && f.classifications.some((c) => SENSITIVE.includes(c))) {
      checks.push({ type: "egress", subject, decision: "require_approval", severity: "high", reason: `Sending ${f.kind} to a model endpoint WARD.md doesn't list (${modelHosts.join(", ")}) requires human approval (model-endpoint guardrail; add the host to a Network allow rule to lift this)` });
    }
  }
  return checks;
}
