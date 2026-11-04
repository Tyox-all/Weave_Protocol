/**
 * Report enforcement decisions to a local Weave API dashboard.
 *
 * Off unless a dashboard URL is configured (WEAVE_DASHBOARD_URL, or the
 * `url` option). Reporting never changes a decision and never holds the
 * caller longer than a short timeout: failures are swallowed.
 *
 * Only a summary is sent: the surface, the decision, the tool name or a
 * URL without its query string, and a truncated reason with any quoted
 * argument removed. Command text and argument contents are never sent.
 *
 * Uses fetch, so it works in Node 18+ and in browsers (no Node built-ins).
 */

import type { Decision } from "./enforcer/index.js";

export type ReportSurface =
  | "mcp"
  | "claude-code"
  | "antigravity"
  | "msaf"
  | "browser"
  | "gemini-cli"
  | "codex"
  | "opencode"
  | "cursor";
export type ReportDecision = Decision | "ipi_detected" | "scan";

export interface EnforcementEvent {
  surface: ReportSurface;
  decision: ReportDecision;
  /** Tool name, or a URL (its query string and fragment are dropped) */
  subject: string;
  reason?: string;
  /** ms since epoch; defaults to now */
  timestamp?: number;
}

export interface ReportOptions {
  /** Dashboard base URL, e.g. http://localhost:3000. Default: $WEAVE_DASHBOARD_URL */
  url?: string;
  /** API key. Default: $WEAVE_API_KEY */
  apiKey?: string;
  /** Default 250ms */
  timeoutMs?: number;
}

const MAX = 200;
const env = (key: string): string | undefined =>
  (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.[key];

/** The dashboard URL reportEvent would use, or undefined when reporting is off. */
export function dashboardUrl(opts: ReportOptions = {}): string | undefined {
  const url = opts.url ?? env("WEAVE_DASHBOARD_URL");
  return url ? url.replace(/\/+$/, "") : undefined;
}

/** Strip a URL to origin + path, so tokens in query strings never leave. */
function safeSubject(subject: string): string {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(subject)) {
    try {
      const u = new URL(subject);
      return `${u.origin}${u.pathname}`.slice(0, MAX);
    } catch {
      return "(unparseable URL)";
    }
  }
  return subject.slice(0, MAX);
}

/** Drop the "(arg=value)" suffix evaluateToolCall adds, which can hold argument contents. */
function safeReason(reason: string | undefined): string | undefined {
  if (!reason) return undefined;
  return reason.replace(/\s*\([^()]*\)\s*$/, "").slice(0, MAX);
}

/**
 * Send one event to the dashboard. Resolves when sent, failed or timed out;
 * never rejects. A no-op when no dashboard URL is configured.
 */
export async function reportEvent(event: EnforcementEvent, opts: ReportOptions = {}): Promise<void> {
  const base = dashboardUrl(opts);
  const doFetch = (globalThis as { fetch?: typeof fetch }).fetch;
  if (!base || !doFetch) return;

  const apiKey = opts.apiKey ?? env("WEAVE_API_KEY");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 250);
  try {
    await doFetch(`${base}/api/v1/events`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(apiKey ? { "X-API-Key": apiKey } : {}) },
      body: JSON.stringify({
        surface: event.surface,
        decision: event.decision,
        subject: safeSubject(event.subject),
        reason: safeReason(event.reason),
        timestamp: event.timestamp ?? Date.now(),
      }),
      signal: controller.signal,
    });
  } catch {
    // The dashboard is optional: never let it affect enforcement.
  } finally {
    clearTimeout(timer);
  }
}
