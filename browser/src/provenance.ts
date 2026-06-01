/**
 * Session provenance tracker.
 *
 * Per the 2026 SOTA IPI defense pattern (Zylos research): "flag tool calls
 * to external HTTP endpoints originating from sessions that processed
 * untrusted external content."
 *
 * This module keeps a per-session record of which URLs have been ingested
 * and whether IPI was detected. The guard uses this to decide whether
 * subsequent tool calls in the same session need extra scrutiny.
 *
 * Sessions are identified by an opaque string the caller supplies — typically
 * a request-scoped or agent-run-scoped ID. The map is in-memory only; persist
 * externally if you need cross-process tracking.
 */

import type { SessionProvenance } from './types.js';

const sessions = new Map<string, SessionProvenance>();

export function getOrCreateSession(sessionId: string): SessionProvenance {
  let s = sessions.get(sessionId);
  if (!s) {
    s = { sessionId, ingestedSources: [], tainted: false };
    sessions.set(sessionId, s);
  }
  return s;
}

export function recordIngestion(
  sessionId: string,
  url: string,
  trustLevel: 'trusted' | 'untrusted' | 'unknown',
  hadIpi: boolean,
): void {
  const s = getOrCreateSession(sessionId);
  s.ingestedSources.push({
    url,
    trustLevel,
    ingestedAt: Date.now(),
    hadIpi,
  });
  if (trustLevel === 'untrusted' || hadIpi) {
    s.tainted = true;
  }
}

export function isTainted(sessionId: string): boolean {
  const s = sessions.get(sessionId);
  return s?.tainted ?? false;
}

export function getSession(sessionId: string): SessionProvenance | undefined {
  return sessions.get(sessionId);
}

export function clearSession(sessionId: string): void {
  sessions.delete(sessionId);
}

export function clearAllSessions(): void {
  sessions.clear();
}

/**
 * Classify a URL's trust level. Heuristic for v0.1: any HTTPS URL whose
 * origin matches WARD ## Network allow list is treated as trusted, everything
 * else is untrusted. Callers can override by passing an explicit trustLevel
 * to recordIngestion().
 *
 * For v0.2: integrate WARD ## Data Boundaries to give finer-grained labels
 * (e.g. "trusted-but-untrusted-pii").
 */
export function classifyTrust(url: string, allowedOrigins: string[]): 'trusted' | 'untrusted' {
  try {
    const u = new URL(url);
    const origin = u.origin;
    for (const allowed of allowedOrigins) {
      if (origin === allowed || origin.endsWith('.' + allowed.replace(/^https?:\/\//, ''))) {
        return 'trusted';
      }
    }
  } catch {
    // Not a parseable URL — treat as untrusted
  }
  return 'untrusted';
}
