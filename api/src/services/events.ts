/**
 * Enforcement events reported by Weave surfaces (Ward's reportEvent):
 * Hundredmen, the Claude Code / Antigravity / MSAF / Gemini CLI / Codex /
 * OpenCode / Cursor adapters, and the browser guard. Kept in memory, newest last, capped; the dashboard
 * snapshot is built from them. Nothing here is synthetic.
 */

export const SURFACES = ['mcp', 'claude-code', 'antigravity', 'msaf', 'browser', 'gemini-cli', 'codex', 'opencode', 'cursor'] as const;
export const DECISIONS = ['allow', 'deny', 'require_approval', 'ipi_detected', 'scan'] as const;
export type Surface = (typeof SURFACES)[number];
export type EventDecision = (typeof DECISIONS)[number];

export interface StoredEvent {
  id: string;
  surface: Surface;
  decision: EventDecision;
  subject: string;
  reason?: string;
  timestamp: number;
  receivedAt: number;
}

const MAX_TEXT = 200;
const DAY = 24 * 60 * 60 * 1000;

export class EventStore {
  private events: StoredEvent[] = [];
  private seq = 0;

  constructor(private readonly capacity = Number(process.env.WEAVE_EVENTS_MAX) || 5000) {}

  /** Validate and store an event; returns an error message for bad input. */
  add(input: unknown, now = Date.now()): StoredEvent | { error: string } {
    const e = (input ?? {}) as Record<string, unknown>;
    if (!SURFACES.includes(e.surface as Surface)) return { error: `surface must be one of ${SURFACES.join(', ')}` };
    if (!DECISIONS.includes(e.decision as EventDecision)) return { error: `decision must be one of ${DECISIONS.join(', ')}` };
    if (typeof e.subject !== 'string' || !e.subject) return { error: 'subject is required' };
    // Trust the reporter's clock only within a day of ours
    const ts = typeof e.timestamp === 'number' && Math.abs(e.timestamp - now) < DAY ? e.timestamp : now;
    const event: StoredEvent = {
      id: `evt-${now}-${++this.seq}`,
      surface: e.surface as Surface,
      decision: e.decision as EventDecision,
      subject: e.subject.slice(0, MAX_TEXT),
      ...(typeof e.reason === 'string' && e.reason ? { reason: e.reason.slice(0, MAX_TEXT) } : {}),
      timestamp: ts,
      receivedAt: now,
    };
    this.events.push(event);
    if (this.events.length > this.capacity) this.events.splice(0, this.events.length - this.capacity);
    return event;
  }

  /** Newest first, by when the event happened (reports can arrive late). */
  recent(limit = 12): StoredEvent[] {
    return [...this.events].sort((a, b) => b.timestamp - a.timestamp || b.receivedAt - a.receivedAt).slice(0, limit);
  }

  since(ts: number): StoredEvent[] {
    return this.events.filter((e) => e.timestamp >= ts);
  }

  clear(): void {
    this.events = [];
  }

  get size(): number {
    return this.events.length;
  }
}

/** Shared store for the running API. */
export const events = new EventStore();
