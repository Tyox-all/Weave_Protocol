/**
 * Window key generation for spending caps.
 *
 * A window key is a stable string that identifies the current bucket for
 * a (window-type, scope) pair. Counters are keyed by these strings in the
 * store; when the window rolls over, the new key is fresh (counter = 0).
 *
 * Format: `<window>:<bucket>:<scope>` (e.g. 'day:2026-06-29:default')
 */

import type { SpendingWindow } from './types.js';

/**
 * Compute the current window key given a window type, scope, and clock.
 */
export function windowKey(window: SpendingWindow, scope: string, now: number): string {
  const bucket = windowBucket(window, now);
  return `${window}:${bucket}:${scope}`;
}

/**
 * Compute the bucket string for a given window type.
 * 'run' is a session-random stable value; others are calendar-derived.
 */
function windowBucket(window: SpendingWindow, now: number): string {
  const d = new Date(now);
  switch (window) {
    case 'run':
      return RUN_ID;
    case 'hour':
      return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}`;
    case 'day':
      return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
    case 'week': {
      const startOfYear = Date.UTC(d.getUTCFullYear(), 0, 1);
      const dayOfYear = Math.floor((now - startOfYear) / 86_400_000);
      const week = Math.floor(dayOfYear / 7) + 1;
      return `${d.getUTCFullYear()}-W${pad(week)}`;
    }
    case 'month':
      return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}`;
  }
}

function pad(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}

/**
 * Session-scoped random ID for 'run' windows. Fresh on each Node process.
 */
const RUN_ID = Math.random().toString(36).slice(2, 8);

/**
 * Get the current run's ID (exposed for CLI status output).
 */
export function currentRunId(): string {
  return RUN_ID;
}
