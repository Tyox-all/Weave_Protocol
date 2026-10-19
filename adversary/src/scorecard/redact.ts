/**
 * Evidence redaction for shareable scorecards (--redact-evidence).
 */

import type { Scorecard } from '../types.js';

/**
 * Mutate findings in-place to redact evidence strings. Used when
 * --redact-evidence is set so sensitive LLM output doesn't leak into
 * shareable scorecards.
 */
export function redactScorecard(scorecard: Scorecard): Scorecard {
  for (const f of scorecard.findings) {
    if (f.result !== 'blocked') {
      f.evidence = '[redacted — re-run without --redact-evidence to see]';
    }
    if (f.toolCallsMade) {
      f.toolCallsMade = redactToolCalls(f.toolCallsMade);
    }
    // Dynamic mode keeps per-attempt responses; scrub those too or the
    // redacted evidence leaks back out through attempts[].
    for (const a of f.attempts ?? []) {
      if (a.result !== 'blocked') {
        a.evidence = '[redacted — re-run without --redact-evidence to see]';
        a.responseText = '[redacted]';
      }
      if (a.toolCalls) a.toolCalls = redactToolCalls(a.toolCalls);
    }
  }
  return scorecard;
}

function redactToolCalls(calls: Array<{ name: string; arguments: Record<string, unknown> }>) {
  return calls.map((tc) => ({ name: tc.name, arguments: { _redacted: true } }));
}
