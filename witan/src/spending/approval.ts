/**
 * Approval handler dispatch.
 *
 * Two paths:
 *
 *   1. Programmatic: user passes an `approvalHandler` async callback that
 *      returns true/false (Slack, PagerDuty, custom UI, etc.)
 *
 *   2. Interactive CLI: if no handler is supplied AND the process is a TTY,
 *      show a yellow-box prompt on stderr and read y/n from stdin.
 *
 *   3. Neither TTY nor handler: safe default — return false (denied).
 *      This is the correct behavior for CI, daemon processes, and any
 *      non-interactive context where "silent approval" would be dangerous.
 */

import { createInterface } from 'node:readline/promises';
import type { PendingApprovalEvent } from './types.js';

export type ApprovalHandler = (event: PendingApprovalEvent) => Promise<boolean>;

/**
 * Interactive TTY prompt for approval. Only invoked when:
 *   - No user handler was supplied
 *   - process.stdin is a TTY
 */
export const interactiveApprovalHandler: ApprovalHandler = async (event) => {
  const YEL_BG = '\x1b[43m\x1b[1;30m';
  const BOLD = '\x1b[1m';
  const RESET = '\x1b[0m';

  const lines = [
    '',
    `${YEL_BG} ⚠  SPENDING CAP APPROVAL REQUIRED ${RESET}`,
    '',
    `  ${BOLD}Cap:${RESET}       ${event.cap.label || `${event.cap.window} window`} (${event.cap.window})`,
    `  ${BOLD}Limit:${RESET}     ${event.violation.limit}`,
    `  ${BOLD}Current:${RESET}   ${event.violation.current}`,
    `  ${BOLD}Proposed:${RESET}  ${event.violation.proposed}`,
    `  ${BOLD}Overage:${RESET}   ${(event.violation.proposed - event.violation.limit).toFixed(4)}`,
    `  ${BOLD}Reason:${RESET}    ${event.violation.reason}`,
    '',
    `  ${BOLD}Est. cost:${RESET} $${event.estimatedCostUSD.toFixed(6)} USD`,
    '',
  ];
  for (const l of lines) process.stderr.write(l + '\n');

  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    const answer = await rl.question('  Approve? [y/N]: ');
    return /^y(es)?$/i.test(answer.trim());
  } finally {
    rl.close();
  }
};

/**
 * Non-interactive safe default. Denies approval and logs to stderr.
 */
export const denyByDefaultHandler: ApprovalHandler = async (event) => {
  process.stderr.write(
    `[witan/spending] require_approval cap hit with no approval handler and non-TTY; denying.\n` +
      `  cap: ${event.cap.label || event.cap.window} window; violation: ${event.violation.reason}\n`,
  );
  return false;
};

/**
 * Resolve which handler to use given options.
 */
export function resolveHandler(userHandler?: ApprovalHandler): ApprovalHandler {
  if (userHandler) return userHandler;
  if (process.stdin.isTTY) return interactiveApprovalHandler;
  return denyByDefaultHandler;
}
