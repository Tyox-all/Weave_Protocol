/**
 * Where Ward keeps its state (receipts, the limits ledger, the receipt key)
 * when the usual place, ~/.weave, can't be written.
 *
 * Harness sandboxes often make the home folder read-only for everything they
 * run, hooks included: Gemini CLI and Qwen Code under macOS Seatbelt, TRAE's
 * "Run in Sandbox" mode, read-only containers. They do leave the temp folder
 * writable (and point TMPDIR at their own). So when a default path under
 * ~/.weave can't be written, Ward uses the same layout under the temp folder.
 * A path set by a WEAVE_* variable is always used as given.
 *
 * Writability is checked with access(2) on the nearest existing folder, which
 * sandboxes answer without counting it as a violation (TRAE's sandbox makes
 * the hook fail on an actual write attempt, but not on this check).
 */

import { accessSync, constants, existsSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";

/** Can this path be written, or created? */
export function canWrite(path: string): boolean {
  let p = path;
  while (!existsSync(p)) {
    const up = dirname(p);
    if (up === p) return false;
    p = up;
  }
  try {
    accessSync(p, constants.W_OK);
    return true;
  } catch {
    return false;
  }
}

/** ~/.weave, the usual home for Ward's state. */
export const weaveHome = () => join(homedir(), ".weave");

/** The temp-folder stand-in for ~/.weave, one per user. */
export const tempWeaveHome = () => join(tmpdir(), `weave-${process.getuid?.() ?? "user"}`);

/**
 * `rel` under ~/.weave if that can be written, else under the temp stand-in.
 * Returns the ~/.weave path when neither is writable, so the error names it.
 */
export function stateDir(rel: string): string {
  const home = join(weaveHome(), rel);
  if (canWrite(home)) return home;
  const temp = join(tempWeaveHome(), rel);
  return canWrite(temp) ? temp : home;
}

/**
 * A state file under ~/.weave, unless it doesn't exist yet and can't be
 * created there: then under the temp stand-in. An existing file is only read,
 * which read-only sandboxes allow, so it stays put.
 */
export function stateFile(rel: string): string {
  const home = join(weaveHome(), rel);
  if (existsSync(home) || canWrite(dirname(home))) return home;
  const temp = join(tempWeaveHome(), rel);
  return existsSync(temp) || canWrite(dirname(temp)) ? temp : home;
}
