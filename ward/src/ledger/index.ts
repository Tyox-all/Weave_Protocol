/**
 * @weave_protocol/ward/ledger: session and spend history on disk (Node only).
 *
 * Hook-based adapters run a fresh process for every tool call, so the counts
 * behind WARD.md's Behavioral Limits and `spending_limits:` caps have to live
 * somewhere. This keeps one small JSON file per agent:
 *
 *   $WEAVE_LEDGER_DIR (default ~/.weave/ledger)/<agent>.json   mode 0600
 *
 * Each record is a call that wasn't denied: when, which session, the tool
 * and capability, the USD amount for payments, and hosts contacted. No
 * arguments or payloads are stored. Records older than 31 days are dropped.
 * Parallel hook processes are serialized with a lock file; writes are atomic.
 */

import { mkdirSync, openSync, closeSync, readFileSync, writeFileSync, renameSync, rmSync, statSync, chmodSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { WardPolicy } from "../types.js";
import { evaluateToolCall, aggregate, type EvaluateOptions, type ToolCallEvaluation, type ToolCallCheck } from "../enforcer/toolcall.js";
import { checkSessionLimits, needsLedger, type LedgerEvent, type LedgerSnapshot } from "../enforcer/limits.js";

const KEEP_MS = 31 * 86_400_000;
const LOCK_STALE_MS = 5_000;
const LOCK_WAIT_MS = 2_000;
const SLEEP = new Int32Array(new SharedArrayBuffer(4));

interface LedgerFile {
  version: 1;
  sessions: Record<string, { startedAt: number }>;
  events: LedgerEvent[];
}

export interface LedgerOptions {
  /** Directory for ledger files (default $WEAVE_LEDGER_DIR or ~/.weave/ledger) */
  dir?: string;
}

export function ledgerDir(opts: LedgerOptions = {}): string {
  return opts.dir ?? process.env.WEAVE_LEDGER_DIR ?? join(homedir(), ".weave", "ledger");
}

const fileName = (agent: string) => `${(agent || "default").replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 80) || "default"}.json`;

/** A per-agent ledger file. */
export class FileLedger {
  readonly path: string;
  private lockPath: string;

  constructor(agent: string, opts: LedgerOptions = {}) {
    const dir = ledgerDir(opts);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    this.path = join(dir, fileName(agent));
    this.lockPath = `${this.path}.lock`;
  }

  /** Read, let `fn` decide and append, then write, all under the lock. */
  transact<T>(fn: (data: LedgerFile, now: number) => { result: T; append?: LedgerEvent; session?: string }): T {
    const locked = this.lock();
    try {
      const now = Date.now();
      const data = this.read(now);
      const { result, append, session } = fn(data, now);
      if (session && !data.sessions[session]) data.sessions[session] = { startedAt: now };
      if (append) data.events.push(append);
      if (append || session) this.write(data);
      return result;
    } finally {
      if (locked) this.unlock();
    }
  }

  snapshot(session: string): LedgerSnapshot {
    const data = this.read(Date.now());
    return { events: data.events, sessionStartedAt: data.sessions[session]?.startedAt };
  }

  private read(now: number): LedgerFile {
    let data: LedgerFile = { version: 1, sessions: {}, events: [] };
    try {
      const parsed = JSON.parse(readFileSync(this.path, "utf8"));
      if (parsed && Array.isArray(parsed.events) && parsed.sessions && typeof parsed.sessions === "object") data = parsed;
    } catch {
      // Missing or unreadable: start fresh
    }
    data.events = data.events.filter((e) => now - e.at < KEEP_MS);
    for (const [id, s] of Object.entries(data.sessions)) if (now - s.startedAt > KEEP_MS) delete data.sessions[id];
    return data;
  }

  private write(data: LedgerFile): void {
    const tmp = `${this.path}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(data), { mode: 0o600 });
    renameSync(tmp, this.path);
    try { chmodSync(this.path, 0o600); } catch { /* best effort */ }
  }

  private lock(): boolean {
    const deadline = Date.now() + LOCK_WAIT_MS;
    for (;;) {
      try {
        closeSync(openSync(this.lockPath, "wx", 0o600));
        return true;
      } catch {
        try {
          if (Date.now() - statSync(this.lockPath).mtimeMs > LOCK_STALE_MS) { rmSync(this.lockPath, { force: true }); continue; }
        } catch { continue; }
        if (Date.now() > deadline) return false; // proceed unlocked rather than hang the agent
        Atomics.wait(SLEEP, 0, 0, 10); // hooks are synchronous; sleep 10ms without spinning
      }
    }
  }

  private unlock(): void {
    rmSync(this.lockPath, { force: true });
  }
}

export interface LedgerEvaluateOptions extends EvaluateOptions, LedgerOptions {
  /** The harness's session or conversation id. Without one, calls share the "default" session. */
  session?: string;
  /** Use this ledger instead of the file for the policy's agent */
  ledger?: FileLedger;
}

/**
 * evaluateToolCall plus the limits that need history. The ledger is only
 * touched when WARD.md declares such limits. A call that isn't denied is
 * recorded (one needing approval too: if approved, it runs).
 */
export function evaluateWithLedger(
  policy: WardPolicy,
  toolName: string,
  args: Record<string, unknown> | undefined,
  opts: LedgerEvaluateOptions = {},
): ToolCallEvaluation {
  const base = evaluateToolCall(policy, toolName, args, opts);
  if (!needsLedger(policy)) return base;

  const session = opts.session || "default";
  const capability = opts.mappings?.[toolName]?.capability ?? toolName;
  const ledger = opts.ledger ?? new FileLedger(policy.agent ?? "default", opts);

  return ledger.transact((data, now) => {
    const snapshot: LedgerSnapshot = { events: data.events, sessionStartedAt: data.sessions[session]?.startedAt };
    const limits = checkSessionLimits(policy, snapshot, { session, tool: toolName, capability, payment: base.payment, hosts: base.hosts }, now);
    const result: ToolCallEvaluation = { ...aggregate([...base.checks, ...(limits as ToolCallCheck[])]), ...(base.payment ? { payment: base.payment } : {}), ...(base.hosts ? { hosts: base.hosts } : {}) };
    const append: LedgerEvent | undefined = result.decision === "deny" ? undefined : {
      at: now, session, tool: toolName, capability,
      ...(base.payment?.amountUSD !== undefined ? { amountUSD: base.payment.amountUSD } : {}),
      ...(base.hosts?.length ? { hosts: base.hosts } : {}),
    };
    return { result, append, session };
  });
}
