/**
 * Spend and session limits (Ward 0.3.6).
 *
 * Two parts:
 *
 *   - The payment guard, always on: a call that moves money (a payment,
 *     transfer, purchase or withdrawal tool, or a wallet / Stripe CLI in a
 *     shell command) needs human approval unless WARD.md allows that exact
 *     capability by name. A default "allow" or a wildcard doesn't count.
 *     (In October 2026 an agent spent from a crypto wallet it was never
 *     authorized to use.)
 *
 *   - Session limits, from what has already happened: WARD.md's Behavioral
 *     Limits (maxToolCalls, maxRuntimeSeconds, maxExternalServices) and
 *     `spending_limits:` caps (tool_calls, per-tool max_calls and
 *     max_amount_usd) over run / hour / day / week / month windows. The
 *     history comes from a ledger: @weave_protocol/ward/ledger keeps one on
 *     disk for hook-based adapters, whose every call is a fresh process.
 *
 * USD and token budgets for LLM usage are Witan's: hooks never see model
 * usage. No Node built-ins: Ward also runs in browsers.
 */

import type { WardPolicy, SpendingCap, SpendingWindow } from "../types.js";
import type { CheckResult } from "./index.js";

// ─────────────────────────────────────────────────────────
// Payments
// ─────────────────────────────────────────────────────────

/** Words that always mean money moves */
const PAYMENT_WORD = /(?:^|[_\W])(pay|payment|payments|payout|payouts|purchase|checkout|withdraw|withdrawal|wire|send_money|sendmoney|send_eth|send_sol|send_crypto|send_transaction|sign_transaction|transfer_funds|create_charge|charge_card)(?:$|[_\W])/i;
/** Words that mean money moves when the call carries an amount */
const MAYBE_PAYMENT_WORD = /(?:^|[_\W])(transfer|swap|bridge|buy|order|refund|charge|tip|donate|send)(?:$|[_\W])/i;
const AMOUNT_KEY = /^(amount|amount_usd|amount_cents|value|value_usd|price|total|sum|lamports|wei)$/;
const CURRENCY_KEY = /^(currency|currency_code|asset|token|coin)$/;
/** Wallet, exchange and payment CLIs that move money */
const PAYMENT_COMMAND = /(?:^|[\s;|&(`])(?:cast\s+send|solana\s+transfer|spl-token\s+transfer|bitcoin-cli\s+(?:sendtoaddress|sendmany|sendrawtransaction)|eth\s+send|near\s+send|aptos\s+account\s+transfer|stripe\s+(?:payouts|transfers|charges|payment_intents|refunds)\s+create|paypal\s+payouts)\b/i;

const snake = (key: string) => key.replace(/([a-z0-9])([A-Z])/g, "$1_$2").replace(/-/g, "_").toLowerCase();

export interface PaymentCall {
  /** Amount in USD, when the call states one in USD (or no currency) */
  amountUSD?: number;
  /** The amount as stated, for the reason text */
  stated?: string;
  /** Found in a shell command (a wallet or payment CLI) rather than a tool name */
  viaCommand?: boolean;
}

/** Is this call moving money? Returns what's known about the amount. */
export function detectPayment(toolName: string, capability: string, args: Record<string, unknown>, command?: string): PaymentCall | null {
  const names = `${toolName} ${capability}`;
  let amount: number | undefined;
  let stated: string | undefined;
  let currency: string | undefined;
  for (const [key, raw] of Object.entries(args)) {
    const k = snake(key);
    if (AMOUNT_KEY.test(k) && (typeof raw === "number" || (typeof raw === "string" && /^\s*\$?\d[\d,]*(\.\d+)?\s*$/.test(raw)))) {
      const n = typeof raw === "number" ? raw : Number(raw.replace(/[$,\s]/g, ""));
      if (Number.isFinite(n)) {
        amount = k === "amount_cents" ? n / 100 : n;
        stated = `${raw}${k === "amount_cents" ? " cents" : ""}`;
      }
    } else if (CURRENCY_KEY.test(k) && typeof raw === "string") {
      currency = raw.trim().toUpperCase();
    }
  }
  const byName = PAYMENT_WORD.test(names) || (MAYBE_PAYMENT_WORD.test(names) && amount !== undefined);
  const viaCommand = !byName && !!command && PAYMENT_COMMAND.test(command);
  if (!byName && !viaCommand) return null;
  if (currency && stated) stated = `${stated} ${currency}`;
  const usd = amount !== undefined && (!currency || currency === "USD" || currency === "USDC" || currency === "USDT") ? amount : undefined;
  return { ...(usd !== undefined ? { amountUSD: usd } : {}), ...(stated ? { stated } : {}), ...(viaCommand ? { viaCommand } : {}) };
}

/**
 * Does WARD.md allow this capability by its exact name (not by default or
 * wildcard)? The name `payments` allows every payment.
 */
export function explicitlyAllowed(policy: WardPolicy, ...names: string[]): boolean {
  const allow = policy.capabilities?.allow ?? [];
  return names.some((n) => allow.includes(n));
}

// ─────────────────────────────────────────────────────────
// Session limits
// ─────────────────────────────────────────────────────────

/** One call the ledger remembers. */
export interface LedgerEvent {
  /** Milliseconds since the epoch */
  at: number;
  session: string;
  tool: string;
  capability: string;
  /** USD moved, for payment calls with a known amount */
  amountUSD?: number;
  /** Hosts the call contacted */
  hosts?: string[];
}

/** What a limit check needs to know about the past. */
export interface LedgerSnapshot {
  /** Events from at least the last 31 days, any session */
  events: LedgerEvent[];
  /** When this session's first call was seen */
  sessionStartedAt?: number;
}

/** The call being decided. */
export interface PendingCall {
  session: string;
  tool: string;
  capability: string;
  payment?: PaymentCall | null;
  hosts?: string[];
}

export interface LimitCheck extends CheckResult {
  type: "limits";
  subject: string;
}

const WINDOW_MS: Record<Exclude<SpendingWindow, "run">, number> = {
  hour: 3_600_000,
  day: 86_400_000,
  week: 7 * 86_400_000,
  month: 30 * 86_400_000,
};

/** Does this policy have any limit that needs history? */
export function needsLedger(policy: WardPolicy): boolean {
  const b = policy.behavioral;
  return !!(b?.maxToolCalls !== undefined || b?.maxRuntimeSeconds !== undefined || b?.maxExternalServices !== undefined ||
    policy.spending?.some((c) => c.budget.tool_calls !== undefined || c.budget.tools));
}

const ACTION = { block: "deny", require_approval: "require_approval", notify: "allow" } as const;

/**
 * Check a call against the Behavioral Limits and spending caps, given what
 * the ledger has seen. Counts include the call being decided.
 */
export function checkSessionLimits(policy: WardPolicy, snapshot: LedgerSnapshot, call: PendingCall, now = Date.now()): LimitCheck[] {
  const checks: LimitCheck[] = [];
  const mine = snapshot.events.filter((e) => e.session === call.session);
  const b = policy.behavioral;

  if (b?.maxToolCalls !== undefined && mine.length + 1 > b.maxToolCalls) {
    checks.push({ type: "limits", subject: `session ${call.session}`, decision: "deny", severity: "medium", reason: `Max tool calls for this session reached (${b.maxToolCalls}; WARD.md Behavioral Limits)` });
  }
  const started = snapshot.sessionStartedAt ?? mine[0]?.at;
  if (b?.maxRuntimeSeconds !== undefined && started !== undefined && (now - started) / 1000 > b.maxRuntimeSeconds) {
    checks.push({ type: "limits", subject: `session ${call.session}`, decision: "deny", severity: "high", reason: `Max runtime for this session reached (${b.maxRuntimeSeconds}s; WARD.md Behavioral Limits)` });
  }
  if (b?.maxExternalServices !== undefined && call.hosts?.length) {
    const hosts = new Set(mine.flatMap((e) => e.hosts ?? []));
    const before = hosts.size;
    call.hosts.forEach((h) => hosts.add(h));
    if (hosts.size > before && hosts.size > b.maxExternalServices) {
      checks.push({ type: "limits", subject: `session ${call.session}`, decision: "deny", severity: "medium", reason: `Max external services for this session reached (${b.maxExternalServices}; WARD.md Behavioral Limits)` });
    }
  }

  for (const cap of policy.spending ?? []) {
    const decision = ACTION[cap.onExceeded];
    const label = cap.label ?? `${cap.window} cap`;
    const inWindow = cap.window === "run" ? mine : snapshot.events.filter((e) => now - e.at < WINDOW_MS[cap.window as Exclude<SpendingWindow, "run">]);

    if (cap.budget.tool_calls !== undefined && inWindow.length + 1 > cap.budget.tool_calls) {
      checks.push({ type: "limits", subject: label, decision, severity: "medium", reason: `Spending limit '${label}': ${cap.budget.tool_calls} tool calls per ${cap.window} reached` });
    }
    for (const [name, tb] of Object.entries(cap.budget.tools ?? {})) {
      if (name !== call.tool && name !== call.capability) continue;
      const same = inWindow.filter((e) => e.tool === name || e.capability === name);
      if (tb.max_calls !== undefined && same.length + 1 > tb.max_calls) {
        checks.push({ type: "limits", subject: label, decision, severity: "high", reason: `Spending limit '${label}': ${name} allowed ${tb.max_calls} times per ${cap.window}` });
      }
      if (tb.max_amount_usd !== undefined) {
        const amount = call.payment?.amountUSD;
        if (amount === undefined) {
          checks.push({ type: "limits", subject: label, decision: "require_approval", severity: "high", reason: `Spending limit '${label}': ${name} has a $${tb.max_amount_usd} cap but this call's USD amount is unknown${call.payment?.stated ? ` (${call.payment.stated})` : ""}` });
          continue;
        }
        const spent = same.reduce((sum, e) => sum + (e.amountUSD ?? 0), 0);
        if (spent + amount > tb.max_amount_usd) {
          checks.push({ type: "limits", subject: label, decision, severity: "critical", reason: `Spending limit '${label}': ${name} would move $${(spent + amount).toFixed(2)} this ${cap.window}, over the $${tb.max_amount_usd} cap ($${spent.toFixed(2)} already)` });
        }
      }
    }
  }
  return checks.filter((c) => c.decision !== "allow");
}
