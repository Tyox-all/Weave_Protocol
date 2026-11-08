/**
 * `spending_limits:` parser, the format @weave_protocol/witan reads:
 *
 *   spending_limits:
 *     - window: day            # run | hour | day | week | month
 *       budget:
 *         tool_calls: 100
 *         tools:
 *           send_payment:
 *             max_amount_usd: 500
 *             max_calls: 5
 *       on_exceeded: require_approval   # block | require_approval | notify
 *
 * Ward's small YAML reader doesn't handle lists of maps, so this is a
 * dedicated block parser, ported from Witan's so both read the same caps.
 */

import type { SpendingAction, SpendingCap, SpendingWindow, ToolBudget } from "../types.js";

const WINDOWS = ["run", "hour", "day", "week", "month"];
const ACTIONS = ["block", "require_approval", "notify"];

/** Caps from the first `spending_limits:` block in the text, or []. */
export function parseSpendingLimits(text: string): SpendingCap[] {
  const block = text.match(/(?:^|\n)spending_limits:\s*\n([\s\S]*?)(?=\n[A-Za-z_#][^\n]*|$)/);
  if (!block) return [];
  return block[1]
    .split(/\n\s*-\s+/)
    .map((item) => parseItem(item.replace(/^\s*-\s+/, "")))
    .filter((c): c is SpendingCap => c !== null);
}

function parseItem(item: string): SpendingCap | null {
  const window = scalar(item, /window:\s*(\w+)/) as SpendingWindow | undefined;
  const onExceeded = scalar(item, /on_exceeded:\s*(\w+)/) as SpendingAction | undefined;
  if (!window || !WINDOWS.includes(window) || !onExceeded || !ACTIONS.includes(onExceeded)) return null;

  const toolsAt = item.search(/\btools:\s*\n/);
  const outer = toolsAt >= 0 ? item.slice(0, toolsAt) + item.slice(item.search(/\n\s*(?:on_exceeded|label|scope):/) >>> 0) : item;
  const budget: SpendingCap["budget"] = {};
  const usd = parseFloat(scalar(outer, /(?:^|\s)usd:\s*([\d.]+)/) ?? "");
  const tokens = parseInt(scalar(outer, /(?:^|\s)tokens:\s*(\d+)/) ?? "", 10);
  const calls = parseInt(scalar(outer, /(?:^|\s)tool_calls:\s*(\d+)/) ?? "", 10);
  if (Number.isFinite(usd)) budget.usd = usd;
  if (Number.isFinite(tokens)) budget.tokens = tokens;
  if (Number.isFinite(calls)) budget.tool_calls = calls;

  const toolsBlock = item.match(/\btools:\s*\n([\s\S]*?)(?=\n\s*(?:on_exceeded|label|scope):|$)/);
  if (toolsBlock) {
    const tools = parseTools(toolsBlock[1]);
    if (Object.keys(tools).length) budget.tools = tools;
  }

  const label = scalar(item, /label:\s*["']?([^"'\n]+)["']?/);
  const scope = scalar(item, /scope:\s*["']?([^"'\n]+)["']?/);
  return { window, budget, onExceeded, ...(label ? { label } : {}), ...(scope ? { scope } : {}) };
}

function parseTools(block: string): Record<string, ToolBudget> {
  const headers = [...block.matchAll(/(?:^|\n)(\s*)([\w.*-]+):\s*(?=\n)/g)].map((m) => ({
    name: m[2],
    indent: m[1].replace(/\n/g, "").length,
    start: m.index! + m[0].length,
  }));
  if (!headers.length) return {};
  const min = Math.min(...headers.map((h) => h.indent));
  const top = headers.filter((h) => h.indent === min);
  const tools: Record<string, ToolBudget> = {};
  top.forEach((h, i) => {
    const body = block.slice(h.start, i + 1 < top.length ? top[i + 1].start : block.length);
    const amt = parseFloat(scalar(body, /max_amount_usd:\s*([\d.]+)/) ?? "");
    const cnt = parseInt(scalar(body, /max_calls:\s*(\d+)/) ?? "", 10);
    tools[h.name] = {};
    if (Number.isFinite(amt)) tools[h.name].max_amount_usd = amt;
    if (Number.isFinite(cnt)) tools[h.name].max_calls = cnt;
  });
  return tools;
}

function scalar(text: string, re: RegExp): string | undefined {
  return text.match(re)?.[1]?.trim();
}
