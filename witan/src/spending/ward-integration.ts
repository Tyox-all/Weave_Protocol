/**
 * WARD.md → SpendingCap[] parser.
 *
 * Reads the `spending_limits:` YAML section from a WARD.md file and
 * translates it into structured SpendingCap objects.
 *
 * Also handles backward-compat: if `behavioral_limits.maxCostUSD` is
 * present (v0.1 WARD spec), it becomes a run-window USD cap with
 * onExceeded=block.
 *
 * WARD extension shape (v0.2 addition, backward compatible):
 *
 *   spending_limits:
 *     - window: day
 *       budget:
 *         usd: 5.00
 *       on_exceeded: require_approval
 *     - window: run
 *       budget:
 *         tool_calls: 100
 *       on_exceeded: block
 *     - window: day
 *       budget:
 *         tools:
 *           send_payment:
 *             max_amount_usd: 500
 *       on_exceeded: require_approval
 */

import type { SpendingCap, CapAction, SpendingWindow } from './types.js';

/**
 * Parse spending caps out of a WARD.md text string.
 * Uses a lightweight YAML-block extractor rather than pulling in a full
 * YAML dependency — WARD.md's spending_limits section has a stable shape.
 */
export function parseSpendingCapsFromWard(text: string): SpendingCap[] {
  const caps: SpendingCap[] = [];

  // Extract the spending_limits: block
  // Match from `spending_limits:` (at line start) up to the next top-level
  // YAML key (a line starting with a letter at column 0) or end of file.
  const blockMatch = text.match(/(?:^|\n)spending_limits:\s*\n([\s\S]*?)(?=\n[a-zA-Z_][a-zA-Z0-9_-]*:|$)/);
  if (blockMatch) {
    const block = blockMatch[1];
    caps.push(...parseSpendingBlock(block));
  }

  // Legacy: behavioral_limits.maxCostUSD → run window USD cap
  const legacyMatch = text.match(/maxCostUSD:\s*([\d.]+)/);
  if (legacyMatch) {
    const usd = parseFloat(legacyMatch[1]);
    // Only add if no explicit spending_limits was defined
    if (caps.length === 0 && Number.isFinite(usd)) {
      caps.push({
        window: 'run',
        budget: { usd },
        onExceeded: 'block',
        label: 'legacy maxCostUSD',
      });
    }
  }

  return caps;
}

function parseSpendingBlock(block: string): SpendingCap[] {
  const caps: SpendingCap[] = [];
  // Split on `- window:` boundaries (each item starts with a `-`)
  const items = block.split(/\n\s*-\s+/).filter((s) => s.trim());
  for (const item of items) {
    const cap = parseSpendingItem(item);
    if (cap) caps.push(cap);
  }
  return caps;
}

function parseSpendingItem(item: string): SpendingCap | null {
  const window = matchScalar(item, /window:\s*(\w+)/) as SpendingWindow | undefined;
  const onExceeded = matchScalar(item, /on_exceeded:\s*(\w+)/) as CapAction | undefined;
  const label = matchScalar(item, /label:\s*["']?([^"'\n]+)["']?/);
  const scope = matchScalar(item, /scope:\s*["']?([^"'\n]+)["']?/);

  if (!window || !onExceeded) return null;
  if (!['run', 'hour', 'day', 'week', 'month'].includes(window)) return null;
  if (!['block', 'require_approval', 'notify'].includes(onExceeded)) return null;

  const usd = parseFloat(matchScalar(item, /(?:^|\s)usd:\s*([\d.]+)/) || '');
  const tokens = parseInt(matchScalar(item, /(?:^|\s)tokens:\s*(\d+)/) || '', 10);
  const toolCalls = parseInt(matchScalar(item, /(?:^|\s)tool_calls:\s*(\d+)/) || '', 10);

  const budget: SpendingCap['budget'] = {};
  if (Number.isFinite(usd)) budget.usd = usd;
  if (Number.isFinite(tokens)) budget.tokens = tokens;
  if (Number.isFinite(toolCalls)) budget.tool_calls = toolCalls;

  // Per-tool budgets — a nested structure under tools:
  const toolsBlock = item.match(/tools:\s*\n([\s\S]*?)(?=\n\s{2,6}(?:on_exceeded|label|scope):|$)/);
  if (toolsBlock) {
    budget.tools = parseToolsBlock(toolsBlock[1]);
    // If we found per-tool budgets, and the item didn't have a top-level usd
    // outside the tools block, un-set the accidental capture from within.
    if (Object.keys(budget.tools).length > 0 && !/^\s*budget:\s*\n\s*usd:/m.test(item)) {
      // Recompute: only consider `usd:` lines NOT inside the tools: block
      const preTools = item.slice(0, item.indexOf('tools:'));
      const outerUsd = parseFloat(matchScalar(preTools, /(?:^|\s)usd:\s*([\d.]+)/) || '');
      if (!Number.isFinite(outerUsd)) delete budget.usd;
    }
  }

  return {
    window,
    budget,
    onExceeded,
    ...(label ? { label } : {}),
    ...(scope ? { scope } : {}),
  };
}

function parseToolsBlock(block: string): Record<string, { max_amount_usd?: number; max_calls?: number }> {
  const tools: Record<string, { max_amount_usd?: number; max_calls?: number }> = {};
  // Match each `<name>:` header followed by its nested fields.
  // A tool starts with `<name>:` at some indent; the next tool starts at
  // the same or shallower indent. We use a pragmatic pattern: each tool
  // header is a word ending in `:` at line start (with any indent), and
  // the body is everything up to the next such header or end.
  const toolHeaderRe = /(?:^|\n)(\s*)(\w+):\s*\n/g;
  const headers: Array<{ name: string; indent: number; bodyStart: number }> = [];
  let m: RegExpExecArray | null;
  while ((m = toolHeaderRe.exec(block)) !== null) {
    headers.push({
      name: m[2],
      indent: m[1].length,
      bodyStart: m.index + m[0].length,
    });
  }
  if (headers.length === 0) return tools;
  // Filter to top-level tool headers (shallowest indent seen)
  const minIndent = Math.min(...headers.map((h) => h.indent));
  const topLevel = headers.filter((h) => h.indent === minIndent);
  for (let i = 0; i < topLevel.length; i++) {
    const h = topLevel[i];
    const nextStart = i + 1 < topLevel.length ? topLevel[i + 1].bodyStart - 0 : block.length;
    const body = block.slice(h.bodyStart, nextStart);
    const amt = parseFloat(matchScalar(body, /max_amount_usd:\s*([\d.]+)/) || '');
    const cnt = parseInt(matchScalar(body, /max_calls:\s*(\d+)/) || '', 10);
    tools[h.name] = {};
    if (Number.isFinite(amt)) tools[h.name].max_amount_usd = amt;
    if (Number.isFinite(cnt)) tools[h.name].max_calls = cnt;
  }
  return tools;
}

function matchScalar(text: string, re: RegExp): string | undefined {
  const m = text.match(re);
  return m ? m[1].trim() : undefined;
}

/**
 * Load and parse spending caps from a WARD.md file path.
 * Returns [] if the file doesn't exist or has no spending section.
 */
export function loadSpendingCapsFromWardFile(filepath: string): SpendingCap[] {
  try {
    const fs = require('node:fs') as typeof import('node:fs');
    if (!fs.existsSync(filepath)) return [];
    const text = fs.readFileSync(filepath, 'utf8');
    return parseSpendingCapsFromWard(text);
  } catch {
    return [];
  }
}
