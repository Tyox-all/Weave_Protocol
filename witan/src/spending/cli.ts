#!/usr/bin/env node
/**
 * weave-witan-spending — CLI for the autonomous spending caps module.
 *
 * This is invoked either as a standalone command or via the parent
 * witan CLI as `weave-witan spending <subcommand>`.
 *
 * Subcommands:
 *
 *   status   Show current window usage vs configured caps
 *   caps     Print the caps parsed from WARD.md
 *   reset    Reset counters for a window (in-memory only in v1.1)
 *   simulate Dry-run: given a scenario, print what would trigger
 *
 * Note: because v1.1 uses in-memory storage, `status` and `reset` only make
 * sense within a long-lived process. For CI/one-shot testing use the
 * programmatic API. v1.2 will add persistent stores that make CLI state
 * queries meaningful across invocations.
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { SpendingTracker } from './tracker.js';
import { loadSpendingCapsFromWardFile } from './ward-integration.js';
import type { SpendingCap, ProposedAction } from './types.js';

const args = process.argv.slice(2);
const cmd = args[0];

function banner() {
  console.log('');
  console.log('  💰  \x1b[1mweave-witan spending\x1b[0m');
  console.log('  Autonomous spending caps for AI agents');
  console.log('');
}

function findWardFile(): string | undefined {
  const candidates = [
    process.env.WEAVE_WARD_PATH,
    join(process.cwd(), 'WARD.md'),
    join(process.cwd(), '.weave', 'WARD.md'),
  ].filter(Boolean) as string[];
  return candidates.find((p) => existsSync(p));
}

function showHelp() {
  banner();
  console.log('  Usage:  weave-witan spending <subcommand> [options]');
  console.log('');
  console.log('  Subcommands:');
  console.log('    status                  Show current usage vs configured caps');
  console.log('    caps                    Print caps parsed from WARD.md');
  console.log('    simulate --scenario=X   Dry-run a scenario, show what would trigger');
  console.log('    reset [--window=X]      Reset counters (in-memory session only)');
  console.log('    help                    This message');
  console.log('');
  console.log('  Scenarios for `simulate`:');
  console.log('    llm-run                 Simulate 100 LLM calls at avg cost');
  console.log('    payment-1000            Simulate a $1000 payment via send_payment');
  console.log('    tool-flood              Simulate 1000 tool calls');
  console.log('');
}

function cmdCaps() {
  banner();
  const ward = findWardFile();
  if (!ward) {
    console.log('  \x1b[2mNo WARD.md found in cwd or $WEAVE_WARD_PATH.\x1b[0m');
    console.log('');
    console.log('  Create a WARD.md with a spending_limits: section, e.g.:');
    console.log('');
    console.log('    spending_limits:');
    console.log('      - window: day');
    console.log('        budget:');
    console.log('          usd: 5.00');
    console.log('        on_exceeded: require_approval');
    console.log('');
    return;
  }
  console.log(`  WARD.md: \x1b[36m${ward}\x1b[0m`);
  console.log('');

  const caps = loadSpendingCapsFromWardFile(ward);
  if (caps.length === 0) {
    console.log('  \x1b[2mNo spending_limits section found in WARD.md.\x1b[0m');
    return;
  }
  console.log(`  \x1b[1m${caps.length} caps loaded:\x1b[0m`);
  console.log('');
  for (const cap of caps) {
    printCap(cap);
  }
  console.log('');
}

function printCap(cap: SpendingCap) {
  const label = cap.label || `${cap.window} cap`;
  const budget: string[] = [];
  if (cap.budget.usd !== undefined) budget.push(`$${cap.budget.usd.toFixed(2)}`);
  if (cap.budget.tokens !== undefined) budget.push(`${cap.budget.tokens.toLocaleString()} tokens`);
  if (cap.budget.tool_calls !== undefined) budget.push(`${cap.budget.tool_calls} tool calls`);
  if (cap.budget.tools) {
    for (const [name, tb] of Object.entries(cap.budget.tools)) {
      const parts = [];
      if (tb.max_amount_usd !== undefined) parts.push(`≤$${tb.max_amount_usd.toFixed(2)}`);
      if (tb.max_calls !== undefined) parts.push(`≤${tb.max_calls} calls`);
      budget.push(`${name}(${parts.join(', ')})`);
    }
  }
  const actionColor = cap.onExceeded === 'block' ? '\x1b[31m' : cap.onExceeded === 'require_approval' ? '\x1b[33m' : '\x1b[36m';
  console.log(`  ${actionColor}${cap.onExceeded.padEnd(20)}\x1b[0m ${cap.window.padEnd(8)} ${budget.join(', ')}  \x1b[2m${label}\x1b[0m`);
}

async function cmdSimulate() {
  banner();
  const ward = findWardFile();
  if (!ward) {
    console.log('  Need a WARD.md with spending_limits to simulate.');
    return;
  }
  const caps = loadSpendingCapsFromWardFile(ward);
  if (caps.length === 0) {
    console.log('  No spending caps in WARD.md.');
    return;
  }

  const flags = parseFlags();
  const scenario = (flags.scenario as string) || 'llm-run';

  console.log(`  Simulating: \x1b[1m${scenario}\x1b[0m against ${caps.length} caps`);
  console.log('');

  const tracker = new SpendingTracker({ caps, approvalHandler: async () => false });

  const results: Array<{ label: string; check: any }> = [];
  const actions = buildScenarioActions(scenario);
  for (const [label, action] of actions) {
    const check = await tracker.checkAction(action);
    results.push({ label, check });
    if (check.blocked || check.requiresApproval) {
      console.log(`  ${check.blocked ? '\x1b[31mblocked\x1b[0m' : '\x1b[33mapproval\x1b[0m'}  ${label}`);
      for (const v of check.violations) console.log(`             ${v.reason}`);
    } else {
      console.log(`  \x1b[32mallowed\x1b[0m   ${label}`);
    }
    // Record the action's effect so subsequent iterations see accumulated state
    if (action.kind === 'llm') {
      await tracker.recordLLM({
        provider: action.provider,
        model: action.model,
        inputTokens: action.estInputTokens,
        outputTokens: action.estOutputTokens,
      });
    } else {
      await tracker.recordTool({ tool: action.tool, args: action.args, amountUSD: action.amountUSD });
    }
  }
  console.log('');
  const blocked = results.filter((r) => r.check.blocked).length;
  const approval = results.filter((r) => r.check.requiresApproval && !r.check.blocked).length;
  console.log(`  Summary:  ${results.length - blocked - approval} allowed  ·  ${approval} approval  ·  ${blocked} blocked`);
  console.log('');
}

function buildScenarioActions(scenario: string): Array<[string, ProposedAction]> {
  const items: Array<[string, ProposedAction]> = [];
  if (scenario === 'llm-run') {
    for (let i = 0; i < 100; i++) {
      items.push([
        `LLM call #${i + 1} (haiku, 500+300 tok)`,
        { kind: 'llm', provider: 'anthropic', model: 'claude-3-5-haiku-20241022', estInputTokens: 500, estOutputTokens: 300 },
      ]);
    }
  } else if (scenario === 'payment-1000') {
    items.push([
      'send_payment $1000',
      { kind: 'tool', tool: 'send_payment', args: { amount: 1000, recipient: 'someone@example.com' }, amountUSD: 1000 },
    ]);
  } else if (scenario === 'tool-flood') {
    for (let i = 0; i < 1000; i++) {
      items.push([
        `tool call #${i + 1} (http_request)`,
        { kind: 'tool', tool: 'http_request', args: {} },
      ]);
    }
  }
  return items;
}

function parseFlags(): Record<string, string | boolean> {
  const flags: Record<string, string | boolean> = {};
  for (const a of args.slice(1)) {
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq > 0) flags[a.slice(2, eq)] = a.slice(eq + 1);
      else flags[a.slice(2)] = true;
    }
  }
  return flags;
}

(async () => {
  try {
    if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') return showHelp();
    if (cmd === 'caps') return cmdCaps();
    if (cmd === 'simulate') return await cmdSimulate();
    if (cmd === 'status' || cmd === 'reset') {
      console.log(`  \x1b[2mNote: v1.1 uses in-memory storage; '${cmd}' is only meaningful in long-lived processes.\x1b[0m`);
      console.log(`  \x1b[2mUse the programmatic API for scripted use. v1.2 will add persistent storage.\x1b[0m`);
      return;
    }
    console.log(`Unknown subcommand: ${cmd}`);
    showHelp();
    process.exit(1);
  } catch (err) {
    console.error('Error:', (err as Error).stack || err);
    process.exit(1);
  }
})();
