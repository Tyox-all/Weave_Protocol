#!/usr/bin/env node
/**
 * weave-adversary CLI
 *
 *   weave-adversary demo              run the corpus against the demo target
 *   weave-adversary list              list attacks (filter via --category, --severity)
 *   weave-adversary attack <target>   (v0.2) run against a real target
 *   weave-adversary report <file>     re-render an existing JSON scorecard
 *   weave-adversary help              show this
 */

import { writeFileSync, readFileSync } from 'node:fs';
import { AdversarialAgent } from './agent.js';
import { DemoTarget } from './targets/demo.js';
import { ALL_ATTACKS, ATTACKS_BY_CATEGORY, CORPUS_STATS } from './attacks/index.js';
import { renderMarkdownScorecard, renderJsonScorecard } from './scorecard/index.js';
import { loadWardPolicy } from './ward.js';
import type { AttackCategory, AttackSeverity, RunOptions, Scorecard } from './types.js';

const args = process.argv.slice(2);
const cmd = args[0];

function banner() {
  console.log('');
  console.log('  ⚔️   \x1b[1mweave-adversary\x1b[0m');
  console.log('  Offensive engine for AI agent security testing');
  console.log('');
}

function showHelp() {
  banner();
  console.log('  \x1b[1mUsage:\x1b[0m  weave-adversary <command> [options]');
  console.log('');
  console.log('  \x1b[1mCommands:\x1b[0m');
  console.log('    demo                    Run the full corpus against the built-in vulnerable demo agent');
  console.log('    list                    List all attacks in the corpus');
  console.log('    report <file.json>      Re-render a saved JSON scorecard as Markdown');
  console.log('    help                    Show this message');
  console.log('');
  console.log('  \x1b[1mOptions:\x1b[0m');
  console.log('    --category=<cat>        Limit to one category (ipi|tool_coercion|jailbreak|extraction|goal_corruption)');
  console.log('    --severity=<sev>        Limit to one severity (low|medium|high|critical)');
  console.log('    --stop-on-breach        Stop after the first breach (faster for "is anything broken")');
  console.log('    --no-ward-aware         Disable WARD-aware prioritization');
  console.log('    --json=<path>           Write JSON scorecard to <path>');
  console.log('    --md=<path>             Write Markdown scorecard to <path> (default: stdout)');
  console.log('    --per-category=<n>      Cap attacks per category at n');
  console.log('');
  console.log('  \x1b[1mExamples:\x1b[0m');
  console.log('    weave-adversary demo');
  console.log('    weave-adversary demo --category=ipi --json=./scorecard.json');
  console.log('    weave-adversary list --severity=critical');
  console.log('');
  console.log('  \x1b[1mCorpus:\x1b[0m  ' + CORPUS_STATS.total + ' attacks');
  for (const [cat, n] of Object.entries(CORPUS_STATS.byCategory)) {
    console.log(`    ${cat.padEnd(20)} ${n}`);
  }
  console.log('');
  console.log('  Docs:  https://github.com/Tyox-all/Weave_Protocol/tree/main/adversary');
  console.log('');
}

function parseFlags(argv: string[]): Record<string, string | boolean> {
  const flags: Record<string, string | boolean> = {};
  for (const a of argv) {
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq > 0) {
        flags[a.slice(2, eq)] = a.slice(eq + 1);
      } else {
        flags[a.slice(2)] = true;
      }
    }
  }
  return flags;
}

async function cmdDemo() {
  banner();
  const flags = parseFlags(args.slice(1));

  const ward = loadWardPolicy();
  if (ward.loaded) {
    console.log(`  WARD policy loaded: \x1b[36m${ward.source}\x1b[0m`);
    console.log(`    ${ward.deniedCapabilities.length} denied capabilities · ${ward.deniedUrls.length} denied URLs`);
  } else {
    console.log(`  \x1b[2mNo WARD.md found — running corpus unfiltered\x1b[0m`);
  }
  console.log('');

  const target = new DemoTarget();
  const agent = new AdversarialAgent(target, { ward });

  const runOpts: RunOptions = {};
  if (flags.category) runOpts.categories = [flags.category as AttackCategory];
  if (flags.severity) runOpts.severities = [flags.severity as AttackSeverity];
  if (flags['stop-on-breach']) runOpts.stopOnBreach = true;
  if (flags['no-ward-aware']) runOpts.wardAware = false;
  if (flags['per-category']) runOpts.perCategoryLimit = parseInt(String(flags['per-category']), 10);

  const planned = agent.selectAttacks(runOpts);
  console.log(`  Running \x1b[1m${planned.length}\x1b[0m attacks against \x1b[1m${target.identifier}\x1b[0m...`);
  console.log('');

  const t0 = Date.now();
  const scorecard = await agent.run(runOpts);
  const elapsed = ((Date.now() - t0) / 1000).toFixed(1);

  console.log(`  Done in ${elapsed}s.`);
  console.log('');
  console.log(`  \x1b[1mScore:\x1b[0m ${scoreColor(scorecard.summary.score)}  ${scorecard.summary.score}/100`);
  console.log(
    `  \x1b[32m${scorecard.summary.blocked} blocked\x1b[0m · ` +
      `\x1b[33m${scorecard.summary.partial} partial\x1b[0m · ` +
      `\x1b[31m${scorecard.summary.breached} breached\x1b[0m`,
  );
  console.log('');

  // Write outputs
  if (flags.json) {
    writeFileSync(String(flags.json), renderJsonScorecard(scorecard));
    console.log(`  Wrote JSON: ${flags.json}`);
  }

  const md = renderMarkdownScorecard(scorecard);
  if (flags.md) {
    writeFileSync(String(flags.md), md);
    console.log(`  Wrote Markdown: ${flags.md}`);
  } else if (!flags.json) {
    console.log('  \x1b[2m─── Markdown scorecard ───────────────────────────────────\x1b[0m');
    console.log('');
    console.log(md);
  }
}

function cmdList() {
  banner();
  const flags = parseFlags(args.slice(1));
  let pool = ALL_ATTACKS;
  if (flags.category) pool = pool.filter((a) => a.category === flags.category);
  if (flags.severity) pool = pool.filter((a) => a.severity === flags.severity);

  console.log(`  ${pool.length} attacks ${flags.category || flags.severity ? '(filtered)' : ''}`);
  console.log('');
  for (const a of pool) {
    const sev = `[${a.severity.toUpperCase()}]`.padEnd(10);
    console.log(`  ${sevColor(a.severity)}${sev}\x1b[0m ${a.id.padEnd(40)} ${a.name}`);
  }
  console.log('');
}

function cmdReport() {
  const path = args[1];
  if (!path) {
    console.error('Usage: weave-adversary report <file.json>');
    process.exit(1);
  }
  const scorecard: Scorecard = JSON.parse(readFileSync(path, 'utf8'));
  console.log(renderMarkdownScorecard(scorecard));
}

function scoreColor(n: number): string {
  if (n >= 90) return '\x1b[42m\x1b[30m';
  if (n >= 70) return '\x1b[43m\x1b[30m';
  if (n >= 50) return '\x1b[41m\x1b[37m';
  return '\x1b[41m\x1b[37m';
}

function sevColor(sev: string): string {
  switch (sev) {
    case 'critical': return '\x1b[31m';
    case 'high': return '\x1b[33m';
    case 'medium': return '\x1b[36m';
    default: return '\x1b[2m';
  }
}

(async () => {
  try {
    if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') {
      showHelp();
      return;
    }
    if (cmd === 'demo') {
      await cmdDemo();
      return;
    }
    if (cmd === 'list') {
      cmdList();
      return;
    }
    if (cmd === 'report') {
      cmdReport();
      return;
    }
    if (cmd === 'attack') {
      console.error('`weave-adversary attack <target>` is planned for v0.2 (Claude Code / MSAF / Antigravity adapters).');
      console.error('For now, use `weave-adversary demo` to see the corpus in action.');
      process.exit(1);
    }
    console.error(`Unknown command: ${cmd}`);
    showHelp();
    process.exit(1);
  } catch (err) {
    console.error('Error:', (err as Error).stack || err);
    process.exit(1);
  }
})();
