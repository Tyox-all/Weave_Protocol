#!/usr/bin/env node
/**
 * agentsecbench CLI
 *
 *   agentsecbench run --suite=<id>       run a suite against the built-in demo target
 *   agentsecbench compare a.json b.json  diff two reports
 *   agentsecbench suite [id]             list suites or show suite manifest
 *   agentsecbench help                   show usage
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { DemoTarget } from '@weave_protocol/adversary';
import { runSuite } from './runner.js';
import { renderMarkdownReport, renderJsonReport } from './report/index.js';
import {
  compareReports,
  renderMarkdownComparison,
  renderJsonComparison,
} from './compare/index.js';
import { SUITES, getSuite, listSuites } from './suites/index.js';
import type { Report } from './types.js';

const args = process.argv.slice(2);
const cmd = args[0];

function banner() {
  console.log('');
  console.log('  🎯  \x1b[1magentsecbench\x1b[0m');
  console.log('  Standardized AI agent security benchmark');
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

function showHelp() {
  banner();
  console.log('  \x1b[1mUsage:\x1b[0m  agentsecbench <command> [options]');
  console.log('');
  console.log('  \x1b[1mCommands:\x1b[0m');
  console.log('    run                    Run a suite against the built-in demo target');
  console.log('    compare <a> <b>        Diff two JSON reports — A is baseline, B is new');
  console.log('    suite [id]             List suites, or print manifest for one');
  console.log('    help                   This message');
  console.log('');
  console.log('  \x1b[1mOptions for run:\x1b[0m');
  console.log('    --suite=<id>           Suite to run (default: ASB-Browser-v1)');
  console.log('    --name=<name>          Target display name (default: "demo")');
  console.log('    --vendor=<name>        Optional vendor name');
  console.log('    --anonymize            Mark report as anonymized');
  console.log('    --measure-ward-delta   Also run without WARD for delta analysis');
  console.log('    --json=<path>          Write JSON report to <path>');
  console.log('    --md=<path>            Write Markdown report to <path> (default: stdout)');
  console.log('');
  console.log('  \x1b[1mExamples:\x1b[0m');
  console.log('    agentsecbench run');
  console.log('    agentsecbench run --suite=ASB-Browser-v1 --measure-ward-delta --json=report.json');
  console.log('    agentsecbench compare baseline.json new.json --md=diff.md');
  console.log('    agentsecbench suite ASB-Browser-v1');
  console.log('');
  console.log('  \x1b[1mSuites:\x1b[0m');
  for (const s of listSuites()) {
    console.log(`    ${s.id.padEnd(24)} ${s.name} (${s.attackIds.length} attacks)`);
  }
  console.log('');
}

async function cmdRun() {
  banner();
  const flags = parseFlags(args.slice(1));
  const suiteId = (flags.suite as string) || 'ASB-Browser-v1';
  const suite = getSuite(suiteId);
  if (!suite) {
    console.error(`Unknown suite: ${suiteId}`);
    console.error(`Available: ${Object.keys(SUITES).join(', ')}`);
    process.exit(1);
  }

  console.log(`  Suite: \x1b[1m${suite.id}\x1b[0m v${suite.version} (${suite.attackIds.length} attacks)`);
  console.log(`  Target: \x1b[1m${(flags.name as string) || 'demo:vulnerable-agent'}\x1b[0m`);
  if (flags['measure-ward-delta']) console.log('  Mode: measuring WARD delta (will run twice)');
  console.log('');

  const target = new DemoTarget();
  const report = await runSuite({
    target,
    suite,
    targetMeta: {
      name: (flags.name as string) || target.identifier,
      vendor: flags.vendor as string | undefined,
      type: 'demo:browser-mock',
      anonymized: !!flags.anonymize,
      configuration: {},
    },
    measureWardDelta: !!flags['measure-ward-delta'],
  });

  console.log(`  Tier: \x1b[1m${report.result.tier}\x1b[0m · Score: \x1b[1m${report.result.score}\x1b[0m / 100`);
  console.log(`  ${report.result.blocked} blocked · ${report.result.partial} partial · ${report.result.breached} breached`);
  console.log('');

  if (flags.json) {
    writeFileSync(String(flags.json), renderJsonReport(report));
    console.log(`  Wrote JSON: ${flags.json}`);
  }

  const md = renderMarkdownReport(report);
  if (flags.md) {
    writeFileSync(String(flags.md), md);
    console.log(`  Wrote Markdown: ${flags.md}`);
  } else if (!flags.json) {
    console.log('  \x1b[2m─── Markdown report ──────────────────────────────────────\x1b[0m');
    console.log('');
    console.log(md);
  }
}

function cmdCompare() {
  const aPath = args[1];
  const bPath = args[2];
  if (!aPath || !bPath) {
    console.error('Usage: agentsecbench compare <a.json> <b.json>');
    process.exit(1);
  }
  const flags = parseFlags(args.slice(3));

  const a: Report = JSON.parse(readFileSync(aPath, 'utf8'));
  const b: Report = JSON.parse(readFileSync(bPath, 'utf8'));

  const cmp = compareReports(a, b);

  if (flags.json) {
    writeFileSync(String(flags.json), renderJsonComparison(cmp));
    console.log(`Wrote JSON: ${flags.json}`);
  }

  const md = renderMarkdownComparison(cmp);
  if (flags.md) {
    writeFileSync(String(flags.md), md);
    console.log(`Wrote Markdown: ${flags.md}`);
  } else if (!flags.json) {
    console.log(md);
  }
}

function cmdSuite() {
  banner();
  const id = args[1];
  if (!id) {
    console.log('  \x1b[1mAvailable suites:\x1b[0m');
    console.log('');
    for (const s of listSuites()) {
      console.log(`    \x1b[1m${s.id}\x1b[0m v${s.version}`);
      console.log(`      ${s.name}`);
      console.log(`      ${s.attackIds.length} attacks · target type: ${s.targetType}`);
      console.log('');
    }
    return;
  }
  const suite = getSuite(id);
  if (!suite) {
    console.error(`Unknown suite: ${id}`);
    process.exit(1);
  }
  console.log(`  \x1b[1m${suite.id}\x1b[0m v${suite.version}`);
  console.log(`  ${suite.name}`);
  console.log('');
  console.log(`  ${suite.description}`);
  console.log('');
  console.log(`  Target type: ${suite.targetType}`);
  console.log(`  Adversary compat: v${suite.adversaryCompatVersion}`);
  console.log(`  Attacks: ${suite.attackIds.length}`);
  console.log('');
  console.log('  Tier thresholds:');
  console.log(`    A (>= ${suite.tierThresholds.A})`);
  console.log(`    B (>= ${suite.tierThresholds.B})`);
  console.log(`    C (>= ${suite.tierThresholds.C})`);
  console.log(`    D (>= ${suite.tierThresholds.D})`);
  console.log(`    F (< ${suite.tierThresholds.D})`);
  console.log('');
  console.log('  Trophy attacks:');
  for (const t of suite.trophyAttacks) {
    console.log(`    - ${t.name} (${t.context})`);
  }
  console.log('');
  console.log('  Attack IDs:');
  for (const id of suite.attackIds) {
    console.log(`    - ${id}`);
  }
  console.log('');
}

(async () => {
  try {
    if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') {
      showHelp();
      return;
    }
    if (cmd === 'run') {
      await cmdRun();
      return;
    }
    if (cmd === 'compare') {
      cmdCompare();
      return;
    }
    if (cmd === 'suite' || cmd === 'suites') {
      cmdSuite();
      return;
    }
    console.error(`Unknown command: ${cmd}`);
    showHelp();
    process.exit(1);
  } catch (err) {
    console.error('Error:', (err as Error).stack || err);
    process.exit(1);
  }
})();
