#!/usr/bin/env node
/**
 * weave-adversary CLI
 *
 *   weave-adversary demo                       run mock corpus (fast, no API)
 *   weave-adversary demo --real                run corpus against a real LLM (NEW v0.2.1)
 *   weave-adversary list                       list attacks (filter via flags)
 *   weave-adversary attack --url=<endpoint>    run corpus against a real browser agent
 *   weave-adversary report <file.json>         re-render saved JSON scorecard
 *   weave-adversary help                       show usage
 */

import { writeFileSync, readFileSync } from 'node:fs';
import { AdversarialAgent } from './agent.js';
import { DemoTarget } from './targets/demo.js';
import { PlaywrightTarget } from './targets/playwright.js';
import { ALL_ATTACKS, ATTACKS_BY_CATEGORY, CORPUS_STATS } from './attacks/index.js';
import { renderMarkdownScorecard, renderJsonScorecard } from './scorecard/index.js';
import { loadWardPolicy } from './ward.js';
import { DEFAULT_MODEL, MODEL_PRICING } from './anthropic.js';
import type { AttackCategory, AttackSeverity, RunOptions, Scorecard } from './types.js';

const args = process.argv.slice(2);
const cmd = args[0];

// ─── Red callout block helper ───────────────────────────────────
function redCallout(title: string, lines: string[]): void {
  const RED_BG = '\x1b[41m\x1b[1;37m';
  const RESET = '\x1b[0m';
  const width = Math.max(title.length + 4, ...lines.map((l) => l.length + 4), 50);
  const top = '┌─ ' + title + ' ' + '─'.repeat(Math.max(0, width - title.length - 4)) + '┐';
  const bot = '└' + '─'.repeat(width) + '┘';
  const pad = (s: string) => '│ ' + s + ' '.repeat(Math.max(0, width - s.length - 2)) + '│';
  console.log('');
  console.log(RED_BG + ' ' + top + ' ' + RESET);
  console.log(RED_BG + ' ' + pad('') + ' ' + RESET);
  for (const l of lines) console.log(RED_BG + ' ' + pad(l) + ' ' + RESET);
  console.log(RED_BG + ' ' + pad('') + ' ' + RESET);
  console.log(RED_BG + ' ' + bot + ' ' + RESET);
  console.log('');
}

function yellowCallout(title: string, lines: string[]): void {
  const YEL = '\x1b[43m\x1b[1;30m';
  const RESET = '\x1b[0m';
  const width = Math.max(title.length + 4, ...lines.map((l) => l.length + 4), 50);
  const top = '┌─ ' + title + ' ' + '─'.repeat(Math.max(0, width - title.length - 4)) + '┐';
  const bot = '└' + '─'.repeat(width) + '┘';
  const pad = (s: string) => '│ ' + s + ' '.repeat(Math.max(0, width - s.length - 2)) + '│';
  console.log('');
  console.log(YEL + ' ' + top + ' ' + RESET);
  console.log(YEL + ' ' + pad('') + ' ' + RESET);
  for (const l of lines) console.log(YEL + ' ' + pad(l) + ' ' + RESET);
  console.log(YEL + ' ' + pad('') + ' ' + RESET);
  console.log(YEL + ' ' + bot + ' ' + RESET);
  console.log('');
}

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
  console.log('    demo                                    Run corpus against built-in mock target');
  console.log('    demo --real                             Run corpus against a real LLM (requires ANTHROPIC_API_KEY) (NEW v0.2.1)');
  console.log('    list                                    List all attacks in the corpus');
  console.log('    attack --url=<agent-endpoint>           Run corpus against a real HTTP agent endpoint');
  console.log('    attack --executable=<path-to-agent>     Run corpus against a CLI agent');
  console.log('    report <file.json>                      Re-render saved JSON scorecard as Markdown');
  console.log('    help                                    Show this message');
  console.log('');
  console.log('  \x1b[1mOptions:\x1b[0m');
  console.log('    --category=<cat>                        Limit to category (ipi|tool_coercion|jailbreak|extraction|goal_corruption)');
  console.log('    --severity=<sev>                        Limit to severity (low|medium|high|critical)');
  console.log('    --stop-on-breach                        Stop after first breach');
  console.log('    --no-ward-aware                         Disable WARD-aware prioritization');
  console.log('    --json=<path>                           Write JSON scorecard to <path>');
  console.log('    --md=<path>                             Write Markdown scorecard to <path>');
  console.log('    --per-category=<n>                      Cap attacks per category at n');
  console.log('    --browser=<chromium|firefox|webkit>     Playwright browser (default: chromium)');
  console.log('    --headed                                Show the browser window');
  console.log('    --real                                  Use real LLM for demo (NEW v0.2.1)');
  console.log('    --model=<model-id>                      LLM model id (default: ' + DEFAULT_MODEL + ')');
  console.log('    --redact-evidence                       Replace breach evidence with [redacted] in scorecard (NEW v0.2.1)');
  console.log('');
  console.log('  \x1b[1mExamples:\x1b[0m');
  console.log('    weave-adversary demo');
  console.log('    weave-adversary demo --real --per-category=3 --json=./run.json');
  console.log('    weave-adversary demo --real --redact-evidence --md=./run.md');
  console.log('    weave-adversary attack --url=https://my-agent.com/run');
  console.log('');
  console.log('  \x1b[1mCorpus:\x1b[0m  ' + CORPUS_STATS.total + ' attacks');
  for (const [cat, n] of Object.entries(CORPUS_STATS.byCategory)) {
    console.log(`    ${cat.padEnd(20)} ${n}`);
  }
  console.log('');
}

function parseFlags(argv: string[]): Record<string, string | boolean> {
  const flags: Record<string, string | boolean> = {};
  for (const a of argv) {
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq > 0) flags[a.slice(2, eq)] = a.slice(eq + 1);
      else flags[a.slice(2)] = true;
    }
  }
  return flags;
}

function buildRunOptionsFromFlags(flags: Record<string, string | boolean>): RunOptions {
  const o: RunOptions = {};
  if (flags.category) o.categories = [flags.category as AttackCategory];
  if (flags.severity) o.severities = [flags.severity as AttackSeverity];
  if (flags['stop-on-breach']) o.stopOnBreach = true;
  if (flags['no-ward-aware']) o.wardAware = false;
  if (flags['per-category']) o.perCategoryLimit = parseInt(String(flags['per-category']), 10);
  return o;
}

/**
 * Mutate findings in-place to redact evidence strings. Used when
 * --redact-evidence is set so sensitive LLM output doesn't leak into
 * shareable scorecards.
 */
function redactScorecard(scorecard: Scorecard): Scorecard {
  for (const f of scorecard.findings) {
    if (f.result !== 'blocked') {
      f.evidence = '[redacted — re-run without --redact-evidence to see]';
    }
    if (f.toolCallsMade) {
      f.toolCallsMade = f.toolCallsMade.map((tc) => ({
        name: tc.name,
        arguments: { _redacted: true },
      }));
    }
  }
  return scorecard;
}

async function cmdDemo() {
  banner();
  const flags = parseFlags(args.slice(1));

  // ── Determine mode ────────────────────────────────────────
  const isReal = !!flags.real || process.env.ADVERSARY_DEMO_MODE === 'real';
  const apiKey = process.env.ANTHROPIC_API_KEY;
  const model = (flags.model as string) || DEFAULT_MODEL;

  // ── Pre-flight check for --real ───────────────────────────
  if (isReal && !apiKey) {
    redCallout('ANTHROPIC_API_KEY not set', [
      'The --real flag uses a live Claude API call for each attack.',
      'That requires an Anthropic API key.',
      '',
      'Get one at https://console.anthropic.com/settings/keys',
      '',
      'Then export it:',
      '',
      '  export ANTHROPIC_API_KEY=sk-ant-...',
      '',
      'And re-run:',
      '',
      '  weave-adversary demo --real',
    ]);
    process.exit(1);
  }

  // ── Cost warning for real mode ────────────────────────────
  if (isReal) {
    const pricing = MODEL_PRICING[model];
    const costPerRun = pricing ? `~$${(pricing.input * 0.04 + pricing.output * 0.06).toFixed(3)}` : 'unknown';
    yellowCallout('Real-LLM mode', [
      'This run will make live Anthropic API calls.',
      '',
      `  Model:               ${model}`,
      `  Estimated cost:      ${costPerRun} per full 68-attack run`,
      `  Sensitive content:   responses may contain mildly adult/illegal content`,
      '                       (jailbreaks produce drug/weapon/exfil instructions)',
      '',
      'To redact breach evidence from the scorecard, add --redact-evidence.',
    ]);
  }

  const ward = loadWardPolicy();
  if (ward.loaded) {
    console.log(`  WARD policy loaded: \x1b[36m${ward.source}\x1b[0m`);
    console.log(`    ${ward.deniedCapabilities.length} denied capabilities · ${ward.deniedUrls.length} denied URLs`);
  } else {
    console.log(`  \x1b[2mNo WARD.md found — running corpus unfiltered\x1b[0m`);
  }
  console.log('');

  let target: DemoTarget;
  try {
    target = new DemoTarget({ mode: isReal ? 'real' : 'mock', model });
  } catch (err) {
    redCallout('Demo target failed to initialize', [(err as Error).message]);
    process.exit(1);
  }

  const agent = new AdversarialAgent(target, { ward });
  const runOpts = buildRunOptionsFromFlags(flags);
  // Real mode: extend the per-attack timeout for live API latency
  if (isReal) runOpts.attackTimeoutMs = runOpts.attackTimeoutMs ?? 45_000;
  const planned = agent.selectAttacks(runOpts);

  console.log(`  Running \x1b[1m${planned.length}\x1b[0m attacks against \x1b[1m${target.identifier}\x1b[0m...`);
  console.log('');

  const t0 = Date.now();
  const scorecard = await agent.run(runOpts);
  const elapsed = ((Date.now() - t0) / 1000).toFixed(1);

  console.log(`  Done in ${elapsed}s.`);

  // ── Real mode: print usage and cost ───────────────────────
  if (isReal) {
    const u = target.getUsage();
    console.log('');
    console.log('  \x1b[1mAPI usage:\x1b[0m');
    console.log(`    Calls:           ${u.apiCalls}${u.errors > 0 ? ` (${u.errors} errors)` : ''}`);
    console.log(`    Input tokens:    ${u.inputTokens.toLocaleString()}`);
    console.log(`    Output tokens:   ${u.outputTokens.toLocaleString()}`);
    console.log(`    Estimated cost:  $${u.estimatedCostUSD.toFixed(4)}`);
    console.log(`    Model:           ${u.model}`);
  }

  printSummary(scorecard);

  // ── Apply redaction if requested ──────────────────────────
  const finalScorecard = flags['redact-evidence'] ? redactScorecard(scorecard) : scorecard;

  emitOutputs(finalScorecard, flags);
}

async function cmdAttack() {
  banner();
  const flags = parseFlags(args.slice(1));

  const url = flags.url as string | undefined;
  const executable = flags.executable as string | undefined;
  if (!url && !executable) {
    redCallout('Missing target', [
      'The "attack" command needs to know where to send the attacks.',
      '',
      'Run one of these:',
      '',
      '  weave-adversary attack --url=https://my-agent.example.com/run',
      '  weave-adversary attack --executable=./my-agent-cli',
      '',
      'For the demo target (no real agent needed), use:',
      '  weave-adversary demo',
    ]);
    process.exit(1);
  }

  try {
    await import('playwright');
  } catch {
    redCallout('Playwright not installed', [
      'The "attack" command drives a real browser via Playwright.',
      '',
      'Run these two commands:',
      '',
      '  npm install playwright',
      '  npx playwright install chromium',
      '',
      'Then re-run:',
      '',
      `  weave-adversary attack ${url ? `--url=${url}` : `--executable=${executable}`}`,
    ]);
    process.exit(1);
  }

  const browserType = (flags.browser as 'chromium' | 'firefox' | 'webkit') || 'chromium';
  const headless = !flags.headed;

  console.log(`  Target: \x1b[1m${url || executable}\x1b[0m`);
  console.log(`  Browser: ${browserType}${headless ? '' : ' (headed)'}`);
  console.log('');

  const target = new PlaywrightTarget({ agentEndpoint: url, executable, browserType, headless });
  const ward = loadWardPolicy();
  const agent = new AdversarialAgent(target, { ward });
  const runOpts = buildRunOptionsFromFlags(flags);
  runOpts.attackTimeoutMs = runOpts.attackTimeoutMs ?? 60_000;

  const planned = agent.selectAttacks(runOpts);
  console.log(`  Running \x1b[1m${planned.length}\x1b[0m attacks. This may take several minutes.`);
  console.log('');

  let scorecard: Scorecard;
  try {
    scorecard = await agent.run(runOpts);
  } catch (err) {
    redCallout('Run failed', [
      `Error: ${(err as Error).message}`,
      '',
      'Common causes:',
      '  • Agent endpoint unreachable or returned errors',
      '  • Playwright browser failed to launch (try --headed)',
      '  • Executable not found or threw at startup',
    ]);
    process.exit(2);
  }

  printSummary(scorecard);

  const finalScorecard = flags['redact-evidence'] ? redactScorecard(scorecard) : scorecard;
  emitOutputs(finalScorecard, flags);
}

function printSummary(scorecard: Scorecard) {
  console.log('');
  console.log(`  \x1b[1mScore:\x1b[0m ${scoreColor(scorecard.summary.score)}  ${scorecard.summary.score}/100`);
  console.log(
    `  \x1b[32m${scorecard.summary.blocked} blocked\x1b[0m · ` +
      `\x1b[33m${scorecard.summary.partial} partial\x1b[0m · ` +
      `\x1b[31m${scorecard.summary.breached} breached\x1b[0m`,
  );
  console.log('');
}

function emitOutputs(scorecard: Scorecard, flags: Record<string, string | boolean>) {
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
    if (cmd === 'demo') return await cmdDemo();
    if (cmd === 'attack') return await cmdAttack();
    if (cmd === 'list') return cmdList();
    if (cmd === 'report') return cmdReport();
    console.error(`Unknown command: ${cmd}`);
    showHelp();
    process.exit(1);
  } catch (err) {
    console.error('Error:', (err as Error).stack || err);
    process.exit(1);
  }
})();
