#!/usr/bin/env node
/**
 * weave-adversary CLI
 *
 *   weave-adversary demo                       run mock corpus (fast, no API)
 *   weave-adversary demo --real                run corpus against a real LLM (NEW v0.2.1)
 *   weave-adversary providers                  list model providers (NEW v0.4)
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
import { DEFAULT_MODEL } from './anthropic.js';
import { PROVIDERS, resolveModelConfig, estimateModelCost, type ModelConfig } from './providers.js';
import { DynamicAttackMutator } from './dynamic.js';
import { redactScorecard } from './scorecard/redact.js';
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

function fmtCost(usd: number | null, digits = 4): string {
  return usd === null ? 'unknown (no price on file for this model)' : `$${usd.toFixed(digits)}`;
}

/** Resolve a provider/model pair from flags, or exit with an actionable callout. */
function resolveOrExit(title: string, provider: string | undefined, model: string | undefined, flags: Record<string, string | boolean>): ModelConfig {
  try {
    return resolveModelConfig({
      provider,
      model,
      baseUrl: flags['base-url'] as string | undefined,
      reasoningEffort: flags['reasoning-effort'] as string | undefined,
      rpm: flags.rpm ? Number(flags.rpm) : undefined,
    });
  } catch (err) {
    redCallout(title, [
      (err as Error).message,
      '',
      'Keys go in your shell profile, for example:',
      '',
      '  export ANTHROPIC_API_KEY=...      (default provider)',
      '  export GEMINI_API_KEY=...         (--provider=gemini --model=<id>)',
      '',
      'See all providers and their key variables:',
      '',
      '  weave-adversary providers',
    ]);
    process.exit(1);
  }
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
  console.log('    demo --real                             Run corpus against a real LLM (any provider; see "providers")');
  console.log('    providers                               List model providers and their key variables (NEW v0.4)');
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
  console.log('    --real                                  Use real LLM for demo (v0.2.1)');
  console.log('    --provider=<id>                         Model provider (default: anthropic; see "providers") (v0.4)');
  console.log('    --model=<model-id>                      Target LLM model id (default: ' + DEFAULT_MODEL + ' on anthropic)');
  console.log('    --base-url=<url>                        Override the provider endpoint (self-hosted, regional) (v0.4)');
  console.log('    --reasoning-effort=<level>              reasoning_effort for OpenAI-compatible thinking models (v0.4)');
  console.log('    --rpm=<n>                               Stay under n requests per minute (free tiers) (v0.4)');
  console.log('    --redact-evidence                       Replace breach evidence with [redacted] in scorecard (v0.2.1)');
  console.log('    --dynamic                               NEW v0.3: LLM-driven mutations when target half-blocks');
  console.log('    --dynamic-provider=<id>                 Mutation LLM provider (default: same as --provider)');
  console.log('    --dynamic-model=<model-id>              Mutation LLM (default: same as --model)');
  console.log('    --dynamic-max-retries=<n>               Variant retries per half-blocked attack (default: 2)');
  console.log('');
  console.log('  \x1b[1mExamples:\x1b[0m');
  console.log('    weave-adversary demo');
  console.log('    weave-adversary demo --real --per-category=3 --json=./run.json');
  console.log('    weave-adversary demo --real --provider=gemini --model=gemini-3.5-flash --per-category=3 --rpm=5');
  console.log('    weave-adversary demo --real --provider=ollama --model=qwen2.5-coder:7b');
  console.log('    weave-adversary demo --real --dynamic --json=./run.json');
  console.log('    weave-adversary demo --real --redact-evidence --md=./run.md');
  console.log('    weave-adversary attack --url=https://my-agent.com/run --dynamic');
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
  if (flags.dynamic) o.dynamic = true;
  return o;
}

async function cmdDemo() {
  banner();
  const flags = parseFlags(args.slice(1));

  // ── Determine mode ────────────────────────────────────────
  const isReal = !!flags.real || process.env.ADVERSARY_DEMO_MODE === 'real';
  const isDynamic = !!flags.dynamic;
  const provider = flags.provider as string | undefined;
  const model = flags.model as string | undefined;
  const dynamicProvider = (flags['dynamic-provider'] as string) || provider;
  // Reuse the target model only when the mutator uses the same provider
  const dynamicModel = (flags['dynamic-model'] as string) || (dynamicProvider === provider ? model : undefined);
  const dynamicMaxRetries = flags['dynamic-max-retries']
    ? parseInt(String(flags['dynamic-max-retries']), 10)
    : 2;

  // ── Pre-flight: provider, model and key ───────────────────
  const targetCfg = isReal ? resolveOrExit('Cannot run --real', provider, model, flags) : undefined;
  const mutatorCfg = isDynamic ? resolveOrExit('Cannot run --dynamic', dynamicProvider, dynamicModel, flags) : undefined;

  // ── Cost warning for real mode ────────────────────────────
  if (targetCfg) {
    const est = estimateModelCost(targetCfg, 40_000, 60_000);
    yellowCallout('Real-LLM mode', [
      `This run will make live ${PROVIDERS[targetCfg.provider].label} API calls.`,
      '',
      `  Model:               ${targetCfg.provider}/${targetCfg.model}`,
      `  Estimated cost:      ${est === null ? 'unknown' : `~$${est.toFixed(3)}`} per full 68-attack run`,
      `  Sensitive content:   responses may contain mildly adult/illegal content`,
      '                       (jailbreaks produce drug/weapon/exfil instructions)',
      '',
      'To redact breach evidence from the scorecard, add --redact-evidence.',
    ]);
  }

  // ── Cost warning for dynamic mode ─────────────────────────
  if (mutatorCfg) {
    const est = estimateModelCost(mutatorCfg, 60_000, 40_000);
    const mutationCostPerRun = est === null ? 'unknown' : `~$${(est * dynamicMaxRetries).toFixed(3)}`;
    yellowCallout('Dynamic-mutation mode', [
      'When the target half-blocks an attack, an LLM will synthesize a',
      'novel variant of the payload and Adversary will retry.',
      '',
      `  Mutation model:      ${mutatorCfg.provider}/${mutatorCfg.model}`,
      `  Max retries/attack:  ${dynamicMaxRetries}`,
      `  Est. mutation cost:  ${mutationCostPerRun} on top of any --real target cost`,
      '',
      'Corpus is unchanged. Dynamic mode is a RETRY mechanism, not a',
      'replacement for the 68-attack corpus. Per-attempt detail lives in',
      'Finding.attempts[]; scorecard schema v1.0 preserved.',
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
    target = new DemoTarget(targetCfg ? { mode: 'real', ...targetCfg } : { mode: 'mock' });
  } catch (err) {
    redCallout('Demo target failed to initialize', [(err as Error).message]);
    process.exit(1);
  }

  // ── Instantiate mutator if dynamic mode ───────────────────
  let mutator: DynamicAttackMutator | undefined;
  if (mutatorCfg) {
    try {
      mutator = new DynamicAttackMutator({ ...mutatorCfg, maxRetries: dynamicMaxRetries });
    } catch (err) {
      redCallout('Dynamic mutator failed to initialize', [(err as Error).message]);
      process.exit(1);
    }
  }

  const agent = new AdversarialAgent(target, { ward, mutator });
  const runOpts = buildRunOptionsFromFlags(flags);
  // Real/dynamic mode: extend the per-attack timeout for live API latency
  if (isReal || isDynamic) runOpts.attackTimeoutMs = runOpts.attackTimeoutMs ?? 45_000;
  const planned = agent.selectAttacks(runOpts);

  console.log(`  Running \x1b[1m${planned.length}\x1b[0m attacks against \x1b[1m${target.identifier}\x1b[0m...`);
  if (isDynamic) console.log(`  Dynamic mode enabled — up to ${dynamicMaxRetries} variant retries per half-blocked attack.`);
  console.log('');

  const t0 = Date.now();
  const scorecard = await agent.run(runOpts);
  const elapsed = ((Date.now() - t0) / 1000).toFixed(1);

  console.log(`  Done in ${elapsed}s.`);

  // ── Real mode: print target usage and cost ────────────────
  if (isReal) {
    const u = target.getUsage();
    console.log('');
    console.log('  \x1b[1mTarget API usage:\x1b[0m');
    console.log(`    Calls:           ${u.apiCalls}${u.errors > 0 ? ` (${u.errors} errors)` : ''}`);
    console.log(`    Input tokens:    ${u.inputTokens.toLocaleString()}`);
    console.log(`    Output tokens:   ${u.outputTokens.toLocaleString()}`);
    console.log(`    Estimated cost:  ${fmtCost(u.estimatedCostUSD)}`);
    console.log(`    Model:           ${u.provider}/${u.model}`);
  }

  // ── Dynamic mode: print mutation usage and cost ───────────
  if (isDynamic && mutator) {
    const u = mutator.getUsage();
    console.log('');
    console.log('  \x1b[1mMutation API usage:\x1b[0m');
    console.log(`    Variants:        ${u.mutations}${u.errors > 0 ? ` (${u.errors} errors)` : ''}`);
    console.log(`    Input tokens:    ${u.inputTokens.toLocaleString()}`);
    console.log(`    Output tokens:   ${u.outputTokens.toLocaleString()}`);
    console.log(`    Estimated cost:  ${fmtCost(u.estimatedCostUSD)}`);
    console.log(`    Model:           ${u.provider}/${u.model}`);
  }

  // ── API health: errored attacks are scored "blocked", so a run where
  //    the API failed would otherwise look like a perfect defense. ──
  if (isReal) {
    const errors = target.getUsage().errors;
    const ran = scorecard.findings.length;
    const firstError = scorecard.findings.find((f) => f.evidence.startsWith('(real-mode API error'))?.evidence;
    const stopped = scorecard.stoppedEarly;
    if (stopped && ran === 0) {
      redCallout('Provider quota used up before any attack ran — no score', [
        stopped.reason.slice(0, 160),
        '',
        'Free tiers cap requests per day. Re-run after the quota resets, and',
        'fit the run to the quota with --per-category=<n> (5 categories).',
      ]);
      process.exit(2);
    }
    if (stopped) {
      yellowCallout(`Provider quota used up: stopped after ${ran} of ${stopped.planned} attacks`, [
        'The score covers completed attacks only and is not comparable with',
        'a full run. The scorecard is marked as a partial run.',
        '',
        'Free tiers cap requests per day. To fit the quota, re-run after it',
        'resets with --per-category=<n>, or --category=<cat> to pick up the',
        'categories that did not run. --rpm=<n> paces per-minute limits.',
        '',
        stopped.reason.slice(0, 160),
      ]);
    }
    if (errors > 0 && errors >= ran) {
      redCallout(`All ${errors} target API calls failed — no score`, [
        'Every attack errored before reaching the model, so the run measured',
        'nothing. Errored attacks would otherwise be scored as "blocked".',
        '',
        ...(firstError ? [firstError.slice(0, 160)] : []),
      ]);
      process.exit(2);
    }
    if (errors > 0) {
      yellowCallout(`${errors} of ${ran} attacks errored`, [
        'Errored attacks are scored as "blocked", so the score below is',
        'inflated. Fix the errors and re-run for a trustworthy result.',
        ...(firstError ? ['', firstError.slice(0, 160)] : []),
      ]);
    }
  }
  if (isDynamic && mutator && mutator.getUsage().errors > 0) {
    yellowCallout(`${mutator.getUsage().errors} mutation calls failed`, [
      'Those attacks were not retried with a variant, so dynamic mode',
      'under-tested them.',
    ]);
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

  // ── Dynamic mode (also supported for attack command) ──────
  const isDynamic = !!flags.dynamic;
  const dynamicMaxRetries = flags['dynamic-max-retries']
    ? parseInt(String(flags['dynamic-max-retries']), 10)
    : 2;
  const mutatorCfg = isDynamic
    ? resolveOrExit(
        'Cannot run --dynamic',
        (flags['dynamic-provider'] as string) || (flags.provider as string),
        (flags['dynamic-model'] as string) || (flags.model as string),
        flags,
      )
    : undefined;

  let mutator: DynamicAttackMutator | undefined;
  if (mutatorCfg) {
    try {
      mutator = new DynamicAttackMutator({ ...mutatorCfg, maxRetries: dynamicMaxRetries });
    } catch (err) {
      redCallout('Dynamic mutator failed', [(err as Error).message]);
      process.exit(1);
    }
  }

  const target = new PlaywrightTarget({ agentEndpoint: url, executable, browserType, headless });
  const ward = loadWardPolicy();
  const agent = new AdversarialAgent(target, { ward, mutator });
  const runOpts = buildRunOptionsFromFlags(flags);
  runOpts.attackTimeoutMs = runOpts.attackTimeoutMs ?? 60_000;

  const planned = agent.selectAttacks(runOpts);
  console.log(`  Running \x1b[1m${planned.length}\x1b[0m attacks. This may take several minutes.`);
  if (isDynamic) console.log(`  Dynamic mode enabled — up to ${dynamicMaxRetries} variant retries per half-blocked attack.`);
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

  if (isDynamic && mutator) {
    const u = mutator.getUsage();
    console.log('');
    console.log('  \x1b[1mMutation API usage:\x1b[0m');
    console.log(`    Variants:        ${u.mutations}${u.errors > 0 ? ` (${u.errors} errors)` : ''}`);
    console.log(`    Input tokens:    ${u.inputTokens.toLocaleString()}`);
    console.log(`    Output tokens:   ${u.outputTokens.toLocaleString()}`);
    console.log(`    Estimated cost:  ${fmtCost(u.estimatedCostUSD)}`);
    console.log(`    Model:           ${u.provider}/${u.model}`);
  }

  printSummary(scorecard);

  const finalScorecard = flags['redact-evidence'] ? redactScorecard(scorecard) : scorecard;
  emitOutputs(finalScorecard, flags);
}

function printSummary(scorecard: Scorecard) {
  console.log('');
  const partial = scorecard.stoppedEarly
    ? `  \x1b[33m(partial: ${scorecard.stoppedEarly.completed} of ${scorecard.stoppedEarly.planned} attacks)\x1b[0m`
    : '';
  console.log(`  \x1b[1mScore:\x1b[0m ${scoreColor(scorecard.summary.score)}  ${scorecard.summary.score}/100${partial}`);
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

function cmdProviders() {
  banner();
  console.log('  \x1b[1mProviders\x1b[0m  (--provider=<id>; every provider but anthropic needs --model=<id>)');
  console.log('');
  for (const [id, p] of Object.entries(PROVIDERS)) {
    const key = p.keyEnv.length ? p.keyEnv.join(' | ') : '(no key)';
    const set = p.keyEnv.length === 0 || p.keyEnv.some((k) => process.env[k]) ? '\x1b[32m✓\x1b[0m' : '\x1b[2m·\x1b[0m';
    console.log(`  ${set} ${id.padEnd(11)} ${p.label.padEnd(29)} ${key}`);
  }
  console.log('');
  console.log('  \x1b[2m✓ = key found in this shell. Local providers need the server running.\x1b[0m');
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
    if (cmd === 'providers') return cmdProviders();
    if (cmd === 'report') return cmdReport();
    console.error(`Unknown command: ${cmd}`);
    showHelp();
    process.exit(1);
  } catch (err) {
    console.error('Error:', (err as Error).stack || err);
    process.exit(1);
  }
})();
