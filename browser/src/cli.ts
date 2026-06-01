#!/usr/bin/env node
/**
 * weave-browser CLI
 *
 *   weave-browser init [--framework=playwright|puppeteer|stagehand]
 *       Print an integration snippet for the chosen framework.
 *
 *   weave-browser status
 *       Show the active WARD policy and loaded IPI pattern count.
 *
 *   weave-browser test-url <url>
 *       Dry-run a navigation check.
 *
 *   weave-browser scan <file-or-url>
 *       Fetch the URL or read the file and scan for IPI.
 *
 *   weave-browser help
 */

import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { resolveWardForCwd, evaluateNavigation } from './policy.js';
import { scanForIpi, getPatternCatalog } from './ipi.js';

// ─── ANSI ──────────────────────────────────────────────────────
const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const c = {
  reset: tty ? '\x1b[0m' : '',
  bold: tty ? '\x1b[1m' : '',
  dim: tty ? '\x1b[2m' : '',
  red: tty ? '\x1b[31m' : '',
  green: tty ? '\x1b[32m' : '',
  yellow: tty ? '\x1b[33m' : '',
  blue: tty ? '\x1b[34m' : '',
  cyan: tty ? '\x1b[36m' : '',
  magenta: tty ? '\x1b[35m' : '',
  gray: tty ? '\x1b[90m' : '',
};

function banner(): void {
  console.error(`
${c.cyan}${c.bold}🌐  weave-browser${c.reset}
${c.gray}WARD.md enforcement + IPI detection for browser-based AI agents${c.reset}
`);
}

function help(): void {
  banner();
  console.error(`${c.bold}Usage:${c.reset} weave-browser <command> [options]\n`);
  console.error(`${c.bold}Commands:${c.reset}`);
  console.error(`  ${c.cyan}init${c.reset} ${c.gray}[--framework=playwright|puppeteer|stagehand]${c.reset}     Print integration snippet`);
  console.error(`  ${c.cyan}status${c.reset}                                Show active WARD + IPI patterns`);
  console.error(`  ${c.cyan}test-url${c.reset} ${c.gray}<url>${c.reset}                       Dry-run a navigation check`);
  console.error(`  ${c.cyan}scan${c.reset} ${c.gray}<file-or-url>${c.reset}                   Scan content for IPI`);
  console.error(`  ${c.cyan}help${c.reset}                                  Show this message\n`);
  console.error(`${c.bold}Examples:${c.reset}`);
  console.error(`  ${c.gray}$${c.reset} weave-browser init --framework=playwright`);
  console.error(`  ${c.gray}$${c.reset} weave-browser status`);
  console.error(`  ${c.gray}$${c.reset} weave-browser test-url https://api.github.com/repos/foo/bar`);
  console.error(`  ${c.gray}$${c.reset} weave-browser scan ./suspicious-page.html\n`);
  console.error(`${c.gray}Docs: https://github.com/Tyox-all/Weave_Protocol/tree/main/browser${c.reset}\n`);
}

function parseFlag(args: string[], name: string): string | undefined {
  for (const a of args) {
    if (a === `--${name}`) return '';
    if (a.startsWith(`--${name}=`)) return a.slice(`--${name}=`.length);
  }
  return undefined;
}

// ─── init ──────────────────────────────────────────────────────
function runInit(args: string[]): number {
  banner();
  const framework = (parseFlag(args, 'framework') || 'playwright').toLowerCase();
  console.error(`${c.bold}Integration snippet for ${c.cyan}${framework}${c.reset}${c.bold}${c.reset}\n`);

  if (framework === 'playwright') {
    console.log(`// In your Playwright-based browser agent:

import { chromium } from 'playwright';
import { WardBrowserGuard } from '@weave_protocol/browser';

const guard = new WardBrowserGuard();   // auto-loads ./WARD.md
// Or: new WardBrowserGuard({ ipiSensitivity: 'strict' });

const browser = await chromium.launch();
const context = await browser.newContext();
const page = await context.newPage();

// Wrap once — navigation, content, and downloads are auto-gated
guard.wrapPlaywrightPage(page, 'session-1');

await page.goto('https://example.com');  // gated against WARD ## Network
// HTML responses auto-scanned for IPI; downloads auto-gated by extension/MIME

// You can also explicitly check before tool calls in tainted sessions:
const action = await guard.checkAction('http_request', 'session-1');
if (action.decision === 'require_approval') {
  console.log('Tainted session — needs human approval to proceed');
}
`);
  } else if (framework === 'puppeteer') {
    console.log(`// In your Puppeteer-based browser agent:

import puppeteer from 'puppeteer';
import { WardBrowserGuard } from '@weave_protocol/browser';

const guard = new WardBrowserGuard();

const browser = await puppeteer.launch();
const page = await browser.newPage();
const sessionId = 'puppeteer-session-1';

// Puppeteer doesn't have an exact equivalent to wrapPlaywrightPage, but
// the same hook points work:
page.on('framenavigated', async (frame) => {
  if (frame === page.mainFrame()) {
    await guard.checkNavigation({ url: frame.url(), source: 'page-link' }, sessionId);
  }
});

page.on('response', async (response) => {
  const ct = response.headers()['content-type'] || '';
  if (!ct.includes('text/html')) return;
  const body = await response.text();
  await guard.scanForInjection(body, { url: response.url(), sessionId, isHtml: true });
});

// Manual check before navigation:
await guard.checkNavigation('https://example.com', sessionId);
await page.goto('https://example.com');
`);
  } else if (framework === 'stagehand') {
    console.log(`// In your Stagehand-based browser agent:

import { Stagehand } from '@browserbasehq/stagehand';
import { WardBrowserGuard } from '@weave_protocol/browser';

const guard = new WardBrowserGuard();
const stagehand = new Stagehand({ env: 'LOCAL' });
await stagehand.init();
const sessionId = 'stagehand-session-1';

// Stagehand exposes the underlying Playwright Page via stagehand.page
guard.wrapPlaywrightPage(stagehand.page, sessionId);

// Then use Stagehand's act / extract / observe as normal — WARD enforcement
// applies transparently.
await stagehand.page.goto('https://example.com');
await stagehand.act({ action: 'click the search button' });
`);
  } else {
    console.error(`${c.red}Unknown framework: ${framework}${c.reset}`);
    console.error(`${c.gray}Supported: playwright, puppeteer, stagehand${c.reset}`);
    return 2;
  }

  console.error('');
  console.error(`${c.gray}─${c.reset}`.repeat(60));
  console.error(`${c.bold}Next:${c.reset}`);
  console.error(`  ${c.gray}1.${c.reset} Drop a ${c.cyan}WARD.md${c.reset} in your project root (npx @weave_protocol/ward init)`);
  console.error(`  ${c.gray}2.${c.reset} Paste the snippet above into your agent setup`);
  console.error(`  ${c.gray}3.${c.reset} Run ${c.cyan}weave-browser status${c.reset} to verify policy loads`);
  console.error('');
  return 0;
}

// ─── status ────────────────────────────────────────────────────
function runStatus(): number {
  banner();
  console.error(`${c.bold}Active WARD policy${c.reset}`);
  console.error(`${c.gray}─${c.reset}`.repeat(60));
  try {
    const resolved = resolveWardForCwd(process.cwd());
    if (!resolved) {
      console.error(`  ${c.yellow}No WARD.md found${c.reset}`);
      console.error(`  ${c.gray}Looked at:${c.reset}`);
      if (process.env.WEAVE_WARD_PATH) {
        console.error(`    ${c.gray}•${c.reset} ${process.env.WEAVE_WARD_PATH} ${c.gray}(WEAVE_WARD_PATH)${c.reset}`);
      }
      console.error(`    ${c.gray}•${c.reset} ${resolve(process.cwd(), 'WARD.md')}`);
      console.error(`    ${c.gray}•${c.reset} ${resolve(process.cwd(), '.weave', 'WARD.md')}`);
      console.error(`    ${c.gray}•${c.reset} ${resolve(process.cwd(), '.browser', 'WARD.md')}`);
    } else {
      console.error(`  ${c.gray}Source:${c.reset}        ${c.cyan}${resolved.source}${c.reset}`);
      console.error(`  ${c.gray}Name:${c.reset}          ${resolved.policy.name || c.gray + '(unnamed)' + c.reset}`);
      console.error(`  ${c.gray}Agent:${c.reset}         ${resolved.policy.agent || c.gray + '(none)' + c.reset}`);
      console.error(`  ${c.gray}WARD version:${c.reset}  ${resolved.policy.version}`);
      const netAllow = resolved.policy.network?.allow?.length || 0;
      const netDeny = resolved.policy.network?.deny?.length || 0;
      console.error(`  ${c.gray}Network:${c.reset}       ${c.green}${netAllow}${c.reset} allow / ${c.red}${netDeny}${c.reset} deny rules`);
    }
  } catch (err) {
    console.error(`  ${c.red}Error:${c.reset} ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }
  console.error('');

  console.error(`${c.bold}IPI detection patterns${c.reset}`);
  console.error(`${c.gray}─${c.reset}`.repeat(60));
  const cat = getPatternCatalog();
  console.error(`  ${c.gray}Trigger phrases:${c.reset}    ${c.cyan}${cat.triggerPhrases}${c.reset}`);
  console.error(`  ${c.gray}Action directives:${c.reset}  ${c.cyan}${cat.actionDirectives}${c.reset}  ${c.gray}(critical severity)${c.reset}`);
  console.error(`  ${c.gray}DoS suppression:${c.reset}    ${c.cyan}${cat.dosPatterns}${c.reset}`);
  console.error(`  ${c.gray}Tool-call mimicry:${c.reset}  ${c.cyan}${cat.toolCallMimicry}${c.reset}`);
  console.error(`  ${c.gray}Hidden CSS:${c.reset}         ${c.cyan}${cat.hiddenCssPatterns}${c.reset}`);
  console.error(`  ${c.gray}Standalone:${c.reset}         ${c.cyan}10${c.reset}  ${c.gray}(payment, base64, unicode, comments, etc.)${c.reset}`);
  console.error(`  ${c.bold}Total:${c.reset}              ${c.cyan}${c.bold}${cat.totalPatterns}${c.reset}`);
  console.error('');
  return 0;
}

// ─── test-url ──────────────────────────────────────────────────
function runTestUrl(args: string[]): number {
  const url = args[0];
  if (!url) {
    console.error(`${c.red}✗${c.reset} Usage: weave-browser test-url <url>`);
    return 2;
  }
  banner();

  const resolved = resolveWardForCwd();
  if (!resolved) {
    console.error(`${c.yellow}⚠${c.reset} No WARD.md found — navigation would be allowed by default.`);
    return 0;
  }

  console.error(`Testing navigation to ${c.bold}${url}${c.reset}`);
  console.error(`Policy: ${c.cyan}${resolved.source}${c.reset}\n`);

  const result = evaluateNavigation(resolved.policy, url);
  const colorMap = { allow: c.green, deny: c.red, require_approval: c.yellow };
  const iconMap = { allow: '✓', deny: '✗', require_approval: '⚠' };
  console.error(`Decision: ${colorMap[result.decision]}${iconMap[result.decision]} ${result.decision.toUpperCase()}${c.reset}`);
  if (result.reasons.length) {
    console.error(`\nReasons:`);
    for (const r of result.reasons) console.error(`  ${c.gray}•${c.reset} ${r}`);
  }
  console.error('');
  return result.decision === 'deny' ? 1 : 0;
}

// ─── scan ──────────────────────────────────────────────────────
async function runScan(args: string[]): Promise<number> {
  const target = args[0];
  if (!target) {
    console.error(`${c.red}✗${c.reset} Usage: weave-browser scan <file-or-url>`);
    return 2;
  }
  banner();

  let content: string;
  let label: string;
  let isHtml = true;

  if (target.startsWith('http://') || target.startsWith('https://')) {
    console.error(`Fetching ${c.cyan}${target}${c.reset}...`);
    try {
      const res = await fetch(target);
      content = await res.text();
      label = target;
      const ct = res.headers.get('content-type') || '';
      isHtml = ct.includes('text/html') || ct.includes('application/xhtml');
    } catch (err) {
      console.error(`${c.red}Fetch failed:${c.reset} ${err instanceof Error ? err.message : String(err)}`);
      return 1;
    }
  } else {
    if (!existsSync(target)) {
      console.error(`${c.red}File not found:${c.reset} ${target}`);
      return 2;
    }
    content = readFileSync(target, 'utf8');
    label = target;
    isHtml = /\.html?$/i.test(target);
  }

  console.error(`Scanning ${c.cyan}${label}${c.reset} (${content.length} chars, ${isHtml ? 'HTML' : 'plain text'})\n`);
  const result = scanForIpi(content, { isHtml });

  const riskColor = {
    none: c.green,
    low: c.yellow,
    medium: c.yellow,
    high: c.red,
    critical: c.magenta,
  } as const;
  const riskIcon = { none: '✓', low: '!', medium: '!', high: '✗', critical: '☠' };

  console.error(`${c.bold}Risk:${c.reset} ${riskColor[result.riskLevel]}${riskIcon[result.riskLevel]} ${result.riskLevel.toUpperCase()}${c.reset}`);
  console.error(`${c.bold}Threats:${c.reset} ${result.threats.length}\n`);

  if (result.threats.length > 0) {
    for (const t of result.threats) {
      const sevColor = {
        low: c.gray,
        medium: c.yellow,
        high: c.red,
        critical: c.magenta,
      }[t.severity];
      console.error(`  ${sevColor}[${t.severity.toUpperCase()}]${c.reset} ${c.bold}${t.type}${c.reset}`);
      console.error(`    ${c.gray}${t.description}${c.reset}`);
      console.error(`    ${c.gray}Confidence:${c.reset} ${(t.confidence * 100).toFixed(0)}%`);
      console.error(`    ${c.gray}Evidence:${c.reset} ${t.evidence}`);
      console.error('');
    }
  } else {
    console.error(`  ${c.green}No IPI patterns detected.${c.reset}\n`);
  }

  return result.riskLevel === 'high' || result.riskLevel === 'critical' ? 1 : 0;
}

// ─── router ────────────────────────────────────────────────────
async function main(): Promise<void> {
  const [, , cmd, ...rest] = process.argv;
  let code = 0;
  try {
    switch (cmd) {
      case 'init':
        code = runInit(rest);
        break;
      case 'status':
        code = runStatus();
        break;
      case 'test-url':
        code = runTestUrl(rest);
        break;
      case 'scan':
        code = await runScan(rest);
        break;
      case 'help':
      case '--help':
      case '-h':
      case undefined:
        help();
        break;
      default:
        console.error(`${c.red}Unknown command: ${cmd}${c.reset}\n`);
        help();
        code = 2;
    }
  } catch (err) {
    console.error(`${c.red}Error:${c.reset} ${err instanceof Error ? err.message : String(err)}`);
    if (process.env.DEBUG) console.error(err);
    code = 2;
  }
  process.exit(code);
}

main();
