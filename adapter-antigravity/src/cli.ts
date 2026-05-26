#!/usr/bin/env node
/**
 * weave-antigravity CLI
 *
 *   weave-antigravity init [--matcher=X] [--fail-closed]   Install the WARD hook
 *   weave-antigravity disable                              Remove the WARD hook
 *   weave-antigravity status                               Show current config + WARD
 *   weave-antigravity test <tool> [--input=JSON]           Dry-run a tool call
 *   weave-antigravity hook <event> [--fail-closed]         Hook handler (called by agy)
 *   weave-antigravity help
 */

import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  installHook,
  removeHook,
  readSettings,
  isHookInstalled,
  antigravitySettingsPath,
  antigravityConfigDir,
  userWardPath,
} from './config.js';
import { resolveWardForCwd, evaluateCall, runPreToolUseHook } from './hook.js';

// ─── ANSI colors ───────────────────────────────────────────────
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
  gray: tty ? '\x1b[90m' : '',
};

function banner(): void {
  console.error(`
${c.cyan}${c.bold}🛡️  weave-antigravity${c.reset}
${c.gray}WARD.md enforcement for Google Antigravity via PreToolUse hooks${c.reset}
`);
}

// ─── help ──────────────────────────────────────────────────────
function help(): void {
  banner();
  console.error(`${c.bold}Usage:${c.reset} weave-antigravity <command> [options]\n`);
  console.error(`${c.bold}Commands:${c.reset}`);
  console.error(`  ${c.cyan}init${c.reset} ${c.gray}[--matcher=X] [--fail-closed]${c.reset}    Install the WARD pre-tool-use hook`);
  console.error(`  ${c.cyan}disable${c.reset}                            Remove the WARD hook`);
  console.error(`  ${c.cyan}status${c.reset}                             Show hook installation + active WARD policy`);
  console.error(`  ${c.cyan}test${c.reset} ${c.gray}<tool> [--input=JSON]${c.reset}         Dry-run a tool call against your WARD.md`);
  console.error(`  ${c.cyan}hook${c.reset} ${c.gray}<event>${c.reset}                       Internal: called by Antigravity as a hook`);
  console.error(`  ${c.cyan}help${c.reset}                               Show this message\n`);
  console.error(`${c.bold}Examples:${c.reset}`);
  console.error(`  ${c.gray}$${c.reset} weave-antigravity init`);
  console.error(`  ${c.gray}$${c.reset} weave-antigravity status`);
  console.error(`  ${c.gray}$${c.reset} weave-antigravity test Bash --input='{"command":"rm -rf ~/.gcloud"}'`);
  console.error(`  ${c.gray}$${c.reset} weave-antigravity disable\n`);
  console.error(`${c.gray}Docs: https://github.com/Tyox-all/Weave_Protocol/tree/main/adapter-antigravity${c.reset}\n`);
}

// ─── arg helpers ───────────────────────────────────────────────
function parseFlag(args: string[], name: string): string | undefined {
  for (const a of args) {
    if (a === `--${name}`) return '';
    if (a.startsWith(`--${name}=`)) return a.slice(`--${name}=`.length);
  }
  return undefined;
}

function hasFlag(args: string[], name: string): boolean {
  return args.some((a) => a === `--${name}` || a.startsWith(`--${name}=`));
}

// ─── init ──────────────────────────────────────────────────────
function runInit(args: string[]): number {
  banner();
  const matcher = parseFlag(args, 'matcher') || undefined;
  const failClosed = hasFlag(args, 'fail-closed');

  const settings = readSettings();
  const wasInstalled = isHookInstalled(settings);

  installHook({
    toolMatcher: matcher,
    failClosed,
    timeoutSeconds: 5,
  });

  const verb = wasInstalled ? 'Updated' : 'Installed';
  console.error(`${c.green}✓${c.reset} ${verb} WARD hook in ${c.cyan}${antigravitySettingsPath()}${c.reset}`);
  console.error(`  ${c.gray}matcher:${c.reset} ${matcher || '*'}`);
  console.error(`  ${c.gray}fail mode:${c.reset} ${failClosed ? c.red + 'closed' + c.reset : c.green + 'open' + c.reset}`);
  console.error('');
  console.error(`Next:`);
  console.error(`  ${c.gray}1.${c.reset} Drop a ${c.cyan}WARD.md${c.reset} in your project root (or at ${c.cyan}.agents/WARD.md${c.reset} next to AGENTS.md)`);
  console.error(`  ${c.gray}2.${c.reset} Run ${c.cyan}agy${c.reset} in that project — the hook will gate tool calls automatically`);
  console.error(`  ${c.gray}3.${c.reset} Run ${c.cyan}weave-antigravity status${c.reset} to verify`);
  console.error('');
  return 0;
}

// ─── disable ───────────────────────────────────────────────────
function runDisable(): number {
  banner();
  const result = removeHook();
  if (result.removed === 0) {
    console.error(`${c.yellow}⚠${c.reset}  No WARD hooks found in ${antigravitySettingsPath()}.`);
    return 0;
  }
  console.error(`${c.green}✓${c.reset} Removed ${result.removed} WARD hook entry from ${c.cyan}${antigravitySettingsPath()}${c.reset}`);
  console.error(`${c.gray}  (your other hooks were not touched)${c.reset}`);
  return 0;
}

// ─── status ────────────────────────────────────────────────────
function runStatus(): number {
  banner();
  const settingsPath = antigravitySettingsPath();
  const exists = existsSync(settingsPath);

  console.error(`${c.bold}Antigravity CLI config${c.reset}`);
  console.error(`${c.gray}─${c.reset}`.repeat(60));
  console.error(`  ${c.gray}Config dir:${c.reset}     ${c.cyan}${antigravityConfigDir()}${c.reset}`);
  console.error(`  ${c.gray}settings.json:${c.reset}  ${exists ? c.green + 'present' + c.reset : c.red + 'missing' + c.reset}`);

  if (exists) {
    const settings = readSettings();
    const installed = isHookInstalled(settings);
    console.error(`  ${c.gray}WARD hook:${c.reset}      ${installed ? c.green + 'installed' + c.reset : c.yellow + 'not installed' + c.reset}`);
  }

  console.error('');
  console.error(`${c.bold}Active WARD policy${c.reset}`);
  console.error(`${c.gray}─${c.reset}`.repeat(60));
  try {
    const resolved = resolveWardForCwd(process.cwd());
    if (!resolved) {
      console.error(`  ${c.yellow}No WARD.md found${c.reset}`);
      console.error(`  ${c.gray}Looked at:${c.reset}`);
      if (process.env.WEAVE_WARD_PATH) console.error(`    ${c.gray}•${c.reset} ${process.env.WEAVE_WARD_PATH} ${c.gray}(WEAVE_WARD_PATH)${c.reset}`);
      console.error(`    ${c.gray}•${c.reset} ${resolve(process.cwd(), 'WARD.md')}`);
      console.error(`    ${c.gray}•${c.reset} ${resolve(process.cwd(), '.agents', 'WARD.md')} ${c.gray}(next to AGENTS.md)${c.reset}`);
      console.error(`    ${c.gray}•${c.reset} ${resolve(process.cwd(), '.weave', 'WARD.md')}`);
      console.error(`    ${c.gray}•${c.reset} ${userWardPath()} ${c.gray}(user-global)${c.reset}`);
    } else {
      console.error(`  ${c.gray}Source:${c.reset}        ${c.cyan}${resolved.source}${c.reset}`);
      console.error(`  ${c.gray}Name:${c.reset}          ${resolved.policy.name || c.gray + '(unnamed)' + c.reset}`);
      console.error(`  ${c.gray}Agent:${c.reset}         ${resolved.policy.agent || c.gray + '(none)' + c.reset}`);
      console.error(`  ${c.gray}WARD version:${c.reset}  ${resolved.policy.version}`);
    }
  } catch (err) {
    console.error(`  ${c.red}Error loading WARD.md:${c.reset} ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }
  console.error('');
  return 0;
}

// ─── test ──────────────────────────────────────────────────────
function runTest(args: string[]): number {
  const tool = args[0];
  if (!tool) {
    console.error(`${c.red}✗${c.reset} Usage: weave-antigravity test <tool> [--input='{"file_path":"..."}']`);
    return 2;
  }

  banner();

  const inputArg = parseFlag(args, 'input');
  let toolInput: Record<string, unknown> = {};
  if (inputArg) {
    try {
      toolInput = JSON.parse(inputArg);
    } catch {
      console.error(`${c.red}✗${c.reset} --input must be valid JSON`);
      return 2;
    }
  }

  const resolved = resolveWardForCwd(process.cwd());
  if (!resolved) {
    console.error(`${c.yellow}⚠${c.reset} No WARD.md found — call would be allowed by default.`);
    return 0;
  }

  console.error(`Testing ${c.bold}${tool}${c.reset}${inputArg ? ' with ' + c.cyan + JSON.stringify(toolInput) + c.reset : ''}`);
  console.error(`Policy: ${c.cyan}${resolved.source}${c.reset}\n`);

  const result = evaluateCall(resolved.policy, tool, toolInput);
  const colorMap = {
    allow: c.green,
    deny: c.red,
    require_approval: c.yellow,
  } as const;
  const iconMap = { allow: '✓', deny: '✗', require_approval: '⚠' };

  console.error(`Decision: ${colorMap[result.decision]}${iconMap[result.decision]} ${result.decision.toUpperCase()}${c.reset}`);
  if (result.reasons.length > 0) {
    console.error(`\nReasons:`);
    for (const r of result.reasons) console.error(`  ${c.gray}•${c.reset} ${r}`);
  }
  console.error('');
  return result.decision === 'deny' ? 1 : 0;
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
      case 'disable':
      case 'uninstall':
        code = runDisable();
        break;
      case 'status':
        code = runStatus();
        break;
      case 'test':
        code = runTest(rest);
        break;
      case 'hook': {
        const event = rest[0];
        const failClosed = hasFlag(rest, 'fail-closed');
        if (event === 'pre-tool-use' || !event) {
          await runPreToolUseHook(failClosed);
          return;
        }
        process.stdout.write('{}');
        process.exit(0);
      }
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
