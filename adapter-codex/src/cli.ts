#!/usr/bin/env node
/**
 * weave-ward-codex CLI
 *
 *   weave-ward-codex init [--matcher=REGEX] [--timeout=SECONDS] [--fail-closed]   Install the WARD hook
 *   weave-ward-codex disable                                                      Remove it
 *   weave-ward-codex status                                                       Hook + active WARD.md
 *   weave-ward-codex test <tool> [--input=JSON]                                   Dry-run a tool call
 *   weave-ward-codex hook pre-tool-use [--fail-closed]                            Hook handler (run by Codex)
 *
 * (Not "weave-codex": that npm name belongs to W&B Weave's Codex integration.)
 */

import { installHook, removeHook, isHookInstalled, readHooks, hooksJsonPath, userWardPath } from './config.js';
import { resolveWardForCwd, evaluateCall, runPreToolUseHook } from './hook.js';

const tty = process.stderr.isTTY && !process.env.NO_COLOR;
const c = {
  reset: tty ? '\x1b[0m' : '', bold: tty ? '\x1b[1m' : '', red: tty ? '\x1b[31m' : '',
  green: tty ? '\x1b[32m' : '', yellow: tty ? '\x1b[33m' : '', cyan: tty ? '\x1b[36m' : '', gray: tty ? '\x1b[90m' : '',
};
const say = (s = '') => console.error(s);

const flag = (args: string[], name: string) => args.includes(`--${name}`);
const option = (args: string[], name: string) => args.find((a) => a.startsWith(`--${name}=`))?.slice(name.length + 3);

function help(): number {
  say(`\n${c.cyan}${c.bold}🛡️  weave-ward-codex${c.reset} ${c.gray}WARD.md enforcement for OpenAI Codex CLI${c.reset}\n`);
  say(`${c.bold}Commands:${c.reset}`);
  say(`  ${c.cyan}init${c.reset} ${c.gray}[--matcher=REGEX] [--timeout=SECONDS] [--fail-closed]${c.reset}  Install the PreToolUse hook in ~/.codex/hooks.json`);
  say(`  ${c.cyan}disable${c.reset}                                              Remove the hook`);
  say(`  ${c.cyan}status${c.reset}                                               Show the hook and the active WARD.md`);
  say(`  ${c.cyan}test${c.reset} ${c.gray}<tool> [--input=JSON]${c.reset}                           Dry-run a tool call against WARD.md`);
  say(`  ${c.cyan}hook pre-tool-use${c.reset} ${c.gray}[--fail-closed]${c.reset}                   Hook handler (Codex runs this)\n`);
  return 0;
}

function init(args: string[]): number {
  const timeout = option(args, 'timeout');
  installHook({
    matcher: option(args, 'matcher'),
    timeoutSeconds: timeout ? Number(timeout) : undefined,
    failClosed: flag(args, 'fail-closed'),
  });
  say(`${c.green}✓${c.reset} WARD hook installed in ${hooksJsonPath()}`);
  say(`${c.yellow}!${c.reset} Codex skips new hooks until you trust them: run ${c.bold}/hooks${c.reset} in Codex and trust "${'Weave: checking WARD.md'}".`);
  const ward = safeResolve(process.cwd());
  if (!ward) {
    say(`${c.yellow}!${c.reset} No WARD.md found here or at ${userWardPath()}; calls are allowed until you add one.`);
  }

  return 0;
}

function disable(): number {
  const { removed } = removeHook();
  say(removed ? `${c.green}✓${c.reset} Removed the WARD hook from ${hooksJsonPath()}` : 'No WARD hook was installed.');
  return 0;
}

function safeResolve(cwd: string) {
  try {
    return resolveWardForCwd(cwd);
  } catch (err) {
    say(`${c.red}✗${c.reset} ${err instanceof Error ? err.message : String(err)}`);
    return null;
  }
}

function status(): number {
  const installed = isHookInstalled(readHooks());
  say(`Hook:     ${installed ? `${c.green}installed${c.reset}` : `${c.yellow}not installed${c.reset}`} (${hooksJsonPath()})`);
  const ward = safeResolve(process.cwd());
  say(`WARD.md:  ${ward ? ward.source : `${c.yellow}none found${c.reset}`}`);
  return installed && ward ? 0 : 1;
}

function test(args: string[]): number {
  const tool = args.find((a) => !a.startsWith('--'));
  if (!tool) {
    say('Usage: weave-ward-codex test <tool> [--input=JSON]');
    return 2;
  }
  const ward = safeResolve(process.cwd());
  if (!ward) {
    say('No WARD.md found; nothing to test against.');
    return 2;
  }
  const input = JSON.parse(option(args, 'input') ?? '{}');
  const result = evaluateCall(ward.policy, tool, input, process.cwd());
  const color = result.decision === 'allow' ? c.green : result.decision === 'deny' ? c.red : c.yellow;
  say(`${color}${result.decision}${c.reset} ${tool}`);
  for (const r of result.reasons) say(`  ${c.gray}${r}${c.reset}`);
  return result.decision === 'allow' ? 0 : 1;
}

async function main(): Promise<number> {
  const [cmd, ...rest] = process.argv.slice(2);
  switch (cmd) {
    case 'init': return init(rest);
    case 'disable':
    case 'uninstall': return disable();
    case 'status': return status();
    case 'test': return test(rest);
    case 'hook':
      if (rest[0] === 'pre-tool-use' || !rest[0]) return runPreToolUseHook(flag(rest, 'fail-closed'));
      // Other events: print nothing, so the call continues
      return 0;
    default: return help();
  }
}

main().then((code) => process.exit(code), (err) => {
  say(`weave-ward-codex: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
