#!/usr/bin/env node
/**
 * weave-gemini CLI
 *
 *   weave-gemini init [--matcher=REGEX] [--timeout=MS] [--fail-closed]   Install the WARD hook
 *   weave-gemini disable                                                 Remove it
 *   weave-gemini status                                                  Hook + active WARD.md
 *   weave-gemini test <tool> [--input=JSON]                              Dry-run a tool call
 *   weave-gemini hook before-tool [--fail-closed]                        Hook handler (run by Gemini CLI)
 */

import { installHook, removeHook, isHookInstalled, readSettings, geminiSettingsPath, userWardPath } from './config.js';
import { resolveWardForCwd, evaluateCall, runBeforeToolHook } from './hook.js';

const tty = process.stderr.isTTY && !process.env.NO_COLOR;
const c = {
  reset: tty ? '\x1b[0m' : '', bold: tty ? '\x1b[1m' : '', red: tty ? '\x1b[31m' : '',
  green: tty ? '\x1b[32m' : '', yellow: tty ? '\x1b[33m' : '', cyan: tty ? '\x1b[36m' : '', gray: tty ? '\x1b[90m' : '',
};
const say = (s = '') => console.error(s);

const flag = (args: string[], name: string) => args.includes(`--${name}`);
const option = (args: string[], name: string) => args.find((a) => a.startsWith(`--${name}=`))?.slice(name.length + 3);

function help(): number {
  say(`\n${c.cyan}${c.bold}🛡️  weave-gemini${c.reset} ${c.gray}WARD.md enforcement for Gemini CLI${c.reset}\n`);
  say(`${c.bold}Commands:${c.reset}`);
  say(`  ${c.cyan}init${c.reset} ${c.gray}[--matcher=REGEX] [--timeout=MS] [--fail-closed]${c.reset}  Install the BeforeTool hook in ~/.gemini/settings.json`);
  say(`  ${c.cyan}disable${c.reset}                                              Remove the hook`);
  say(`  ${c.cyan}status${c.reset}                                               Show the hook and the active WARD.md`);
  say(`  ${c.cyan}test${c.reset} ${c.gray}<tool> [--input=JSON]${c.reset}                           Dry-run a tool call against WARD.md`);
  say(`  ${c.cyan}hook before-tool${c.reset} ${c.gray}[--fail-closed]${c.reset}                    Hook handler (Gemini CLI runs this)\n`);
  return 0;
}

function init(args: string[]): number {
  const timeout = option(args, 'timeout');
  installHook({
    matcher: option(args, 'matcher'),
    timeoutMs: timeout ? Number(timeout) : undefined,
    failClosed: flag(args, 'fail-closed'),
  });
  say(`${c.green}✓${c.reset} WARD hook installed in ${geminiSettingsPath()}`);
  const ward = safeResolve(process.cwd());
  if (!ward) {
    say(`${c.yellow}!${c.reset} No WARD.md found here or at ${userWardPath()}; calls are allowed until you add one.`);
  }
  say(`${c.gray}Restart Gemini CLI for the hook to take effect.${c.reset}`);
  return 0;
}

function disable(): number {
  const { removed } = removeHook();
  say(removed ? `${c.green}✓${c.reset} Removed the WARD hook from ${geminiSettingsPath()}` : 'No WARD hook was installed.');
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
  const installed = isHookInstalled(readSettings());
  say(`Hook:     ${installed ? `${c.green}installed${c.reset}` : `${c.yellow}not installed${c.reset}`} (${geminiSettingsPath()})`);
  const ward = safeResolve(process.cwd());
  say(`WARD.md:  ${ward ? ward.source : `${c.yellow}none found${c.reset}`}`);
  return installed && ward ? 0 : 1;
}

function test(args: string[]): number {
  const tool = args.find((a) => !a.startsWith('--'));
  if (!tool) {
    say('Usage: weave-gemini test <tool> [--input=JSON]');
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
      if (rest[0] === 'before-tool' || !rest[0]) return runBeforeToolHook(flag(rest, 'fail-closed'));
      // Other events: leave the call alone
      process.stdout.write('{}');
      return 0;
    default: return help();
  }
}

main().then((code) => process.exit(code), (err) => {
  say(`weave-gemini: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
