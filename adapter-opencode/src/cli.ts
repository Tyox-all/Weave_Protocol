#!/usr/bin/env node
/**
 * weave-ward-opencode CLI
 *
 *   weave-ward-opencode init                    Add the plugin to ~/.config/opencode/opencode.json
 *   weave-ward-opencode disable                 Remove it
 *   weave-ward-opencode status                  Plugin + active WARD.md
 *   weave-ward-opencode test <tool> [--input=JSON]   Dry-run a tool call
 *
 * (Not "weave-opencode": that npm name belongs to W&B Weave's opencode integration.)
 */

import { installPlugin, removePlugin, isPluginInstalled, readConfig, opencodeJsonPath, PACKAGE } from './config.js';
import { resolveWard, evaluateCall, opencodeConfigDir } from './policy.js';
import { join } from 'node:path';

const tty = process.stderr.isTTY && !process.env.NO_COLOR;
const c = {
  reset: tty ? '\x1b[0m' : '', bold: tty ? '\x1b[1m' : '', red: tty ? '\x1b[31m' : '',
  green: tty ? '\x1b[32m' : '', yellow: tty ? '\x1b[33m' : '', cyan: tty ? '\x1b[36m' : '', gray: tty ? '\x1b[90m' : '',
};
const say = (s = '') => console.error(s);
const option = (args: string[], name: string) => args.find((a) => a.startsWith(`--${name}=`))?.slice(name.length + 3);

function help(): number {
  say(`\n${c.cyan}${c.bold}🛡️  weave-ward-opencode${c.reset} ${c.gray}WARD.md enforcement for OpenCode${c.reset}\n`);
  say(`${c.bold}Commands:${c.reset}`);
  say(`  ${c.cyan}init${c.reset}                              Add the plugin to ${opencodeJsonPath()}`);
  say(`  ${c.cyan}disable${c.reset}                           Remove it`);
  say(`  ${c.cyan}status${c.reset}                            Show the plugin and the active WARD.md`);
  say(`  ${c.cyan}test${c.reset} ${c.gray}<tool> [--input=JSON]${c.reset}        Dry-run a tool call against WARD.md\n`);
  return 0;
}

function safeResolve() {
  try {
    return resolveWard(process.cwd());
  } catch (err) {
    say(`${c.red}✗${c.reset} ${err instanceof Error ? err.message : String(err)}`);
    return null;
  }
}

function init(): number {
  try {
    installPlugin();
  } catch (err) {
    say(`${c.red}✗${c.reset} ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }
  say(`${c.green}✓${c.reset} Added "${PACKAGE}" to the plugin list in ${opencodeJsonPath()}`);
  if (!safeResolve()) {
    say(`${c.yellow}!${c.reset} No WARD.md found here or at ${join(opencodeConfigDir(), 'WARD.md')}; calls are allowed until you add one.`);
  }
  say(`${c.gray}Restart OpenCode; it installs the plugin on startup.${c.reset}`);
  return 0;
}

function disable(): number {
  const { removed } = removePlugin();
  say(removed ? `${c.green}✓${c.reset} Removed the plugin from ${opencodeJsonPath()}` : 'The plugin was not configured.');
  return 0;
}

function status(): number {
  const installed = isPluginInstalled(readConfig());
  say(`Plugin:   ${installed ? `${c.green}configured${c.reset}` : `${c.yellow}not configured${c.reset}`} (${opencodeJsonPath()})`);
  const ward = safeResolve();
  say(`WARD.md:  ${ward ? ward.source : `${c.yellow}none found${c.reset}`}`);
  return installed && ward ? 0 : 1;
}

function test(args: string[]): number {
  const tool = args.find((a) => !a.startsWith('--'));
  if (!tool) {
    say('Usage: weave-ward-opencode test <tool> [--input=JSON]');
    return 2;
  }
  const ward = safeResolve();
  if (!ward) {
    say('No WARD.md found; nothing to test against.');
    return 2;
  }
  const result = evaluateCall(ward.policy, tool, JSON.parse(option(args, 'input') ?? '{}'), process.cwd());
  const color = result.decision === 'allow' ? c.green : result.decision === 'deny' ? c.red : c.yellow;
  say(`${color}${result.decision}${c.reset} ${tool}`);
  for (const r of result.reasons) say(`  ${c.gray}${r}${c.reset}`);
  return result.decision === 'allow' ? 0 : 1;
}

const [cmd, ...rest] = process.argv.slice(2);
const code =
  cmd === 'init' ? init()
  : cmd === 'disable' || cmd === 'uninstall' ? disable()
  : cmd === 'status' ? status()
  : cmd === 'test' ? test(rest)
  : help();
process.exit(code);
