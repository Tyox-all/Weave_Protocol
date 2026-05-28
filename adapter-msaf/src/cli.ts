#!/usr/bin/env node
/**
 * weave-msaf CLI
 *
 *   weave-msaf init [--language=ts|csharp|python]   Print integration snippet
 *   weave-msaf status                                Show active WARD policy
 *   weave-msaf test <tool> [--input=JSON]            Dry-run a tool call
 *   weave-msaf help
 *
 * Note: Unlike the Claude Code / Antigravity adapters, MSAF middleware is
 * programmatic — registered in the user's agent code, not via a config file.
 * So `init` here prints the integration snippet for the user to paste rather
 * than writing to a settings.json.
 */

import { resolve } from 'node:path';
import { resolveWardForCwd, evaluateCall } from './policy.js';
import { TOOL_MAPPINGS } from './types.js';

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
${c.cyan}${c.bold}🛡️  weave-msaf${c.reset}
${c.gray}WARD.md enforcement for Microsoft Agent Framework via middleware${c.reset}
`);
}

// ─── help ──────────────────────────────────────────────────────
function help(): void {
  banner();
  console.error(`${c.bold}Usage:${c.reset} weave-msaf <command> [options]\n`);
  console.error(`${c.bold}Commands:${c.reset}`);
  console.error(`  ${c.cyan}init${c.reset} ${c.gray}[--language=ts|csharp|python]${c.reset}     Print integration snippet for your code`);
  console.error(`  ${c.cyan}status${c.reset}                                Show active WARD policy`);
  console.error(`  ${c.cyan}test${c.reset} ${c.gray}<tool> [--input=JSON]${c.reset}             Dry-run a tool call against your WARD.md`);
  console.error(`  ${c.cyan}help${c.reset}                                  Show this message\n`);
  console.error(`${c.bold}Examples:${c.reset}`);
  console.error(`  ${c.gray}$${c.reset} weave-msaf init --language=ts`);
  console.error(`  ${c.gray}$${c.reset} weave-msaf status`);
  console.error(`  ${c.gray}$${c.reset} weave-msaf test ShellExec --input='{"command":"rm -rf ~/.azure"}'\n`);
  console.error(`${c.gray}Docs: https://github.com/Tyox-all/Weave_Protocol/tree/main/adapter-msaf${c.reset}\n`);
}

// ─── arg helpers ───────────────────────────────────────────────
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
  const language = parseFlag(args, 'language') || 'ts';

  console.error(`${c.bold}Integration snippet for ${c.cyan}${language}${c.reset}${c.bold}${c.reset}\n`);

  if (language === 'csharp' || language === 'cs' || language === '.net') {
    console.log(`// In your MSAF agent setup:
// (.NET / C#)

using Microsoft.AgentFramework;

// 1. Install: dotnet add package Weave.Protocol.AdapterMsaf
//    (.NET wrapper coming in v0.2 — for now use the Node bridge or call
//     the WARD CLI as a subprocess from your MSAF middleware.)

// 2. Until v0.2, recommended approach: install @weave_protocol/adapter-msaf
//    via Node and call \`weave-msaf test\` from a custom .NET function
//    middleware to evaluate calls. See README for full pattern.
`);
  } else if (language === 'python' || language === 'py') {
    console.log(`# In your MSAF agent setup (Python):

# 1. Install:
#    pip install weave-protocol-msaf      # coming in v0.2 (Python package)
#
#    For now, the npm package can be invoked from Python as a subprocess
#    for testing. The Python middleware shape is:

class WardFunctionMiddleware:
    def __init__(self, ward_path="WARD.md"):
        # load policy
        ...

    async def pre_invoke(self, ctx):
        # evaluate ctx.tool_name and ctx.arguments against WARD
        # call ctx.cancel() if denied
        ...

# Track issue #N for native Python support timeline.
`);
  } else {
    // TypeScript (default)
    console.log(`// In your MSAF agent setup (TypeScript):

import { WardMiddleware } from '@weave_protocol/adapter-msaf';

// 1. Construct with auto-resolved WARD.md
const ward = new WardMiddleware();
// Or with explicit path:
//   const ward = new WardMiddleware({ wardPath: './policies/strict.WARD.md' });

// 2. Register as function middleware on your MSAF agent.
// The exact API depends on your MSAF Node binding; the middleware function
// follows the documented pre_invoke shape:
//
//   async (call, next) => {  ... }
//
agent.useFunctionMiddleware(ward.functionMiddleware());

// 3. (Optional) Custom tool mappings if you have non-standard tool names:
//   const ward = new WardMiddleware({
//     toolMappings: {
//       MyCustomTool: { capability: 'custom_capability' }
//     }
//   });

// 4. (Optional) Allow/deny callbacks for logging/attestation:
//   const ward = new WardMiddleware({
//     onAllow: (call, result) => log('allowed', call.toolName),
//     onDeny:  (call, result) => log('denied',  call.toolName, result.reasons),
//   });
`);
  }

  console.error('');
  console.error(`${c.gray}─${c.reset}`.repeat(60));
  console.error(`${c.bold}Next:${c.reset}`);
  console.error(`  ${c.gray}1.${c.reset} Drop a ${c.cyan}WARD.md${c.reset} in your project root (or pass wardPath explicitly)`);
  console.error(`  ${c.gray}2.${c.reset} Paste the snippet above into your agent setup code`);
  console.error(`  ${c.gray}3.${c.reset} Run ${c.cyan}weave-msaf status${c.reset} to verify policy is found`);
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
      if (process.env.WEAVE_WARD_PATH) console.error(`    ${c.gray}•${c.reset} ${process.env.WEAVE_WARD_PATH} ${c.gray}(WEAVE_WARD_PATH)${c.reset}`);
      console.error(`    ${c.gray}•${c.reset} ${resolve(process.cwd(), 'WARD.md')}`);
      console.error(`    ${c.gray}•${c.reset} ${resolve(process.cwd(), '.weave', 'WARD.md')}`);
      console.error(`    ${c.gray}•${c.reset} ${resolve(process.cwd(), '.msaf', 'WARD.md')}`);
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
  console.error(`${c.bold}Built-in tool mappings${c.reset}`);
  console.error(`${c.gray}─${c.reset}`.repeat(60));
  const mappingNames = Object.keys(TOOL_MAPPINGS).slice(0, 12);
  console.error(`  ${c.gray}${mappingNames.join(', ')}${mappingNames.length < Object.keys(TOOL_MAPPINGS).length ? ', ...' : ''}${c.reset}`);
  console.error(`  ${c.gray}(${Object.keys(TOOL_MAPPINGS).length} total — see README for full list)${c.reset}`);
  console.error('');
  return 0;
}

// ─── test ──────────────────────────────────────────────────────
function runTest(args: string[]): number {
  const tool = args[0];
  if (!tool) {
    console.error(`${c.red}✗${c.reset} Usage: weave-msaf test <tool> [--input='{"path":"..."}']`);
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

  const result = evaluateCall(resolved.policy, { toolName: tool, args: toolInput });
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
      case 'status':
        code = runStatus();
        break;
      case 'test':
        code = runTest(rest);
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
