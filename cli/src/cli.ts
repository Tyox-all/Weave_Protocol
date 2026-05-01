#!/usr/bin/env node
/**
 * weave — top-level CLI for the Weave Protocol.
 *
 *   weave init                    Set up a new project
 *   weave audit [path]            Scan dependencies (delegates to Tollere)
 *   weave dashboard [--port=N]    Launch API + open monitoring dashboard
 *   weave doctor                  Check environment for common issues
 *   weave version                 Print CLI + installed package versions
 *   weave help                    Show help
 */

import { runInit } from "./commands/init.js";
import { runAudit, runDashboard, runDoctor, runVersion } from "./commands/index.js";
import { c, banner } from "./utils/colors.js";

function help(): void {
  console.log(banner());
  console.log(`${c.bold("Usage:")} weave <command> [options]\n`);
  console.log(c.bold("Commands:"));
  console.log(`  ${c.cyan("init")}                       Set up Weave Protocol in the current project`);
  console.log(`  ${c.cyan("audit")} ${c.gray("[path]")}              Scan dependencies for supply chain risk`);
  console.log(`  ${c.cyan("dashboard")} ${c.gray("[--port=N]")}       Launch the API server and open the dashboard`);
  console.log(`  ${c.cyan("doctor")}                     Check environment for common config issues`);
  console.log(`  ${c.cyan("version")}                    Print versions`);
  console.log(`  ${c.cyan("help")}                       Show this message\n`);

  console.log(c.bold("Examples:"));
  console.log(`  ${c.gray("$")} npx @weave_protocol/cli init`);
  console.log(`  ${c.gray("$")} weave audit`);
  console.log(`  ${c.gray("$")} weave dashboard --port=4000`);
  console.log("");

  console.log(c.gray("Docs: https://github.com/Tyox-all/Weave_Protocol"));
  console.log("");
}

async function main(): Promise<void> {
  const [, , cmd, ...rest] = process.argv;

  let exitCode = 0;
  try {
    switch (cmd) {
      case "init":
        exitCode = await runInit();
        break;
      case "audit":
        exitCode = await runAudit(rest);
        break;
      case "dashboard":
        exitCode = await runDashboard(rest);
        break;
      case "doctor":
        exitCode = await runDoctor();
        break;
      case "version":
      case "--version":
      case "-v":
        exitCode = await runVersion();
        break;
      case "help":
      case "--help":
      case "-h":
      case undefined:
        help();
        exitCode = 0;
        break;
      default:
        console.error(c.red(`Unknown command: ${cmd}\n`));
        help();
        exitCode = 2;
    }
  } catch (err) {
    console.error(c.red(`Error: ${err instanceof Error ? err.message : String(err)}`));
    if (process.env.DEBUG) console.error(err);
    exitCode = 2;
  }

  process.exit(exitCode);
}

main();
