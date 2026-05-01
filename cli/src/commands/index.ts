/**
 * `weave audit` — delegates to Tollere to scan the project for supply chain risk.
 * `weave dashboard` — launches the API server + opens browser to /dashboard.
 * `weave doctor` — checks the local environment for common config issues.
 * `weave version` — prints the CLI version + (best effort) installed package versions.
 */

import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { c, banner, header, symbols } from "../utils/colors.js";

// ─────────────────────────────────────────────────────────────
// audit — calls into tollere
// ─────────────────────────────────────────────────────────────
export async function runAudit(args: string[]): Promise<number> {
  const cwd = process.cwd();
  console.log(banner());
  console.log(`${c.cyan("🛂")} Running Tollere supply chain audit on ${c.cyan(cwd)}\n`);

  // Dynamic import so the CLI works even if tollere isn't installed yet
  // (we depend on it, but in dev/local checkouts it might not be linked)
  let scanPackageJson: typeof import("@weave_protocol/tollere").scanPackageJson;
  try {
    const tollere = await import("@weave_protocol/tollere");
    scanPackageJson = tollere.scanPackageJson;
  } catch (e) {
    console.error(c.red(`${symbols.cross} @weave_protocol/tollere is not installed.`));
    console.error(c.gray(`   Run: npm install @weave_protocol/tollere`));
    return 2;
  }

  const pkgPath = args[0] ? resolve(cwd, args[0]) : join(cwd, "package.json");
  if (!existsSync(pkgPath)) {
    console.error(c.red(`${symbols.cross} package.json not found at ${pkgPath}`));
    return 2;
  }

  const contents = readFileSync(pkgPath, "utf8");
  const report = await scanPackageJson(contents);

  console.log(`Scanned ${c.bold(String(report.totalPackages))} packages in ${report.scanDurationMs}ms\n`);

  if (report.blockedPackages.length > 0) {
    console.log(c.red(c.bold(`❌  BLOCKED (${report.blockedPackages.length})`)));
    for (const p of report.blockedPackages) {
      console.log(`   ${c.red("●")} ${c.bold(p.name)}@${p.version} — ${p.issues[0]?.description}`);
    }
    console.log("");
  }
  if (report.warnedPackages.length > 0) {
    console.log(c.yellow(c.bold(`⚠️   WARNINGS (${report.warnedPackages.length})`)));
    for (const p of report.warnedPackages) {
      console.log(`   ${c.yellow("●")} ${c.bold(p.name)}@${p.version} — ${p.issues[0]?.description}`);
    }
    console.log("");
  }

  const summaryColor = report.recommendation === "BLOCK_INSTALL" ? c.red : report.recommendation === "REVIEW_REQUIRED" ? c.yellow : c.green;
  console.log(`Recommendation: ${summaryColor(c.bold(report.recommendation))}\n`);

  if (report.recommendation === "BLOCK_INSTALL") return 2;
  if (report.recommendation === "REVIEW_REQUIRED") return 1;
  return 0;
}

// ─────────────────────────────────────────────────────────────
// dashboard — launches the api and opens the browser
// ─────────────────────────────────────────────────────────────
export async function runDashboard(args: string[]): Promise<number> {
  console.log(banner());

  const port = args.find((a) => a.startsWith("--port="))?.split("=")[1] || process.env.WEAVE_PORT || "3000";
  console.log(`${c.cyan("🔌")} Starting Weave API on ${c.cyan(`http://localhost:${port}`)}`);
  console.log(c.gray("   Press Ctrl+C to stop.\n"));

  // Start the API via npx so we don't need a local install
  const child = spawn("npx", ["-y", "@weave_protocol/api"], {
    stdio: "inherit",
    env: { ...process.env, WEAVE_PORT: port },
    shell: process.platform === "win32",
  });

  // Open the browser after a short delay
  setTimeout(() => {
    const url = `http://localhost:${port}/dashboard`;
    const opener =
      process.platform === "darwin" ? "open" :
      process.platform === "win32" ? "start" :
      "xdg-open";
    spawn(opener, [url], { stdio: "ignore", detached: true, shell: process.platform === "win32" }).unref();
    console.log(`${c.green(symbols.check)} Opened ${c.cyan(url)} in your browser.\n`);
  }, 1500);

  return new Promise((resolveExit) => {
    child.on("exit", (code) => resolveExit(code ?? 0));
  });
}

// ─────────────────────────────────────────────────────────────
// doctor — environment check
// ─────────────────────────────────────────────────────────────
export async function runDoctor(): Promise<number> {
  console.log(banner());
  console.log(header("Environment check"));

  const cwd = process.cwd();
  const checks: Array<{ name: string; ok: boolean; detail: string }> = [];

  // Node version
  const nodeMajor = parseInt(process.versions.node.split(".")[0], 10);
  checks.push({
    name: "Node.js >= 18",
    ok: nodeMajor >= 18,
    detail: `v${process.versions.node}`,
  });

  // package.json
  const hasPkg = existsSync(join(cwd, "package.json"));
  checks.push({
    name: "package.json present",
    ok: hasPkg,
    detail: hasPkg ? "" : "run `npm init` first",
  });

  // .weaverc
  const hasRC = existsSync(join(cwd, ".weaverc"));
  checks.push({
    name: ".weaverc present",
    ok: hasRC,
    detail: hasRC ? "" : "run `weave init`",
  });

  // Weave packages
  if (hasPkg) {
    const pkg = JSON.parse(readFileSync(join(cwd, "package.json"), "utf8"));
    const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    const weaveDeps = Object.keys(deps).filter((d) => d.startsWith("@weave_protocol/") || d === "weave-protocol-llamaindex");
    checks.push({
      name: "At least one Weave package installed",
      ok: weaveDeps.length > 0,
      detail: weaveDeps.length > 0 ? weaveDeps.join(", ") : "run `weave init`",
    });
  }

  // Claude Desktop config
  const home = process.env.HOME || process.env.USERPROFILE || "";
  const claudeConfig =
    process.platform === "darwin"
      ? join(home, "Library/Application Support/Claude/claude_desktop_config.json")
      : process.platform === "win32"
        ? join(home, "AppData/Roaming/Claude/claude_desktop_config.json")
        : join(home, ".config/Claude/claude_desktop_config.json");
  const hasClaudeConfig = existsSync(claudeConfig);
  if (hasClaudeConfig) {
    try {
      const cc = JSON.parse(readFileSync(claudeConfig, "utf8"));
      const mcpServers = Object.keys(cc.mcpServers || {});
      const weaveMcp = mcpServers.filter((n) =>
        ["mund", "hord", "domere", "witan", "hundredmen", "tollere"].includes(n),
      );
      checks.push({
        name: "Claude Desktop MCP servers",
        ok: weaveMcp.length > 0,
        detail: weaveMcp.length > 0 ? `${weaveMcp.length} configured: ${weaveMcp.join(", ")}` : "no Weave MCPs in claude_desktop_config.json",
      });
    } catch {
      checks.push({ name: "Claude Desktop config", ok: false, detail: "config exists but is not valid JSON" });
    }
  }

  console.log("");
  for (const check of checks) {
    const icon = check.ok ? c.green(symbols.check) : c.red(symbols.cross);
    const detail = check.detail ? c.gray(`— ${check.detail}`) : "";
    console.log(`  ${icon} ${check.name} ${detail}`);
  }
  console.log("");

  const failed = checks.filter((c) => !c.ok).length;
  return failed > 0 ? 1 : 0;
}

// ─────────────────────────────────────────────────────────────
// version
// ─────────────────────────────────────────────────────────────
export async function runVersion(): Promise<number> {
  // CLI version is hard to read at runtime in ESM; ship it inlined via constant.
  const CLI_VERSION = "0.1.0";

  console.log(banner());
  console.log(`  ${c.bold("CLI")}                      ${c.cyan(`v${CLI_VERSION}`)}`);

  const pkgs = [
    "@weave_protocol/mund",
    "@weave_protocol/hord",
    "@weave_protocol/domere",
    "@weave_protocol/witan",
    "@weave_protocol/hundredmen",
    "@weave_protocol/tollere",
    "@weave_protocol/langchain",
    "@weave_protocol/api",
    "@weave_protocol/full",
  ];

  for (const p of pkgs) {
    try {
      const mod = await import(`${p}/package.json`, { with: { type: "json" } });
      const v = (mod.default as { version?: string }).version || "?";
      console.log(`  ${p.padEnd(28)} ${c.cyan(`v${v}`)}`);
    } catch {
      console.log(`  ${p.padEnd(28)} ${c.gray("not installed")}`);
    }
  }
  console.log("");
  return 0;
}
