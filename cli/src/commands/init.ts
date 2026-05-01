/**
 * `weave init` — interactive project setup.
 *
 * 1. Detects framework (LangChain/LlamaIndex/MCP/OpenAI/Anthropic/raw)
 * 2. Asks user to confirm or override
 * 3. Asks which Weave packages to enable
 * 4. Generates security middleware code, .weaverc, and install command
 * 5. Optionally writes Claude Desktop MCP config block
 */

import { existsSync, writeFileSync, readFileSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { c, banner, header, divider, symbols } from "../utils/colors.js";
import { confirm, select, multiSelect } from "../utils/prompt.js";
import { detectPackageManager, installCommand, devInstallCommand } from "../utils/package-manager.js";
import { detectFramework, frameworkLabel, type Framework } from "../detect/framework.js";
import { getScaffold } from "../scaffolds/index.js";
import type { WeavePackage, ScaffoldOptions } from "../scaffolds/types.js";

const ALL_PACKAGES: Array<{
  value: WeavePackage;
  label: string;
  emoji: string;
  hint: string;
  defaultOn: boolean;
}> = [
  { value: "tollere",    emoji: "🛂", label: "Tollere",    hint: "Supply chain security (npm/Docker/extensions)", defaultOn: true },
  { value: "mund",       emoji: "🛡️", label: "Mund",       hint: "Input/output threat scanning",                  defaultOn: true },
  { value: "hord",       emoji: "🏛️", label: "Hord",       hint: "Encrypted vault for secrets",                   defaultOn: false },
  { value: "domere",     emoji: "⚖️", label: "Domere",     hint: "Compliance + blockchain anchoring",             defaultOn: false },
  { value: "witan",      emoji: "👥", label: "Witan",      hint: "Multi-agent consensus",                         defaultOn: false },
  { value: "hundredmen", emoji: "🔍", label: "Hundredmen", hint: "Real-time MCP proxy + drift detection",         defaultOn: false },
  { value: "langchain",  emoji: "🔗", label: "Langchain",  hint: "LangChain.js callbacks",                        defaultOn: false },
  { value: "api",        emoji: "🔌", label: "API",        hint: "REST API + monitoring dashboard",               defaultOn: false },
];

function recommendedDefaults(framework: Framework): WeavePackage[] {
  switch (framework) {
    case "langchain-js":
      return ["tollere", "mund", "langchain"];
    case "mcp-server":
      return ["tollere", "mund", "hundredmen"];
    case "anthropic-sdk":
    case "openai-sdk":
    case "vercel-ai":
    case "ai-sdk":
      return ["tollere", "mund"];
    case "llamaindex-js":
      return ["tollere", "mund"];
    default:
      return ["tollere", "mund"];
  }
}

export async function runInit(): Promise<number> {
  console.log(banner());

  const cwd = process.cwd();
  const detection = detectFramework(cwd);

  // ──────────────────────────────────────────────────────
  // 1. Show what we found
  // ──────────────────────────────────────────────────────
  console.log(header("Detected"));
  console.log(`  ${symbols.bullet} Project root:  ${c.cyan(cwd)}`);
  console.log(`  ${symbols.bullet} Language:      ${c.cyan(detection.language)}`);
  console.log(`  ${symbols.bullet} Framework:     ${c.cyan(frameworkLabel(detection.primary))}`);
  if (detection.detected.length > 1) {
    const others = detection.detected.filter((f) => f !== detection.primary).map(frameworkLabel);
    console.log(`  ${symbols.bullet} Also detected: ${c.gray(others.join(", "))}`);
  }

  if (detection.isPython) {
    console.log("");
    console.log(c.yellow(`${symbols.warning}  Python project detected.`));
    console.log(c.gray("   The CLI scaffolds JavaScript/TypeScript today. For Python, install"));
    console.log(c.gray(`   ${c.bold("weave-protocol-llamaindex")} from PyPI directly.`));
    return 0;
  }

  if (!detection.hasPackageJson) {
    console.log("");
    console.log(c.yellow(`${symbols.warning}  No package.json found in this directory.`));
    const proceed = await confirm("Create one and continue?", false);
    if (!proceed) {
      console.log(c.gray("Aborted."));
      return 0;
    }
    writeFileSync(
      join(cwd, "package.json"),
      JSON.stringify({ name: "my-agent", version: "0.0.1", type: "module" }, null, 2),
    );
    console.log(c.green(`${symbols.check} Created package.json`));
  }

  // ──────────────────────────────────────────────────────
  // 2. Confirm framework
  // ──────────────────────────────────────────────────────
  console.log("");
  const useFramework = await select<Framework>(
    "Which framework should we configure for?",
    [
      { value: detection.primary, label: `${frameworkLabel(detection.primary)} ${c.gray("(detected)")}` },
      { value: "langchain-js", label: "LangChain.js" },
      { value: "anthropic-sdk", label: "Anthropic SDK" },
      { value: "openai-sdk", label: "OpenAI SDK" },
      { value: "mcp-server", label: "MCP Server" },
      { value: "raw", label: "None / generic" },
    ],
    0,
  );

  // ──────────────────────────────────────────────────────
  // 3. Select packages
  // ──────────────────────────────────────────────────────
  console.log("");
  const recommended = recommendedDefaults(useFramework);
  const selectedPackages = await multiSelect<WeavePackage>(
    "Which Weave Protocol packages do you want?",
    ALL_PACKAGES.map((p) => ({
      value: p.value,
      label: `${p.emoji} ${p.label}`,
      hint: p.hint,
    })),
    recommended,
  );

  if (selectedPackages.length === 0) {
    console.log(c.yellow("No packages selected. Nothing to do."));
    return 0;
  }

  // ──────────────────────────────────────────────────────
  // 4. Generate scaffold
  // ──────────────────────────────────────────────────────
  const language = detection.language === "typescript" ? "typescript" : "javascript";
  const opts: ScaffoldOptions = {
    language,
    selectedPackages,
    framework: useFramework,
  };
  const output = getScaffold(useFramework, opts);

  console.log(header("Plan"));
  console.log(`  ${symbols.bullet} Install ${c.cyan(String(output.packages.length))} package(s):`);
  for (const p of output.packages) console.log(`     ${c.gray("•")} ${p}`);

  if (output.files.length > 0) {
    console.log(`  ${symbols.bullet} Create ${c.cyan(String(output.files.length))} file(s):`);
    for (const f of output.files) console.log(`     ${c.gray("•")} ${c.cyan(f.path)} ${c.gray(`— ${f.description}`)}`);
  }

  console.log(`  ${symbols.bullet} Write ${c.cyan(".weaverc")} configuration file`);

  console.log("");
  const proceed = await confirm("Proceed?", true);
  if (!proceed) {
    console.log(c.gray("Aborted. Nothing was written."));
    return 0;
  }

  // ──────────────────────────────────────────────────────
  // 5. Write files
  // ──────────────────────────────────────────────────────
  console.log("");
  for (const file of output.files) {
    const fullPath = resolve(cwd, file.path);
    if (existsSync(fullPath)) {
      const ow = await confirm(`${file.path} exists. Overwrite?`, false);
      if (!ow) {
        console.log(c.gray(`  ${symbols.bullet} Skipped ${file.path}`));
        continue;
      }
    }
    mkdirSync(dirname(fullPath), { recursive: true });
    writeFileSync(fullPath, file.content, "utf8");
    console.log(c.green(`  ${symbols.check} Wrote ${file.path}`));
  }

  // .weaverc
  const rcPath = join(cwd, ".weaverc");
  let existingRC: Record<string, unknown> = {};
  if (existsSync(rcPath)) {
    try {
      existingRC = JSON.parse(readFileSync(rcPath, "utf8"));
    } catch {
      // start fresh
    }
  }
  const config: Record<string, unknown> = {
    ...existingRC,
    version: "0.1.0",
    framework: useFramework,
    language,
    packages: selectedPackages,
    generatedAt: new Date().toISOString(),
  };
  for (const entry of output.configEntries) {
    config[entry.key] = entry.value;
  }
  writeFileSync(rcPath, JSON.stringify(config, null, 2) + "\n", "utf8");
  console.log(c.green(`  ${symbols.check} Wrote .weaverc`));

  // ──────────────────────────────────────────────────────
  // 6. Install command
  // ──────────────────────────────────────────────────────
  console.log(header("Install"));
  const pm = detectPackageManager(cwd);
  const installCmd = installCommand(output.packages, pm);
  console.log(`  ${c.gray("Run:")}`);
  console.log(`    ${c.cyan(installCmd)}`);

  // ──────────────────────────────────────────────────────
  // 7. Next steps
  // ──────────────────────────────────────────────────────
  if (output.nextSteps.length > 0) {
    console.log(header("Next steps"));
    for (const step of output.nextSteps) {
      console.log(`  ${c.cyan(symbols.arrow)} ${step}`);
    }
  }

  console.log("");
  console.log(c.green(c.bold(`✨  Weave Protocol initialized!`)));
  console.log("");
  return 0;
}
