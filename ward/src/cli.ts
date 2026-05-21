#!/usr/bin/env node
/**
 * weave-ward CLI
 *
 *   weave-ward init                       Generate a starter WARD.md
 *   weave-ward parse <file>               Print parsed policy as JSON
 *   weave-ward validate <file>            Validate and show issues
 *   weave-ward explain <file>             Human-readable policy summary
 *   weave-ward help
 */

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { parseWard, parseAndValidate } from "./parser/index.js";
import type { WardPolicy } from "./types.js";

// ─────────────────────────────────────────────────────────
// Colors
// ─────────────────────────────────────────────────────────

const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const c = {
  reset: tty ? "\x1b[0m" : "",
  bold: tty ? "\x1b[1m" : "",
  dim: tty ? "\x1b[2m" : "",
  red: tty ? "\x1b[31m" : "",
  green: tty ? "\x1b[32m" : "",
  yellow: tty ? "\x1b[33m" : "",
  blue: tty ? "\x1b[34m" : "",
  cyan: tty ? "\x1b[36m" : "",
  gray: tty ? "\x1b[90m" : "",
};

function banner(): void {
  console.log(`
${c.cyan}${c.bold}🛡️  weave-ward${c.reset}
${c.gray}Agent security policy parser & validator${c.reset}
`);
}

function help(): void {
  banner();
  console.log(`${c.bold}Usage:${c.reset} weave-ward <command> [options]\n`);
  console.log(`${c.bold}Commands:${c.reset}`);
  console.log(`  ${c.cyan}init${c.reset} ${c.gray}[--strict]${c.reset}            Create a starter WARD.md in the current directory`);
  console.log(`  ${c.cyan}parse${c.reset} ${c.gray}<file>${c.reset}              Print parsed policy as JSON`);
  console.log(`  ${c.cyan}validate${c.reset} ${c.gray}<file>${c.reset}           Validate the file and report issues`);
  console.log(`  ${c.cyan}explain${c.reset} ${c.gray}<file>${c.reset}            Human-readable summary of the policy`);
  console.log(`  ${c.cyan}help${c.reset}                       Show this message\n`);
  console.log(`${c.bold}Examples:${c.reset}`);
  console.log(`  ${c.gray}$${c.reset} weave-ward init`);
  console.log(`  ${c.gray}$${c.reset} weave-ward validate WARD.md`);
  console.log(`  ${c.gray}$${c.reset} weave-ward explain ./agents/data-fetcher/WARD.md\n`);
  console.log(`${c.gray}Docs: https://github.com/Tyox-all/Weave_Protocol/tree/main/ward${c.reset}\n`);
}

// ─────────────────────────────────────────────────────────
// Templates
// ─────────────────────────────────────────────────────────

const STARTER_BASIC = `---
ward: "1.0"
agent: my-agent
name: My Agent Security Policy
description: Starter WARD.md - customize for your agent.
---

# WARD.md

Security policy for this agent. Customize the sections below to define
what the agent can and cannot do.

## Filesystem

allow:
  - read: /workspace/**
  - write: /workspace/output/**
deny:
  - read: /workspace/secrets/**
default: deny

## Network

allow:
  - url: "https://api.openai.com/**"
  - url: "https://api.anthropic.com/**"
default: deny

## Capabilities

allow:
  - file_read
  - file_write
  - http_request
deny:
  - shell_exec
  - ssh
default: deny

## Behavioral Limits

maxIterations: 50
maxRuntimeSeconds: 300
maxCostUSD: 5.00
maxTokens: 100000

## Verification

required: true
backend: domere
frequency: session_end

## Incident Response

onViolation:
  - log
  - alert
severityThreshold: medium
`;

const STARTER_STRICT = `---
ward: "1.0"
agent: my-agent
name: Strict Policy (high-security agent)
description: Locked-down policy for agents operating on sensitive systems or data.
---

# WARD.md

Strict security policy. Default-deny everywhere. Approval required for any
elevated action. Mandatory attestation with blockchain anchoring.

## Filesystem

allow:
  - read: /workspace/input/**
  - write: /workspace/output/**
deny:
  - read: /workspace/secrets/**
  - read: ~/.ssh/**
  - read: ~/.aws/**
  - write: /etc/**
  - execute: "**"
default: deny

## Network

allow:
  - url: "https://api.company.com/**"
    methods: [GET]
default: deny

## Capabilities

allow:
  - file_read
  - file_write
requireApproval:
  - http_request
  - code_exec
deny:
  - shell_exec
  - ssh
  - sudo
default: deny

## Data Boundaries

egressAllow:
  - public
  - internal
egressDeny:
  - confidential
  - secret
  - pii
  - phi
  - pci
  - credentials

## Behavioral Limits

maxIterations: 25
maxRuntimeSeconds: 120
maxCostUSD: 2.00
maxTokens: 50000
maxToolCalls: 30
maxExternalServices: 3

## Multi-Agent

isolation: strict
maxSemanticDrift: 0.3

## Verification

required: true
backend: domere
blockchain: solana
frequency: every_action

## Threat Model

inScope:
  - prompt_injection
  - data_exfil
  - credential_theft
  - tool_misuse
  - semantic_drift
  - emergent_behavior

## Incident Response

onViolation:
  - log
  - alert
  - terminate
  - attest_violation
  - notify_human
severityThreshold: low
`;

// ─────────────────────────────────────────────────────────
// Commands
// ─────────────────────────────────────────────────────────

function runInit(args: string[]): number {
  const strict = args.includes("--strict");
  const target = resolve(process.cwd(), "WARD.md");

  if (existsSync(target)) {
    console.error(`${c.red}✗${c.reset} WARD.md already exists at ${target}`);
    console.error(`${c.gray}  Delete it first or use a different directory.${c.reset}`);
    return 1;
  }

  const template = strict ? STARTER_STRICT : STARTER_BASIC;
  writeFileSync(target, template, "utf8");

  console.log(`${c.green}✓${c.reset} Created ${c.cyan}WARD.md${c.reset} ${c.gray}(${strict ? "strict" : "basic"} template)${c.reset}`);
  console.log("");
  console.log(`Next:`);
  console.log(`  ${c.gray}1.${c.reset} Edit ${c.cyan}WARD.md${c.reset} to customize the policy for your agent`);
  console.log(`  ${c.gray}2.${c.reset} Run ${c.cyan}weave-ward validate WARD.md${c.reset} to check for issues`);
  console.log(`  ${c.gray}3.${c.reset} Commit it alongside your AGENTS.md / SKILL.md files`);
  console.log("");
  return 0;
}

function runParse(args: string[]): number {
  const path = args[0];
  if (!path) {
    console.error(`${c.red}✗${c.reset} Usage: weave-ward parse <file>`);
    return 2;
  }
  if (!existsSync(path)) {
    console.error(`${c.red}✗${c.reset} File not found: ${path}`);
    return 2;
  }
  const source = readFileSync(path, "utf8");
  const policy = parseWard(source);
  console.log(JSON.stringify(policy, null, 2));
  return 0;
}

function runValidate(args: string[]): number {
  const path = args[0];
  if (!path) {
    console.error(`${c.red}✗${c.reset} Usage: weave-ward validate <file>`);
    return 2;
  }
  if (!existsSync(path)) {
    console.error(`${c.red}✗${c.reset} File not found: ${path}`);
    return 2;
  }

  banner();
  console.log(`Validating ${c.cyan}${path}${c.reset}...\n`);
  const source = readFileSync(path, "utf8");
  const result = parseAndValidate(source);

  if (result.errors.length > 0) {
    console.log(`${c.red}${c.bold}Errors (${result.errors.length})${c.reset}`);
    for (const e of result.errors) {
      console.log(`  ${c.red}✗${c.reset} ${e.section ? c.gray + `[${e.section}] ` + c.reset : ""}${e.message}`);
      if (e.suggestion) console.log(`    ${c.gray}→ ${e.suggestion}${c.reset}`);
    }
    console.log("");
  }

  if (result.warnings.length > 0) {
    console.log(`${c.yellow}${c.bold}Warnings (${result.warnings.length})${c.reset}`);
    for (const w of result.warnings) {
      console.log(`  ${c.yellow}⚠${c.reset}  ${w.section ? c.gray + `[${w.section}] ` + c.reset : ""}${w.message}`);
      if (w.suggestion) console.log(`    ${c.gray}→ ${w.suggestion}${c.reset}`);
    }
    console.log("");
  }

  if (result.valid && result.warnings.length === 0) {
    console.log(`${c.green}✓ Valid${c.reset} — no errors or warnings.\n`);
    return 0;
  }
  if (result.valid) {
    console.log(`${c.green}✓ Valid${c.reset} ${c.gray}(with ${result.warnings.length} warning(s))${c.reset}\n`);
    return 0;
  }
  console.log(`${c.red}✗ Invalid${c.reset}\n`);
  return 1;
}

function runExplain(args: string[]): number {
  const path = args[0];
  if (!path) {
    console.error(`${c.red}✗${c.reset} Usage: weave-ward explain <file>`);
    return 2;
  }
  if (!existsSync(path)) {
    console.error(`${c.red}✗${c.reset} File not found: ${path}`);
    return 2;
  }

  banner();
  const source = readFileSync(path, "utf8");
  const policy = parseWard(source);
  explainPolicy(policy);
  return 0;
}

function explainPolicy(p: WardPolicy): void {
  const line = (label: string, value: string) =>
    console.log(`  ${c.gray}${label.padEnd(18)}${c.reset} ${value}`);
  const heading = (text: string) => console.log(`\n${c.bold}${text}${c.reset}\n${c.gray}${"─".repeat(60)}${c.reset}`);

  heading("Overview");
  if (p.name) line("Name:", c.cyan + p.name + c.reset);
  if (p.agent) line("Agent:", c.cyan + p.agent + c.reset);
  if (p.description) line("Description:", p.description);
  line("WARD version:", p.version);

  if (p.filesystem) {
    heading("Filesystem");
    line("Default:", p.filesystem.default || "(deny)");
    if (p.filesystem.allow?.length) {
      console.log(`  ${c.green}Allow:${c.reset}`);
      for (const r of p.filesystem.allow) console.log(`    ${c.green}✓${c.reset} ${r.op} ${c.cyan}${r.path}${c.reset}`);
    }
    if (p.filesystem.deny?.length) {
      console.log(`  ${c.red}Deny:${c.reset}`);
      for (const r of p.filesystem.deny) console.log(`    ${c.red}✗${c.reset} ${r.op} ${c.cyan}${r.path}${c.reset}`);
    }
  }

  if (p.network) {
    heading("Network");
    line("Default:", p.network.default || "(deny)");
    if (p.network.allow?.length) {
      console.log(`  ${c.green}Allow:${c.reset}`);
      for (const r of p.network.allow) console.log(`    ${c.green}✓${c.reset} ${c.cyan}${r.url}${c.reset}${r.methods ? c.gray + " [" + r.methods.join(", ") + "]" + c.reset : ""}`);
    }
    if (p.network.deny?.length) {
      console.log(`  ${c.red}Deny:${c.reset}`);
      for (const r of p.network.deny) console.log(`    ${c.red}✗${c.reset} ${c.cyan}${r.url}${c.reset}`);
    }
  }

  if (p.capabilities) {
    heading("Capabilities");
    if (p.capabilities.allow?.length) console.log(`  ${c.green}Allow:${c.reset} ${p.capabilities.allow.join(", ")}`);
    if (p.capabilities.deny?.length) console.log(`  ${c.red}Deny:${c.reset}  ${p.capabilities.deny.join(", ")}`);
    if (p.capabilities.requireApproval?.length) console.log(`  ${c.yellow}Approval:${c.reset} ${p.capabilities.requireApproval.join(", ")}`);
  }

  if (p.behavioral) {
    heading("Behavioral Limits");
    if (p.behavioral.maxIterations !== undefined) line("Max iterations:", String(p.behavioral.maxIterations));
    if (p.behavioral.maxRuntimeSeconds !== undefined) line("Max runtime:", p.behavioral.maxRuntimeSeconds + "s");
    if (p.behavioral.maxCostUSD !== undefined) line("Max cost:", "$" + p.behavioral.maxCostUSD.toFixed(2));
    if (p.behavioral.maxTokens !== undefined) line("Max tokens:", String(p.behavioral.maxTokens));
    if (p.behavioral.maxToolCalls !== undefined) line("Max tool calls:", String(p.behavioral.maxToolCalls));
  }

  if (p.dataBoundaries) {
    heading("Data Boundaries");
    if (p.dataBoundaries.egressAllow?.length) console.log(`  ${c.green}Egress allow:${c.reset} ${p.dataBoundaries.egressAllow.join(", ")}`);
    if (p.dataBoundaries.egressDeny?.length) console.log(`  ${c.red}Egress deny:${c.reset}  ${p.dataBoundaries.egressDeny.join(", ")}`);
  }

  if (p.multiAgent) {
    heading("Multi-Agent");
    if (p.multiAgent.isolation) line("Isolation:", p.multiAgent.isolation);
    if (p.multiAgent.maxSemanticDrift !== undefined) line("Max drift:", String(p.multiAgent.maxSemanticDrift));
    if (p.multiAgent.trustChain?.upstream?.length) line("Upstream:", p.multiAgent.trustChain.upstream.join(", "));
    if (p.multiAgent.trustChain?.downstream?.length) line("Downstream:", p.multiAgent.trustChain.downstream.join(", "));
  }

  if (p.compliance) {
    heading("Compliance");
    if (p.compliance.frameworks?.length) line("Frameworks:", p.compliance.frameworks.join(", ").toUpperCase());
    if (p.compliance.backend) line("Backend:", p.compliance.backend);
  }

  if (p.verification) {
    heading("Verification");
    line("Required:", p.verification.required ? c.green + "yes" + c.reset : c.gray + "no" + c.reset);
    if (p.verification.backend) line("Backend:", p.verification.backend);
    if (p.verification.blockchain) line("Blockchain:", p.verification.blockchain);
    if (p.verification.frequency) line("Frequency:", p.verification.frequency);
  }

  if (p.threatModel) {
    heading("Threat Model");
    if (p.threatModel.inScope?.length) console.log(`  ${c.green}In scope:${c.reset}     ${p.threatModel.inScope.join(", ")}`);
    if (p.threatModel.outOfScope?.length) console.log(`  ${c.gray}Out of scope:${c.reset} ${p.threatModel.outOfScope.join(", ")}`);
  }

  if (p.incidentResponse) {
    heading("Incident Response");
    if (p.incidentResponse.severityThreshold) line("Threshold:", p.incidentResponse.severityThreshold);
    if (p.incidentResponse.onViolation?.length) {
      console.log(`  ${c.red}On violation:${c.reset}`);
      for (const a of p.incidentResponse.onViolation) {
        console.log(`    ${c.red}●${c.reset} ${a.type}${a.minSeverity ? c.gray + " (min: " + a.minSeverity + ")" + c.reset : ""}`);
      }
    }
  }

  console.log("");
}

// ─────────────────────────────────────────────────────────
// Router
// ─────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const [, , cmd, ...rest] = process.argv;
  let code = 0;

  try {
    switch (cmd) {
      case "init":
        code = runInit(rest);
        break;
      case "parse":
        code = runParse(rest);
        break;
      case "validate":
        code = runValidate(rest);
        break;
      case "explain":
        code = runExplain(rest);
        break;
      case "help":
      case "--help":
      case "-h":
      case undefined:
        help();
        break;
      default:
        console.error(`${c.red}Unknown command: ${cmd}${c.reset}\n`);
        help();
        code = 2;
    }
  } catch (err) {
    console.error(`${c.red}Error: ${err instanceof Error ? err.message : String(err)}${c.reset}`);
    if (process.env.DEBUG) console.error(err);
    code = 2;
  }

  process.exit(code);
}

main();
