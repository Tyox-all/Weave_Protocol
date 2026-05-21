# 🛡️ @weave_protocol/ward

[![npm version](https://img.shields.io/npm/v/@weave_protocol/ward.svg)](https://www.npmjs.com/package/@weave_protocol/ward)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/ward.svg)](https://www.npmjs.com/package/@weave_protocol/ward)
[![license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**WARD.md — the agent security policy standard.**

> *AGENTS.md tells your agent what to do.*
> *SKILL.md tells your agent how to do it.*
> ***WARD.md tells your agent what it can't.***

Part of the [Weave Protocol](https://github.com/Tyox-all/Weave_Protocol) security suite.

```bash
npm install @weave_protocol/ward
```

---

## What is WARD.md?

Agents are now infrastructure-as-code. They're defined in markdown files
(`AGENTS.md`, `SKILL.md`), version-controlled, and shared across registries.

If agent *behavior* is declared in a file, agent *security* should be too.

**WARD.md** is a standard format for declaring the security policy of an
AI agent. It lives next to `AGENTS.md` and `SKILL.md` in the same repo,
and is read by harnesses (Antigravity, Claude Code, MDASH) and runtime
enforcers (Mund, Hundredmen, Dōmere) to keep the agent inside its lane.

```
my-agent-project/
├── AGENTS.md          # what the agent does
├── SKILL.md           # how the agent does it
├── WARD.md            # what the agent can't do  ← this package
└── .weave/
    └── attestations/  # cryptographic proofs that the policy held
```

---

## Quick start

```bash
# Generate a starter WARD.md
npx @weave_protocol/ward init

# Validate it
npx @weave_protocol/ward validate WARD.md

# Show a human-readable summary
npx @weave_protocol/ward explain WARD.md
```

---

## A minimal WARD.md

```markdown
---
ward: "1.0"
agent: my-data-analyzer
---

# WARD.md

## Filesystem
allow:
  - read: /workspace/**
  - write: /workspace/output/**
deny:
  - read: /workspace/secrets/**
default: deny

## Network
deny:
  - url: "**"
default: deny

## Capabilities
allow:
  - file_read
  - file_write
deny:
  - shell_exec
default: deny

## Behavioral Limits
maxIterations: 50
maxRuntimeSeconds: 300
maxCostUSD: 5.00

## Verification
required: true
backend: domere
frequency: session_end
```

That's a complete policy. The agent can read inputs and write outputs, can't
touch secrets, can't make network calls, can't shell out, can't burn more
than $5 or run for more than 5 minutes — and every action is attested at
session end.

---

## Programmatic use

```typescript
import { parseWard, checkFilesystem, checkNetwork, checkCapability } from "@weave_protocol/ward";
import { readFileSync } from "node:fs";

const policy = parseWard(readFileSync("./WARD.md", "utf8"));

// Before any filesystem action:
const fs = checkFilesystem(policy, "read", "/workspace/secrets/keys.txt");
if (fs.decision !== "allow") throw new Error(fs.reason);

// Before any network call:
const net = checkNetwork(policy, "https://api.evil.com/exfil", "POST");
if (net.decision !== "allow") throw new Error(net.reason);

// Before any tool invocation:
const cap = checkCapability(policy, "shell_exec");
if (cap.decision === "require_approval") {
  await promptHuman("shell_exec needs your approval");
} else if (cap.decision === "deny") {
  throw new Error(cap.reason);
}
```

Every check returns `{ decision: "allow" | "deny" | "require_approval", reason, severity }`
so hosts can decide whether to block, log, prompt, or attest.

---

## Policy sections

WARD.md is markdown with YAML frontmatter. Each top-level section maps
to a typed sub-policy:

| Section | Controls |
|---------|----------|
| `## Filesystem` | Read/write/execute/delete/list rules with glob patterns |
| `## Network` | Outbound HTTP allowlist with optional method restrictions |
| `## Capabilities` | Tools the agent may invoke (with optional approval gating) |
| `## Data Boundaries` | Egress classifications (PII, PHI, credentials...) and redaction |
| `## Behavioral Limits` | Iterations, runtime, cost, tokens, tool calls, external services |
| `## Multi-Agent` | Trust chain, isolation level, semantic drift threshold |
| `## Compliance` | SOC2 / HIPAA / GDPR / CCPA / ISO27001 / PCI-DSS frameworks |
| `## Verification` | Attestation backend (Dōmere), blockchain, frequency |
| `## Threat Model` | Which threats this policy is designed against |
| `## Incident Response` | What to do when a violation occurs |

See [SPEC.md](./SPEC.md) for the full specification.

---

## CLI

```bash
weave-ward init [--strict]    Create a starter WARD.md (basic or strict template)
weave-ward parse <file>       Print parsed policy as JSON
weave-ward validate <file>    Validate the file and report issues
weave-ward explain <file>     Human-readable summary
weave-ward help               Show help
```

Exit codes for `validate`: `0` = valid, `1` = invalid, `2` = usage error.
Use in CI to gate PRs that change agent policies.

---

## Examples

The package ships with three example WARD.md files:

- [`examples/basic.WARD.md`](./examples/basic.WARD.md) — read-only data analyzer
- [`examples/strict.WARD.md`](./examples/strict.WARD.md) — locked-down production deployer
- [`examples/compliance.WARD.md`](./examples/compliance.WARD.md) — HIPAA + SOC2 healthcare records agent

---

## Why a standard?

The harness wars are on. Google has Antigravity. Microsoft has MDASH.
Anthropic has Claude Code. Every major platform is building its own
orchestration layer. Their agent definition formats differ slightly, but
they're all converging on the same idea: **agents as files**.

What's missing is a portable, declarative way to say *what an agent isn't
allowed to do*. Today every harness rolls its own ad-hoc allowlist somewhere
in a config file. That doesn't survive cross-platform agent sharing, doesn't
gate at PR review time, and isn't cryptographically attestable.

WARD.md is the format that does all three.

---

## Status

**v0.1 (this release):** parser, validator, type system, CLI, runtime check
primitives (`checkFilesystem`, `checkNetwork`, `checkCapability`,
`checkDataEgress`, `checkBehavioral`).

**Coming next:** platform adapters for Antigravity / Claude Code / MDASH,
integration with Mund's scanner, Dōmere attestation hooks, MCP server.

---

## License

Apache 2.0 — see [LICENSE](../LICENSE).
