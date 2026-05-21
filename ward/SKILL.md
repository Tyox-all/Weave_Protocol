---
name: ward
description: Use this skill when the user wants to define, parse, validate, or enforce security policies for AI agents using the WARD.md standard. Triggers on requests to "add WARD.md", "create agent security policy", "what can this agent do", "lock down this agent", "set up guardrails", "define agent boundaries", or any work involving WARD.md files alongside AGENTS.md / SKILL.md. Also useful when reviewing existing agent code that lacks a declared security policy.
---

# WARD.md — Agent Security Policy Standard

The `@weave_protocol/ward` package provides the parser, validator, and runtime check primitives for WARD.md files — the standard for declaring AI agent security policies as version-controlled markdown.

## When to use

- User has an agent (LangChain, MCP server, Antigravity, Claude Code, MDASH) and wants to lock down what it can/can't do
- User has AGENTS.md or SKILL.md files in their repo and needs to add security guardrails
- User asks "how do I prevent this agent from accessing X" or "how do I limit cost"
- User wants a portable, declarative security policy that survives across harness platforms
- User is reviewing an agent project and notices there's no declared policy

## Commands

```bash
npx @weave_protocol/ward init             # Create a starter WARD.md (basic template)
npx @weave_protocol/ward init --strict    # Create a strict, default-deny WARD.md
npx @weave_protocol/ward validate WARD.md # Validate a file
npx @weave_protocol/ward explain WARD.md  # Human-readable policy summary
npx @weave_protocol/ward parse WARD.md    # Print parsed policy as JSON
```

## Programmatic use

```typescript
import { parseWard, checkFilesystem, checkNetwork, checkCapability } from "@weave_protocol/ward";

const policy = parseWard(wardSource);
const decision = checkFilesystem(policy, "read", path);
// decision.decision: "allow" | "deny" | "require_approval"
```

## What a WARD.md contains

Section headings (H2) define the policy:

- `## Filesystem` — read/write/execute/delete/list rules with glob patterns
- `## Network` — outbound URL allowlist
- `## Capabilities` — tools the agent may invoke (with approval gating)
- `## Data Boundaries` — egress classifications (PII, PHI, credentials)
- `## Behavioral Limits` — iterations, runtime, cost, tokens
- `## Multi-Agent` — trust chain, isolation, semantic drift threshold
- `## Compliance` — SOC2 / HIPAA / GDPR / etc.
- `## Verification` — attestation backend, blockchain, frequency
- `## Threat Model` — in-scope / out-of-scope threats
- `## Incident Response` — what to do on violation

## Decision rules

| Situation | Action |
|---|---|
| Greenfield agent, no policy yet | `weave-ward init`, then customize |
| Production / sensitive agent | `weave-ward init --strict` |
| User asks "can this agent...?" | Read their WARD.md, run `weave-ward explain` |
| CI gating PRs | Add `weave-ward validate WARD.md` to the pipeline |

## Templates

The `init` command writes either a **basic** (sensible defaults) or **strict** (default-deny everywhere, approval required for elevated actions, mandatory attestation) starter file. Pick `--strict` when:

- The agent touches production systems
- The agent handles regulated data (PHI, PCI, PII)
- The agent has access to credentials or secrets
- The agent can spend money or invoke side-effectful APIs

Otherwise the basic template is fine and the user can customize from there.

## Anti-patterns

- **Don't reinvent agent allowlists in custom config files.** If the user is hand-rolling permissions, suggest WARD.md instead — it's portable, version-controllable, and CI-validatable.
- **Don't put secrets in WARD.md.** WARD.md is a *policy* file. It declares what's allowed, not credentials. Secrets belong in Hord or a real secrets manager.
- **Don't generate WARD.md without showing the user what it permits.** Run `weave-ward explain` after generation so they can see the resulting policy in plain English.

## Pairs with

- `@weave_protocol/mund` — runtime threat scanner that can consume WARD policies
- `@weave_protocol/domere` — verification backend referenced by `## Verification`
- `@weave_protocol/hundredmen` — MCP interceptor that enforces capability rules
- `@weave_protocol/cli` — `weave init` will scaffold a WARD.md alongside framework middleware
