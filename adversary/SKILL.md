# ⚔️ Adversary skill — offensive testing for AI agents

You have access to `@weave_protocol/adversary` — a package that generates 68 documented and novel attacks against AI agents and produces standardized scorecards.

## When to invoke

Use Adversary when the user:
- Wants to test an AI agent's security posture
- Is reviewing/auditing a WARD.md policy and wants to verify it holds
- Is preparing for a release and wants a regression check on safety
- Asks about agent red-teaming, prompt injection testing, or jailbreak resistance
- Wants to generate a scorecard for compliance / vendor review

## What's in the corpus

- **33 IPI** (indirect prompt injection) — hostile content patterns from documented in-the-wild attacks (Atlan, EchoLeak, Brave/Comet)
- **15 tool-use coercion** — direct attempts to call dangerous tools
- **10 jailbreak templates** — DAN, AIM, developer mode, grandma exploit
- **5 prompt/policy extraction** — system prompt leakage, WARD enumeration
- **5 goal corruption** — mid-task pivots, fake authority, temporal manipulation

All severity-graded (critical / high / medium / low). All mapped to WARD policy domains.

## Key commands

```bash
# Run the full corpus against the built-in demo agent
weave-adversary demo

# List the corpus, filter by severity
weave-adversary list --severity=critical

# Save scorecard outputs
weave-adversary demo --json=./scorecard.json --md=./scorecard.md

# Limit scope
weave-adversary demo --category=ipi --per-category=10
```

## WARD-aware mode

If a `WARD.md` is present in the cwd, Adversary auto-loads it and prioritizes attacks that probe the rules the policy claims to enforce. This is the key differentiator — the scorecard tells you whether your stated controls actually hold.

## When NOT to use

- For real-time agent monitoring (use `@weave_protocol/hundredmen` or the harness adapters)
- For content scanning during an agent run (use `@weave_protocol/browser` or `@weave_protocol/mund`)
- Without a clear target — Adversary is a test tool; running it against random endpoints is noise

## Programmatic use

```typescript
import { AdversarialAgent, DemoTarget } from '@weave_protocol/adversary';
const agent = new AdversarialAgent(new DemoTarget());
const scorecard = await agent.run({ categories: ['ipi'], perCategoryLimit: 10 });
```

The scorecard JSON schema is locked at v1.0 — designed for AgentSecBench ingestion.
