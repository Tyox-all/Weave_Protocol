# ⚔️ Adversary skill — offensive testing for AI agents

You have access to `@weave_protocol/adversary` v0.2 — a package that generates 68 documented and novel attacks against AI agents and produces standardized scorecards.

## When to invoke

Use Adversary when the user:
- Wants to test an AI agent's security posture
- Is reviewing/auditing a WARD.md policy and wants to verify it holds
- Is preparing for a release and wants a regression check on safety
- Asks about agent red-teaming, prompt injection testing, or jailbreak resistance
- Wants to generate a scorecard for compliance / vendor review
- Has a real running agent (HTTP endpoint, CLI executable, or browser-driving code) — use the `attack` command for real-world testing

## What's in the corpus

- **33 IPI** (indirect prompt injection) — Atlan, EchoLeak, Brave/Comet
- **15 tool-use coercion** — direct attempts to call dangerous tools
- **10 jailbreak templates** — DAN, AIM, developer mode, grandma
- **5 prompt/policy extraction** — system prompt leakage, WARD enumeration
- **5 goal corruption** — mid-task pivots, fake authority, temporal manipulation

All severity-graded (critical/high/medium/low). All mapped to WARD policy domains.

## Key commands

```bash
# Run the full corpus against the built-in demo
weave-adversary demo

# NEW v0.2: attack a real agent via HTTP endpoint
weave-adversary attack --url=https://my-agent.example.com/run

# NEW v0.2: attack a CLI agent (spawned as subprocess)
weave-adversary attack --executable=./my-agent-cli

# Filter scope
weave-adversary attack --url=... --category=ipi --per-category=10

# Save outputs
weave-adversary attack --url=... --json=./scorecard.json --md=./scorecard.md
```

The `attack` command requires Playwright (`npm install playwright && npx playwright install chromium`). The CLI prints a red callout with the exact install commands if it's missing.

## Four breach signal channels (v0.2 PlaywrightTarget)

When running `attack`, Adversary observes the real browser session for:

1. **Network requests** — outbound HTTP triggered by the agent
2. **Form submissions** — `<form action="...">` posts including field names + values
3. **DOM mutations** — via injected MutationObserver (catches localStorage/sessionStorage writes too)
4. **Console output** — page console.log/warn/error

Any of these matching the attack's detection patterns counts as a breach.

## WARD-aware mode

If a `WARD.md` is present, Adversary auto-loads it and prioritizes attacks that probe the rules the policy claims to enforce. This is the differentiator.

## When NOT to use

- For real-time agent monitoring (use Hundredmen or the harness adapters)
- For content scanning during an agent run (use browser or Mund)
- Without a clear target — Adversary is a test tool, not a noise generator

## Programmatic API

```typescript
import { AdversarialAgent, DemoTarget, PlaywrightTarget } from '@weave_protocol/adversary';

// Mock (no API key, no Playwright)
const agent = new AdversarialAgent(new DemoTarget());

// Real browser (requires Playwright peer dep)
const real = new AdversarialAgent(new PlaywrightTarget({
  agentEndpoint: 'https://my-agent.example.com/run',
  browserType: 'chromium',
}));

const scorecard = await real.run({ categories: ['ipi'] });
```

Scorecard schema is locked at v1.0 — designed for AgentSecBench ingestion.
