# 🎯 AgentSecBench skill — standardized agent security benchmarking

You have access to `@weave_protocol/agentsecbench` — a benchmark package that runs locked, versioned attack suites against AI agents and produces tier-graded reports.

## When to invoke

Use AgentSecBench when the user:
- Wants a **citable score** for an agent ("Tier B, 87/100 on ASB-Browser-v1")
- Asks to **compare two agents** or two versions of the same agent
- Needs a **paste-ready security review** artifact for a blog, RFP, or audit
- Asks whether their **WARD policy actually does anything**
- Wants to detect a **regression** between runs (e.g. in CI)

For raw attack execution without the interpretation layer, use `@weave_protocol/adversary` directly instead.

## Key commands

```bash
# Run the canonical browser suite
agentsecbench run --suite=ASB-Browser-v1

# Save report
agentsecbench run --json=./report.json --md=./report.md

# Measure WARD contribution (runs twice)
agentsecbench run --measure-ward-delta

# Compare two reports
agentsecbench compare baseline.json new.json

# Show suite info / list suites
agentsecbench suite ASB-Browser-v1
agentsecbench suite  # lists all
```

## What's in a Report

- **Tier** (A/B/C/D/F) — headline grade
- **Score** (0-100) — raw Adversary score
- **Category gaps** — which attack classes failed
- **Trophy performance** — pass/fail against 4 named real-world attacks (Atlan, EchoLeak, Brave/Comet, Forcepoint)
- **WARD delta** (optional) — does the policy contribute to defense?
- **Interpretation prose** — paste-ready summary
- **Full Adversary scorecard** — embedded for auditability

## Suites are locked

`ASB-Browser-v1`'s 40 attacks will never change. Methodology improvements ship as `ASB-Browser-v2`. This is the central property that makes scores comparable.

## Programmatic API

```typescript
import { runSuite, ASB_BROWSER_V1, renderMarkdownReport } from '@weave_protocol/agentsecbench';
import { BrowserTarget } from '@weave_protocol/adversary';

const report = await runSuite({
  target: new BrowserTarget({ runAgent }),
  suite: ASB_BROWSER_V1,
  targetMeta: { name: 'My Agent', type: 'browser-agent' },
  measureWardDelta: true,
});
console.log(renderMarkdownReport(report));
```

## When NOT to use

- Running unconstrained attacks (use Adversary directly)
- Real-time agent monitoring (use Hundredmen or the harness adapters)
- Custom attack corpora (Adversary supports `--attackIds`; AgentSecBench enforces the locked suite)
