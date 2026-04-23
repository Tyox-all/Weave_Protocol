# Weave Protocol — Planning

This document captures the high-level direction of the Weave Protocol monorepo. For shipped features, see the [Roadmap section in README.md](./README.md#-roadmap).

Last updated: April 22, 2026

---

## Current state (H1 2026)

Weave Protocol consists of nine published packages spanning JavaScript/TypeScript and Python ecosystems, providing defense-in-depth security across the full lifecycle of an AI agent system. Each package addresses a distinct layer of the security model and ships with a Claude Agent Skill for AI-native integration.

For the package inventory and what each one does, see [README.md](./README.md).

---

## H2 2026 — Strategic direction

Two themes drive the second half of 2026: **adoption** and **differentiation**.

### Q3 — Adoption

Lower the barrier to getting started. Make Weave Protocol discoverable, installable, and immediately useful for the largest possible audience.

- **Bundle package + initialization tooling.** A single command from zero to a configured, secured agent.
- **Browser agent security.** A new package targeting the fastest-growing AI surface.
- **Public threat report.** Industry reference document derived from anonymized telemetry.

### Q4 — Differentiation

Deepen technical capability and unlock enterprise revenue.

- **Adversarial testing capability.** Red-team agents for continuous security validation.
- **Next-generation Yoxallismus.** Substantial cipher and key-management upgrades for multi-agent and memory-rich environments.
- **Witan production positioning.** Sharpened use case targeting concrete enterprise pain points.
- **Open security benchmark.** Industry-standard evaluation framework.

Specific implementation details, threat models, and design decisions are intentionally not published here.

---

## Operating principles

These principles guide every package and every release:

1. **Security must be continuous, not a phase.** Tools live alongside Product, Design, and Engineering — not as a downstream gate.
2. **Verification before action.** Checks happen before installs complete, before tool calls execute, before inputs are processed.
3. **AI-native by default.** Every package ships agent integration so the tools are used automatically, not optionally.
4. **Honest attribution.** When we build on others' research, we credit them. Trust compounds.

---

## Distribution and release model

- **TypeScript packages:** published to npm under the `@weave_protocol` scope using GitHub Actions with trusted publishing (OIDC + Sigstore provenance). No long-lived npm tokens in the publish pipeline.
- **Python packages:** published to PyPI using trusted publishing.
- **Versioning:** semver across all packages. Breaking changes require a major bump and a migration note.
- **Workflow:** the `publish-all.yml` matrix workflow handles all npm packages in a single dispatch.

---

## Engagement

For tactical issues, milestones, and bug reports, see [GitHub Issues](https://github.com/Tyox-all/Weave_Protocol/issues).

For partnership, integration, licensing, or strategic inquiries: **TYox-all@tutamail.com**

For security disclosures: see [SECURITY.md](./SECURITY.md).
