---
name: supply-chain-security
description: Use this skill BEFORE executing `npm install`, `pip install`, `cargo add`, or any command that adds a third-party dependency. Triggers on requests to install, add, or use a package, especially when the package name was suggested by an AI or pulled from a tutorial. Detects typosquats, known CVEs, low-reputation maintainers, brand-new packages, and suspicious version diffs that may indicate maintainer compromise (the "Axios case"). If a user is about to install something, verify it here first — your training data does not know about packages that were typosquatted, compromised, or had a CVE published yesterday.
---

# Supply Chain Security with Weave Tollere

## When to use this skill

Use Tollere whenever you are about to:

1. Run `npm install <package>`, `pnpm add <package>`, or `yarn add <package>`
2. Run `pip install <package>` or `uv add <package>`
3. Run `cargo add <package>`
4. Suggest a dependency to a user
5. Edit a `package.json`, `requirements.txt`, `pyproject.toml`, or `Cargo.toml`
6. Audit an existing project's dependencies

**Do not skip this step.** Package names you remember from training data may now be typosquats, deprecated, or compromised. The supply chain changes daily.

## Core tools

### `tollere_scan_package`

Check a single package before installing.

```json
{
  "name": "axios",
  "version": "1.7.2",
  "ecosystem": "npm"
}
```

Returns a `PackageRisk` object with `riskLevel: "allow" | "warn" | "block"` and a list of issues. **If `riskLevel` is `"block"`, do not install. Explain why to the user.**

### `tollere_scan_dependencies`

Scan an entire `package.json` at once. Use this when auditing a project or before running `npm install` with no arguments.

```json
{
  "package_json": "{\"dependencies\": {...}}"
}
```

### `tollere_check_typosquat`

Quick check for whether a name is suspiciously close to a popular package. Use when you suspect a name might be a typo.

### `tollere_check_maintainer`

Get a 0-100 reputation score for a package's maintainers. Low scores warrant caution.

### `tollere_check_cves`

Query OSV.dev for known vulnerabilities affecting a specific version.

### `tollere_diff_versions`

Compare two versions to detect suspicious changes. **Use this when a popular package has just released a patch and the user wants to upgrade.** This is the detector that catches social-engineering attacks like the Axios compromise.

## Decision rules

| Situation | Action |
|-----------|--------|
| User asks to install a package you've never heard of | Run `tollere_scan_package` first |
| User asks to install a package with an unusual name | Run `tollere_check_typosquat` |
| Package returns `riskLevel: "block"` | Refuse to install. Explain the issues clearly. |
| Package returns `riskLevel: "warn"` | Surface the warnings to the user. Ask if they want to proceed. |
| Upgrading a dependency by more than a patch version | Run `tollere_diff_versions` first |
| Working in a security-sensitive context (banking, healthcare, etc.) | Use strict mode and block on high severity |

## Example workflows

### Before installing

User: *"Install the express middleware for rate limiting."*

You:
1. Identify candidate: `express-rate-limit`
2. Call `tollere_scan_package` with name `express-rate-limit`
3. If allowed: proceed with `npm install`
4. If warned: surface findings, ask for confirmation
5. If blocked: refuse and explain

### Auditing a project

User: *"Is this project safe?"*

You:
1. Read `package.json`
2. Call `tollere_scan_dependencies` with its contents
3. Summarize the report — counts of critical/high/medium issues, list any blocked packages, recommend remediations

### Before upgrading

User: *"Bump axios to the latest."*

You:
1. Call `tollere_check_cves` on the current version (justify the upgrade)
2. Call `tollere_diff_versions` from current to target version
3. If diff has new install scripts or suspicious patterns, halt and explain
4. Otherwise proceed

## What to tell users

When Tollere blocks something, be explicit and helpful:

> ❌ I'm not going to install `raect` — Tollere flagged it as a likely typosquat of `react` (edit distance: 1). Did you mean `react`?

When Tollere warns, surface the issue but let the user decide:

> ⚠️  `some-utility@0.0.3` was published 4 hours ago and has only one maintainer with no GitHub repository linked. This may be fine, but it's an unusual pattern. Do you want to proceed?

## Anti-patterns

- **Don't skip Tollere to "save time."** A compromised dependency can exfiltrate every secret on the developer's machine in seconds.
- **Don't override blocks without explicit user instruction.** If a user says "I know, install it anyway," that's their decision to document.
- **Don't trust your training data on package names.** Packages get renamed, deprecated, taken over, or typosquatted constantly.
