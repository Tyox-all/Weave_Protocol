---
name: supply-chain-security
description: Use this skill BEFORE executing any install command - npm install, pip install, cargo add, docker pull, or installing IDE extensions (VS Code, Cursor, Windsurf, JetBrains). Triggers on requests to install, add, pull, or use a package, image, or extension - especially when the name was suggested by an AI or pulled from a tutorial. Detects typosquats, known CVEs, low-reputation maintainers, brand-new packages, suspicious version diffs (Axios attack pattern), sandwich-pattern compromises (Checkmarx attack pattern), Docker tag overwriting, phantom tags, and IDE extension impersonation. If a user is about to install something, verify it here first - your training data does not know about packages, images, or extensions that were typosquatted, compromised, or had a CVE published yesterday.
---

# Supply Chain Security with Weave Tollere

## When to use this skill

Use Tollere whenever you are about to:

1. Run `npm install <package>`, `pnpm add <package>`, or `yarn add <package>`
2. Run `pip install <package>` or `uv add <package>`
3. Run `cargo add <package>`
4. Run `docker pull <image>` or use a Docker image in a Dockerfile/compose
5. Recommend a VS Code, Cursor, Windsurf, JetBrains, or Open VSX extension
6. Suggest a dependency, image, or extension to a user
7. Edit a `package.json`, `requirements.txt`, `pyproject.toml`, `Cargo.toml`, `Dockerfile`, or `.vscode/extensions.json`
8. Audit an existing project's dependencies or container images

**Do not skip this step.** Names you remember from training data may now be typosquats, deprecated, or compromised. The supply chain changes daily. Recent attacks (Axios March 2026, Checkmarx April 2026) prove that even popular, trusted projects get compromised.

## Core tools

### Package scanning

#### `tollere_scan_package`
Check a single package before installing.
```json
{ "name": "axios", "version": "1.7.2", "ecosystem": "npm" }
```

#### `tollere_scan_dependencies`
Scan an entire `package.json` at once.

#### `tollere_check_typosquat`
Quick check for whether a name is suspiciously close to a popular package.

#### `tollere_check_maintainer`
Get a 0-100 reputation score for a package's maintainers.

#### `tollere_check_cves`
Query OSV.dev for known vulnerabilities.

#### `tollere_diff_versions`
Compare two versions to detect suspicious changes. **The Axios case detector.**

### 🆕 v0.2 tools

#### `tollere_detect_sandwich`
Detect sandwich-pattern attacks across version history. **The Checkmarx case detector.** Use when:
- A package has a recent suspicious history
- You're auditing a critical dependency
- The package was recently in the news for a compromise

```json
{ "name": "some-package", "last_n": 20 }
```

The pattern: malicious code in version N → removed in N+1 (clean sandwich filling) → reappears in N+2. Designed to evade "always use latest" defenses.

#### `tollere_scan_docker`
Scan a Docker image before `docker pull`. Detects:
- Tag overwriting (semver tags should be immutable - if `v2.1.20` gets reassigned, that's critical)
- Phantom tags (versions that don't correspond to upstream releases)
- Rapid republishes

```json
{ "image": "nginx:alpine" }
{ "image": "checkmarx/kics:v2.1.20" }
```

#### `tollere_scan_extension`
Scan an IDE extension before recommending or installing. Routes to the right registry:
- `vscode` / `cursor` / `windsurf` → VS Code Marketplace
- `openvsx` → Open VSX Registry
- `jetbrains` → JetBrains Marketplace

```json
{ "full_id": "ms-python.python", "ecosystem": "vscode" }
{ "full_id": "rust-lang.rust", "ecosystem": "openvsx" }
{ "full_id": "Python", "ecosystem": "jetbrains" }
```

Detects unicode homoglyphs (Greek letters disguised as Latin), typosquats, unverified publishers, publisher takeovers, and brand-new extensions trying to ride a popular name.

## Decision rules

| Situation | Action |
|-----------|--------|
| User asks to install a package you've never heard of | Run `tollere_scan_package` first |
| User asks to install a package with an unusual name | Run `tollere_check_typosquat` |
| Result returns `riskLevel: "block"` | Refuse to install. Explain the issues clearly. |
| Result returns `riskLevel: "warn"` | Surface the warnings. Ask if they want to proceed. |
| Upgrading a dependency by more than a patch version | Run `tollere_diff_versions` first |
| Auditing a project for security | Run `tollere_detect_sandwich` on critical deps |
| Adding a Docker image to Dockerfile/compose | Run `tollere_scan_docker` first |
| Recommending an IDE extension | Run `tollere_scan_extension` first |
| Working in a security-sensitive context (banking, healthcare) | Use strict mode and block on high severity |

## Example workflows

### Before installing a package

User: *"Install the express middleware for rate limiting."*

You:
1. Identify candidate: `express-rate-limit`
2. Call `tollere_scan_package` with name `express-rate-limit`
3. If allowed: proceed with `npm install`
4. If warned: surface findings, ask for confirmation
5. If blocked: refuse and explain

### Before pulling a Docker image

User: *"Add the Checkmarx KICS image to my Dockerfile."*

You:
1. Call `tollere_scan_docker` with image `checkmarx/kics:latest`
2. Check for tag overwrites or phantom tags
3. If clean: proceed
4. If risky: surface the issue (e.g., "v2.1.20 was reassigned to a new digest 30 days after original publish — possible compromise")

### Before recommending a VS Code extension

User: *"What's a good Python extension for VS Code?"*

You:
1. Call `tollere_scan_extension` with `ms-python.python` and ecosystem `vscode`
2. Verify it's still publisher-verified, high installs, no recent compromise indicators
3. Recommend with confidence

### Auditing a project

User: *"Is this project safe?"*

You:
1. Read `package.json`
2. Call `tollere_scan_dependencies` with its contents
3. For any critical/popular dependencies, run `tollere_detect_sandwich`
4. Read `Dockerfile` and run `tollere_scan_docker` on each image
5. Summarize findings

## What to tell users

When Tollere blocks something, be explicit and helpful:

> ❌ I'm not going to install `raect` — Tollere flagged it as a likely typosquat of `react` (edit distance: 1). Did you mean `react`?

> ❌ I'm not going to pull `checkmarx/kics:v2.1.21` — Tollere flagged it as a phantom tag (highest known patch in v2.1.x is 20, this jumps to 21 with no upstream release).

> 🥪 I detected a sandwich pattern in `some-package`: malicious install script appeared in 1.17.0, was removed in 1.18.0 (clean), and reappeared in 1.19.0. This pattern is designed to evade "use latest version" defenses. I recommend pinning to 1.16.0 or earlier until the maintainer publishes a clean release.

When Tollere warns, surface the issue but let the user decide.

## Anti-patterns

- **Don't skip Tollere to "save time."** A compromised dependency can exfiltrate every secret on the developer's machine in seconds.
- **Don't override blocks without explicit user instruction.**
- **Don't trust your training data on package/image/extension names.** They get renamed, deprecated, taken over, or typosquatted constantly.
- **Don't assume "latest" is safe.** Sandwich attacks specifically exploit this assumption.
- **Don't skip the Docker scan because "it's just an image."** The Checkmarx attack proves Docker Hub is a primary target.
