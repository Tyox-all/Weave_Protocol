# 🛂 @weave_protocol/tollere

[![npm version](https://img.shields.io/npm/v/@weave_protocol/tollere.svg)](https://www.npmjs.com/package/@weave_protocol/tollere)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/tollere.svg)](https://www.npmjs.com/package/@weave_protocol/tollere)
[![license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Supply chain security for AI-generated code.**

> *Old English `tollere` (n.) — the toll-taker; the customs inspector who stood at the gate and examined every good crossing the boundary.*

Every install is a transaction. Tollere is the customs inspector — for npm, PyPI, Cargo, Go, Maven, **Docker images**, and **IDE extensions** (VS Code, Cursor, Windsurf, Open VSX, JetBrains).

AI coding agents install dependencies at machine speed with zero human review. Every `npm install`, `docker pull`, and extension install is a trust decision — and right now, nobody's checking anything.

Tollere catches typosquats, compromised maintainers, CVEs, suspicious version diffs, sandwich-pattern attacks, and Docker tag overwriting **before** the install completes.

Part of the [Weave Protocol Security Suite](https://github.com/Tyox-all/Weave_Protocol).

---

## 💡 Why

### The Axios attack (March 2026)

> On March 31, 2026, North Korean threat actors (tracked as UNC1069 by [Google's Threat Intelligence Group](https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package) and Sapphire Sleet by [Microsoft](https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/)) published two malicious versions of [`axios`](https://www.npmjs.com/package/axios) — a package with ~100M weekly downloads. They had spent weeks social-engineering the lead maintainer through a fake Slack workspace and a Teams call that installed a RAT, giving them his npm credentials. The poisoned versions shipped a backdoor (WAVESHAPER.V2) for macOS, Windows, and Linux. They were live for three hours.

**Tollere catches this:** Use `tollere diff` to compare any version transition before upgrading. Suspicious patterns (new install scripts, injected dependencies, base64 blobs) are flagged immediately.

### The Checkmarx attack (April 2026)

> On April 22, 2026, [Socket](https://socket.dev/blog/checkmarx-supply-chain-compromise) and Docker disclosed a multi-channel supply chain compromise of Checkmarx's KICS distribution: malicious Docker images overwriting legitimate `v2.1.20` and `alpine` tags, a phantom `v2.1.21` tag with no upstream release, and trojaned VS Code extension releases (1.17.0 and 1.19.0) that fetched and executed remote JavaScript via the Bun runtime. Critically, version 1.18.0 was clean — a "sandwich filling" between two malicious releases designed to evade simple "check the latest version" defenses.

**Tollere catches this:**
- `tollere docker` — detects tag overwrites and phantom tags
- `tollere ext` — flags the malicious extension publishes
- `tollere sandwich` — catches the malicious-clean-malicious pattern across version history

### The pattern

The better AI gets at writing code, the faster the dependency graph grows, and the more attack surface exists in the software supply chain. Attackers have noticed that AI agents pick package names, Docker images, and IDE extensions from training data with no real-time verification. Tollere was built for the world where:

- AI agents pick package names from training data (some of which are typosquats)
- Maintainer compromise events happen monthly across npm, Docker Hub, VS Code Marketplace
- A new CVE drops every few hours
- A "patch" version can introduce an install script that exfiltrates your secrets
- Attackers use sandwich patterns to hide malicious code between clean versions

**Tollere checks before the install completes — not after.**

---

## 📦 Installation

```bash
npm install -g @weave_protocol/tollere
# or run on demand
npx @weave_protocol/tollere scan
```

---

## 🚀 Quick Start

### Package scanning (the basics)

```bash
weave-tollere scan                          # Scan current package.json
weave-tollere check axios 1.7.2             # Check single package
weave-tollere typosquat raect               # Check for typosquat
weave-tollere diff axios 1.7.0 1.7.1        # Compare two versions
```

### 🆕 Sandwich pattern detection (Checkmarx case)

```bash
weave-tollere sandwich some-package         # Scan last 15 versions
weave-tollere sandwich some-package 30      # Scan last 30 versions
```

Detects malicious code that appears in version N, is removed in N+1 (clean filling), and reappears in N+2 — a pattern designed to evade "always use latest" defenses.

### 🆕 Docker image scanning

```bash
weave-tollere docker nginx:alpine           # Scan a Docker image
weave-tollere docker checkmarx/kics:v2.1.20 # The Checkmarx case
```

Detects:
- **Tag overwriting** — semver tags should be immutable; if `v2.1.20` gets reassigned to a new digest, that's a red flag
- **Phantom tags** — tags that don't correspond to upstream releases (e.g. `v2.1.21` appearing when only `v2.1.20` exists upstream)
- **Rapid republishes** — multiple updates to the same tag in a short window

### 🆕 IDE Extension scanning

```bash
# VS Code Marketplace (covers Cursor, Windsurf too — they use the same registry)
weave-tollere ext ms-python.python vscode
weave-tollere ext github.copilot vscode

# Open VSX (VSCodium, Gitpod, Theia)
weave-tollere ext rust-lang.rust openvsx

# JetBrains Marketplace (IntelliJ, PyCharm, WebStorm, GoLand, etc.)
weave-tollere ext "Python" jetbrains
weave-tollere ext "12345" jetbrains          # by plugin ID
```

Detects:
- **Unicode homoglyphs** (e.g. `ms-pythοn.python` with a Greek omicron)
- **Typosquats** of popular extensions
- **Unverified publishers** with low install counts
- **Publisher takeovers** (Open VSX `unrelatedPublisher` flag)
- **Brand new extensions** trying to ride a popular name
- **Pump-and-dump trending** patterns

### Programmatic

```typescript
import {
  scanPackage,
  scanPackageJson,
  detectSandwichPattern,
  scanDockerImage,
  scanExtension,
} from "@weave_protocol/tollere";

// Scan a package
const risk = await scanPackage("axios", "1.7.2");
if (risk.riskLevel === "block") {
  throw new Error(`Blocked: ${risk.issues[0].description}`);
}

// Detect sandwich pattern
const sandwich = await detectSandwichPattern("checkmarx-vscode", { lastN: 20 });
if (sandwich.patternDetected) {
  console.error(`🥪 Sandwich detected: ${sandwich.pattern!.evidence}`);
}

// Scan Docker image
const docker = await scanDockerImage("checkmarx/kics:v2.1.20");
if (docker.riskLevel === "block") {
  console.error(`🐳 Blocked: ${docker.issues.map(i => i.description).join("\n")}`);
}

// Scan IDE extension (works for VS Code, Cursor, Windsurf)
const ext = await scanExtension("ms-python.python", "vscode");
console.log(`Extension risk: ${ext.riskLevel}`);
```

### MCP Server (Claude Desktop / Claude Code)

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "tollere": {
      "command": "npx",
      "args": ["-y", "@weave_protocol/tollere"]
    }
  }
}
```

Then ask Claude: *"Before you run npm install, scan it with tollere. Same for any docker pull or VS Code extension."*

---

## 🔍 What Tollere Detects

### Packages (npm, PyPI, Cargo, Go, Maven)

| Detection | Description |
|-----------|-------------|
| **Typosquats** | `raect` vs `react`, `lodahs` vs `lodash`, hyphen/underscore swaps, number substitutions |
| **CVEs** | Live queries against [OSV.dev](https://osv.dev) (GHSA, PyPA, npm advisories, etc.) |
| **Low Reputation** | Account age, maintainer count, repository links, license, recent activity |
| **Brand New Packages** | Configurable threshold (default: warn if < 72 hours old) |
| **Suspicious Version Diffs** | New install scripts, injected dependencies, obfuscated code, base64 payloads, network calls |
| **🆕 Sandwich Patterns** | Malicious code hidden between a clean "filling" version |

### Docker (Docker Hub)

| Detection | Description |
|-----------|-------------|
| **🆕 Tag Overwriting** | Semver tags reassigned to new digests (should be immutable) |
| **🆕 Phantom Tags** | Tags that skip ahead of the established release pattern |
| **🆕 Rapid Republishes** | Multiple updates to the same tag in a short window |

### IDE Extensions

| Registry | Covers | Detections |
|----------|--------|------------|
| **🆕 VS Code Marketplace** | VS Code, **Cursor**, **Windsurf** | Unicode homoglyphs, typosquats, unverified publishers, brand-new with trending |
| **🆕 Open VSX** | VSCodium, Gitpod, Theia | Unverified namespace, **publisher takeovers** (unrelated publisher flag), missing repo |
| **🆕 JetBrains Marketplace** | IntelliJ, PyCharm, WebStorm, GoLand, RubyMine, PhpStorm, CLion, DataGrip, Rider | Unverified vendor, not-yet-approved plugins, missing source code, low downloads |

---

## 🤖 Built for AI Agents

Tollere is designed to be called by AI coding agents (Claude Code, Cursor, etc.) **before** they execute `npm install`, `docker pull`, or extension installs.

```typescript
const risk = await scanPackage(suggestedPackage, "latest");
if (risk.riskLevel === "block") {
  return { error: risk.issues };
}
```

### Skill File

Tollere ships with a `SKILL.md` file following the [Claude Agent Skills specification](https://docs.anthropic.com/en/docs/claude-code/skills). Drop it in `~/.claude/skills/` and Claude will automatically use Tollere whenever it's about to install a dependency, pull a Docker image, or recommend an IDE extension.

---

## ⚙️ Configuration

```typescript
import { scanPackage, type TollereConfig } from "@weave_protocol/tollere";

const config: TollereConfig = {
  mode: "strict",                // strict | balanced | permissive
  blockOnCritical: true,
  blockOnHigh: true,
  warnOnMedium: true,
  checkTyposquats: true,
  checkCVEs: true,
  checkMaintainers: true,
  checkVersionDiffs: true,
  minMaintainerScore: 50,
  minPackageAgeHours: 168,       // 1 week
  cveDataSource: "both",
  trustedPublishers: ["microsoft", "facebook", "google", "vercel"],
  blockedPackages: [],
  allowedPackages: [],
};

const result = await scanPackage("some-package", "1.0.0", "npm", config);
```

---

## 🌐 Multi-Ecosystem Support

| Ecosystem | Languages / Tools | CVE Checks | Typosquat | Notes |
|-----------|-------------------|------------|-----------|-------|
| npm | JavaScript, TypeScript | ✅ | ✅ | Full support including sandwich pattern |
| PyPI | Python | ✅ | 🚧 v0.3 | |
| Maven | Java, Kotlin, Scala, Android (Gradle) | ✅ | 🚧 v0.3 | |
| crates.io | Rust | ✅ | 🚧 v0.3 | |
| Go | Go | ✅ | 🚧 v0.3 | |
| **🆕 Docker Hub** | Container images | n/a | n/a | Tag overwrite + phantom tag detection |
| **🆕 VS Code Marketplace** | VS Code, Cursor, Windsurf | n/a | ✅ | Unicode homoglyph + typosquat |
| **🆕 Open VSX** | VSCodium, Gitpod, Theia | n/a | ✅ | Publisher takeover detection |
| **🆕 JetBrains Marketplace** | IntelliJ, PyCharm, WebStorm, etc. | n/a | ✅ | Vendor verification |

---

## 🙏 Credit where it's due

Tollere stands on the shoulders of the supply chain security community:

- [**Socket**](https://socket.dev) — surfaced both the Axios broader pattern and the Checkmarx multi-channel compromise
- [**Google Threat Intelligence Group (GTIG/Mandiant)**](https://cloud.google.com/blog/topics/threat-intelligence/) — attributed the Axios campaign to UNC1069
- [**Microsoft Threat Intelligence**](https://www.microsoft.com/en-us/security/blog/) — independent attribution to Sapphire Sleet
- [**Docker Inc.**](https://www.docker.com) — caught the Checkmarx KICS Docker Hub anomaly and notified Socket
- [**Jason Saayman**](https://github.com/axios/axios) — published the Axios post-mortem, helping the entire ecosystem learn
- [**OSV.dev**](https://osv.dev) and the [**GitHub Advisory Database**](https://github.com/advisories) — the underlying vulnerability data Tollere queries

---

## 🔗 Related Packages

| Package | Description |
|---------|-------------|
| [@weave_protocol/mund](https://www.npmjs.com/package/@weave_protocol/mund) | Secret & threat scanning, MCP server vetting |
| [@weave_protocol/hord](https://www.npmjs.com/package/@weave_protocol/hord) | Secure vault & sandbox |
| [@weave_protocol/domere](https://www.npmjs.com/package/@weave_protocol/domere) | Compliance & blockchain anchoring |
| [@weave_protocol/hundredmen](https://www.npmjs.com/package/@weave_protocol/hundredmen) | Real-time MCP proxy |

---

## 📄 License

Apache 2.0

---

*Made with ❤️ for the era of agentic coding.*
