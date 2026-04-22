# 🛂 @weave_protocol/tollere

[![npm version](https://img.shields.io/npm/v/@weave_protocol/tollere.svg)](https://www.npmjs.com/package/@weave_protocol/tollere)
[![npm](https://img.shields.io/npm/dm/@weave_protocol/tollere.svg)](https://www.npmjs.com/package/@weave_protocol/tollere)
[![license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Supply chain security for AI-generated code.**

> *Old English `tollere` (n.) — the toll-taker; the customs inspector who stood at the gate and examined every good crossing the boundary.*

Every `npm install` is a transaction. Tollere is the customs inspector.

AI coding agents install dependencies at machine speed with zero human review. Every `npm install` is a trust decision — and right now, nobody's checking anything.

Tollere catches typosquats, compromised maintainers, CVEs, and suspicious version diffs **before** the install completes.

Part of the [Weave Protocol Security Suite](https://github.com/Tyox-all/Weave_Protocol).

---

## 💡 Why

> On March 31, 2026, North Korean threat actors (tracked as UNC1069 by [Google's Threat Intelligence Group](https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package) and Sapphire Sleet by [Microsoft](https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/)) published two malicious versions of [`axios`](https://www.npmjs.com/package/axios) — a package with ~100M weekly downloads. They had spent weeks social-engineering the lead maintainer through a fake Slack workspace and a Teams call that installed a RAT, giving them his npm credentials. The poisoned versions shipped a backdoor (WAVESHAPER.V2) for macOS, Windows, and Linux. They were live for three hours.

The attack worked because nobody was checking what `npm install` was actually pulling in. The dependency had no provenance, the maintainer's account was technically valid, and `postinstall` scripts ran automatically. Every defense was downstream of the install.

The better AI gets at writing code, the faster the dependency graph grows, and the more attack surface exists in the software supply chain. Tollere was built for the world where:

- AI agents pick package names from training data (some of which are typosquats)
- Maintainer compromise events happen monthly
- A new CVE drops every few hours
- A "patch" version can introduce a fresh install script that exfiltrates your secrets

**Tollere checks before the install completes — not after.**

### Credit where it's due

Tollere stands on the shoulders of the supply chain security community:

- [**Socket**](https://socket.dev) — surfaced the broader pattern, identified other targeted maintainers across the npm ecosystem
- [**Google Threat Intelligence Group (GTIG/Mandiant)**](https://cloud.google.com/blog/topics/threat-intelligence/) — attributed the campaign to UNC1069
- [**Microsoft Threat Intelligence**](https://www.microsoft.com/en-us/security/blog/) — independent attribution to Sapphire Sleet
- [**Jason Saayman**](https://github.com/axios/axios) — published the post-mortem, helping the entire ecosystem learn from the incident
- [**OSV.dev**](https://osv.dev) and the [**GitHub Advisory Database**](https://github.com/advisories) — the underlying vulnerability data Tollere queries
---

## 📦 Installation

```bash
npm install -g @weave_protocol/tollere
# or
npx @weave_protocol/tollere scan
```

---

## 🚀 Quick Start

### CLI

```bash
# Scan your project
weave-tollere scan

# Check a single package before installing
weave-tollere check axios 1.7.2

# Check for typosquat (e.g., "raect" → react)
weave-tollere typosquat raect

# Compare two versions for suspicious changes
weave-tollere diff axios 1.7.0 1.7.1
```

### Programmatic

```typescript
import { scanPackage, scanPackageJson } from "@weave_protocol/tollere";

// Scan one package
const risk = await scanPackage("axios", "1.7.2");
console.log(risk.riskLevel); // "allow" | "warn" | "block"

// Scan an entire package.json
const report = await scanPackageJson(packageJsonContents);
if (report.recommendation === "BLOCK_INSTALL") {
  process.exit(1);
}
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

Then ask Claude: *"Before you run npm install, check this package with tollere."*

---

## 🔍 What Tollere Detects

| Detection | Description |
|-----------|-------------|
| **Typosquats** | `raect` vs `react`, `lodahs` vs `lodash`, hyphen/underscore swaps, number substitutions |
| **CVEs** | Live queries against OSV.dev (GHSA, PyPA, npm advisories, etc.) |
| **Low Reputation** | Account age, maintainer count, repository links, license, recent activity |
| **Brand New Packages** | Configurable threshold (default: warn if < 72 hours old) |
| **Suspicious Version Diffs** | New install scripts, injected dependencies, obfuscated code blobs, base64 payloads, network calls |
| **Dependency Confusion** | Packages mimicking internal scopes |
| **Ownership Changes** | Maintainer churn flagged for review |

---

## 🤖 Built for AI Agents

Tollere is designed to be called by AI coding agents (Claude Code, Cursor, etc.) **before** they execute `npm install`.

```typescript
// Inside an agent harness
const risk = await scanPackage(suggestedPackage, "latest");
if (risk.riskLevel === "block") {
  // Don't install. Explain why to the user.
  return { error: risk.issues };
}
```

### Skill File

Tollere ships with a `SKILL.md` file following the [Claude Agent Skills specification](https://docs.anthropic.com/en/docs/claude-code/skills). Drop it in `~/.claude/skills/` and Claude will automatically use Tollere whenever it's about to install a dependency.

---

## ⚙️ Configuration

```typescript
import { scanPackage, type TollereConfig } from "@weave_protocol/tollere";

const config: TollereConfig = {
  mode: "strict", // strict | balanced | permissive
  blockOnCritical: true,
  blockOnHigh: true,
  warnOnMedium: true,
  checkTyposquats: true,
  checkCVEs: true,
  checkMaintainers: true,
  checkVersionDiffs: true,
  minMaintainerScore: 50,
  minPackageAgeHours: 168, // 1 week
  cveDataSource: "both",
  trustedPublishers: ["microsoft", "facebook", "google", "vercel"],
  blockedPackages: [],
  allowedPackages: [],
};

const result = await scanPackage("some-package", "1.0.0", "npm", config);
```

---

## 📋 Example Output

```
🛡️  Weave Tollere — Supply Chain Scan
────────────────────────────────────────────────────────────
Scanned 47 packages in 1842ms

❌ BLOCKED (1)
────────────────────────────────────────────────────────────
❌ raect@18.2.0 [BLOCK] (risk: 80/100)
   🔴 critical typosquat: Possible typosquat of "react" (edit distance: 1)
      → Did you mean to install "react"?

⚠️  WARNINGS (2)
────────────────────────────────────────────────────────────
⚠️  some-utility@0.0.3 [WARN] (risk: 35/100)
   🟡 medium low_reputation: Low maintainer reputation score: 18/100
   🟡 medium version_anomaly: Package is very new (published 4 hours ago)

Summary:
  🔴 Critical: 1
  🟠 High:     0
  🟡 Medium:   2
  🔵 Low:      0

Recommendation: BLOCK_INSTALL
```

---

## 🌐 Multi-Ecosystem Support

| Ecosystem | Status |
|-----------|--------|
| npm       | ✅ Full support |
| PyPI      | ✅ CVE checks (typosquat coming) |
| Cargo     | ✅ CVE checks (typosquat coming) |
| Go        | ✅ CVE checks |
| Maven     | ✅ CVE checks |

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
