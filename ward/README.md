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

## 🆕 What's new

**0.3.9: receipt checkpoints.** A receipt chain alone can't show that its newest receipts were cut off. `weave-ward receipts checkpoint` signs the log's current head. Keep checkpoints off the machine, or anchor them on-chain with [Dōmere](https://www.npmjs.com/package/@weave_protocol/domere) (`domere_anchor_receipts`). `weave-ward receipts verify --checkpoints=FILE` then fails if any receipt up to a checkpoint was removed or changed. See [checkpoints and anchoring](#checkpoints-and-anchoring-039).

**0.3.8: signed policies.** Sign WARD.md once with `weave-ward sign`, then list the public key in `~/.weave/trusted-policy-keys` on each machine. Every adapter will then refuse a policy that was edited after signing or that a trusted key didn't sign: each call is denied with the reason. A signed policy that was changed is refused even without a trust list. See [signed policies](#signed-policies-038).

**0.3.7: signed decision receipts.** With `required: true` in WARD.md's Verification section, every allow, deny and approval becomes a receipt in an append-only log. Each receipt is **Ed25519-signed and hash-chained** to the one before, so editing, deleting or reordering any receipt fails verification. Run `weave-ward receipts verify` to check a log offline. Arguments are never stored, only a keyed digest. All seven adapters write receipts through Ward. See [decision receipts](#decision-receipts-037).

**0.3.6: payments and spend limits.**
- **Payment guard, on by default.** A call that moves money needs human approval unless WARD.md allows that capability by name. That covers payment, transfer, purchase and withdrawal tools, plus wallet and Stripe CLIs in shell commands. A default `allow` or a wildcard doesn't lift it.
- **Session limits.** `@weave_protocol/ward/ledger` enforces the Behavioral Limits (`maxToolCalls`, `maxRuntimeSeconds`, `maxExternalServices`). It also enforces [Witan's](https://www.npmjs.com/package/@weave_protocol/witan) `spending_limits:` caps: per-tool call counts and cumulative payment amounts per run, hour, day, week or month. Hook-based adapters keep these counts across their separate processes.

See [payments and spend limits](#payments-and-spend-limits-036).

**0.3.5: what's leaving, not just where it goes.** A secret sent to an allowed domain is still a leak. That's the pattern behind Claude Code CVE-2026-54316, exfiltration through a pre-approved domain. Every tool call that sends something is checked for the data it carries:
- literal keys, card numbers, emails and SSNs;
- in shell commands, `$SECRET_VARS`, secret files such as `.env` and SSH keys, and environment dumps.

The Data Boundaries section of WARD.md is now enforced, and two guards are on by default. See [outbound data](#outbound-data-035).

**0.3.3: agents can't switch off their own guardrails.** An agent with a broad write rule could rewrite the files that control it. Writing or deleting any of these now needs human approval, even under a rule like `write: /repo/**`:
- `WARD.md`;
- harness hook and settings files;
- MCP server lists;
- git hooks.

This blocks the CurXecute pattern (CVE-2025-54135). See [self-protection](#evaluating-a-whole-tool-call-020).

**0.3.0–0.3.2: decisions on the dashboard.** `reportEvent()` sends allow and deny decisions to a local [Weave API](https://www.npmjs.com/package/@weave_protocol/api) dashboard. It's off unless you set `WEAVE_DASHBOARD_URL`, and `WEAVE_DASHBOARD_TIMEOUT_MS` raises its timeout.

**0.2.0: one evaluator for every harness.** `evaluateToolCall()` checks every path and URL argument and every token of a shell command. It fixes [WARD-2026-001](SECURITY_ADVISORIES.md), where adapters checked only one field per tool.

WARD.md is enforced today in:
- [Claude Code](https://www.npmjs.com/package/@weave_protocol/adapter-claudecode);
- [Google Antigravity](https://www.npmjs.com/package/@weave_protocol/adapter-antigravity);
- [Microsoft Agent Framework](https://www.npmjs.com/package/@weave_protocol/adapter-msaf);
- [Gemini CLI](https://www.npmjs.com/package/@weave_protocol/adapter-geminicli);
- [Codex](https://www.npmjs.com/package/@weave_protocol/adapter-codex);
- [OpenCode](https://www.npmjs.com/package/@weave_protocol/adapter-opencode);
- [Cursor](https://www.npmjs.com/package/@weave_protocol/adapter-cursor);
- MCP servers, through [Hundredmen](https://www.npmjs.com/package/@weave_protocol/hundredmen);
- Playwright browser agents, through [Browser](https://www.npmjs.com/package/@weave_protocol/browser).

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

### Evaluating a whole tool call (0.2.0+)

Harness adapters should use `evaluateToolCall`, which runs every check a tool call needs in one place:

```typescript
import { parseWard, evaluateToolCall } from "@weave_protocol/ward";

const result = evaluateToolCall(policy, "Bash", { command: "curl https://a.example && cat ~/.ssh/id_rsa" }, {
  mappings: { Bash: { capability: "shell_exec", commandField: "command" } },
  cwd: process.cwd(),
});
// result.decision: "deny"; result.reasons names the offending token
```

- **Capability:** checks the mapped capability and the raw tool name. An explicit rule for either beats a policy default.
- **Path and URL arguments:** checks every one of them, not just a single well-known field:
  - any argument whose name ends in `path`, `file`, `dir`, `src`, `dest`, `target`, `output`, `url`, `uri`, `endpoint`, `href` or `link`, in any casing, including arrays;
  - `dest`, `target` and `output` count as writes, and `src` counts as a read.
- **Shell commands:**
  - every URL in the command is checked;
  - so is every absolute or `~` path, and redirect targets and copy destinations count as writes;
  - relative tokens count only when they match an explicit rule, so commit messages and regexes don't trip a default.

  This scanning is best effort. To draw a hard line on shell use, gate `shell_exec` itself with `requireApproval` or `deny`.
- **Relative paths** resolve against `cwd`.
- **Strictness:** the strictest result wins (deny, then require_approval, then allow).
- **Self-protection (0.3.3):** writing or deleting a file that controls the agent needs human approval, even when a broad rule like `write: /repo/**` covers it. These files are:
  - `WARD.md`;
  - harness hooks and settings: `.claude/settings*.json`, `.cursor/hooks.json`, `.codex/hooks.json` and `config.toml`, `.gemini/settings.json`, `opencode.json` and `.opencode/plugins/`;
  - MCP server lists: `mcp.json`, `.mcp.json`, `claude_desktop_config.json`;
  - git hooks.

  An agent that can rewrite them can turn its own guardrails off, as in Cursor's CurXecute (CVE-2025-54135). To allow edits to one, name that exact file in an allow rule (`- write: /repo/.cursor/mcp.json`). `protectedConfig(path)` tells you whether a path is one of them.

### Outbound data (0.3.5+)

`evaluateToolCall` also checks what a call sends. That covers a call with a URL, a network command (`curl`, `wget`, `scp`, `ssh`, `nc` and others), or a tool whose name says it sends (`send_*`, `post_*`, `*_message`, `upload`, `webhook` and similar). It looks in:
- the URL's path and query;
- body and message arguments;
- the command text.

It doesn't look at recipients (`to`, `cc`, `channel`), harness metadata (`prompt`, `description`) or file paths.

| Found | Class |
|---|---|
| Anthropic, OpenAI, GitHub, AWS, Google, Slack, Stripe and npm keys; private keys; JWTs; `password=`-style assignments | `credentials` and `secret` |
| In commands: secret variables (`$OPENAI_API_KEY`, `$DB_PASSWORD`), secret files (`.env`, `~/.aws/credentials`, `~/.ssh/id_*`, `.netrc`, `*.pem`), `env` and `printenv` dumps | `credentials` and `secret` |
| Card numbers that pass a Luhn check | `pci` |
| Email addresses, US SSNs | `pii` |

Decisions:
- **Your Data Boundaries rules.** A class in `egressDeny` is **denied** to any host, allowed or not. With `egressAllow` set, any class it doesn't list is denied.
- **Credentials guard (default).** A credential sent anywhere but its issuer **needs approval**. For example, `$GITHUB_TOKEN` going to `api.github.com` is fine, but going anywhere else isn't. To lift this, add `credentials` to `egressAllow`.
- **Model-endpoint guardrail (default).** Secrets or personal data sent to a model API that WARD.md doesn't name in an explicit Network allow rule **need approval**. That covers OpenAI, Anthropic, Gemini, OpenRouter, Groq, Mistral, DeepSeek, Azure OpenAI, Bedrock and others. To lift it, add a rule naming the host, such as `- url: "https://openrouter.ai/**"`.

A credential sent only to its own issuer is always allowed, because that's how the API is used. Reasons name the kind of data and the destination, never the value.

Only what's visible is classified. A secret Ward can't see, such as one already encoded or held in an unnamed variable, isn't caught, so treat this as a strong backstop rather than a guarantee. For broader detection, pass a classifier, for example one built on [Mund](https://www.npmjs.com/package/@weave_protocol/mund):

```typescript
evaluateToolCall(policy, tool, args, { classify: (text) => myFindings(text) }); // returns DataFinding[]
```

`checkOutboundData`, `classifyData`, `classifyCommandReferences` and `isModelEndpoint` are exported for hosts that don't use `evaluateToolCall`.

### Payments and spend limits (0.3.6+)

**Payment guard.** `evaluateToolCall` asks for approval before any call that moves money. It recognizes:
- tools named for payments, payouts, purchases, checkout, withdrawals or wires;
- tools named transfer, swap, bridge, buy, refund or send that carry an amount;
- wallet and payment CLIs in shell commands: `cast send`, `solana transfer`, `spl-token transfer`, `bitcoin-cli send…` and `stripe payouts|transfers|charges create`, among others.

To lift the guard, allow the capability by its exact name, or allow `payments` for all of them. Allowing `shell_exec` doesn't lift it for a payment CLI inside a shell command. `detectPayment()` reports the amount: `amount`, `amount_usd`, `amount_cents` (divided by 100), `value`, `price` or `total`, in USD when no other currency is stated.

**Session limits.** These need history, which a hook process doesn't have. `@weave_protocol/ward/ledger` keeps it in one small file per agent, `$WEAVE_LEDGER_DIR` or `~/.weave/ledger/<agent>.json`, with mode 0600. It records when each call ran, its session, its tool, the USD moved and the hosts contacted. No arguments are stored. Parallel hook processes are serialized with a lock.

```typescript
import { evaluateWithLedger } from "@weave_protocol/ward/ledger";

const result = evaluateWithLedger(policy, toolName, args, { mappings, cwd, session: hookInput.session_id });
```

It enforces:

| WARD.md | Limit |
|---|---|
| `## Behavioral Limits` → `maxToolCalls` | Tool calls per session (deny) |
| `maxRuntimeSeconds` | Time since the session's first call (deny) |
| `maxExternalServices` | Distinct hosts contacted per session (deny) |
| `spending_limits:` → `budget.tool_calls` | Tool calls per window |
| `budget.tools.<name>.max_calls` | Calls of one tool per window |
| `budget.tools.<name>.max_amount_usd` | USD that tool may move per window, cumulative. An unknown amount needs approval. |

```yaml
spending_limits:
  - window: day                 # run (the session) | hour | day | week | month (rolling)
    budget:
      tools:
        send_payment:
          max_amount_usd: 500
          max_calls: 5
    on_exceeded: block          # block | require_approval | notify
```

This is the same `spending_limits:` format Witan reads. `budget.usd` and `budget.tokens` cover LLM spend, which hooks can't see, so Witan enforces those. The ledger is only touched when WARD.md declares a limit that needs it. `checkSessionLimits()` is the pure check, for hosts that keep their own history.

### Signed policies (0.3.8+)

```bash
weave-ward sign WARD.md                 # Ed25519; key created at ~/.weave/keys/ward-policy.pem on first use
weave-ward verify WARD.md               # check it against this machine's trusted keys
weave-ward verify WARD.md --key=<b64>   # or against a given key
```

`sign` adds a line at the end of the file that doesn't show when the markdown renders:

```
<!-- ward-signature v1 keyId=… publicKey=… signedAt=… sig=… -->
```

It signs the SHA-256 of the rest of the file, after normalizing line endings and trailing whitespace. Re-signing replaces the line.

Which keys a machine trusts can't come from WARD.md, since whoever edits the file could edit that too. It comes from outside:

| Setting | |
|---|---|
| `~/.weave/trusted-policy-keys` (`$WEAVE_POLICY_TRUSTED_KEYS_FILE`) | Public keys, one per line; `#` starts a comment |
| `WEAVE_POLICY_TRUSTED_KEYS` | Comma-separated public keys |
| `WEAVE_POLICY_KEY_FILE` | The signing key `sign` uses |

| WARD.md | No trusted keys | Trusted keys configured |
|---|---|---|
| Unsigned | Enforced | **Every call denied** |
| Signed, unchanged | Enforced | Enforced if the key is trusted, otherwise **every call denied** |
| Signed, then edited | **Every call denied** | **Every call denied** |

The check runs in `evaluateWithLedger`, so every Weave adapter and Hundredmen (1.4.0+) apply it, and the result is cached per policy text. `signPolicySource`, `checkPolicySignature`, `checkPolicy` and `trustedPolicyKeys` are exported from `@weave_protocol/ward/signing`.

### Decision receipts (0.3.7+)

Turn receipts on in WARD.md:

```yaml
## Verification

required: true
frequency: every_action      # or leave unset
attestor: <base64 public key>   # optional: the key verification should expect
```

`WEAVE_RECEIPTS=1` turns receipts on regardless of WARD.md, and `WEAVE_RECEIPTS=0` turns them off. `evaluateWithLedger`, which every Weave adapter uses, then appends one receipt per decision to `~/.weave/receipts/<agent>.jsonl` (`$WEAVE_RECEIPT_DIR`, mode 0600):

```json
{"type":"receipt","v":1,"seq":42,"at":"2026-11-08T21:40:12.511Z","agent":"my-agent","session":"…","surface":"claude-code",
 "tool":"Bash","capability":"shell_exec","decision":"deny","reasons":["Outbound data contains $AWS_SECRET_ACCESS_KEY ('credentials'), which WARD.md denies egress"],
 "argsDigest":"hmac-sha256:…","policyDigest":"sha256:…","keyId":"3f9a…","prev":"sha256:…","hash":"sha256:…","sig":"…"}
```

- **Chained:** `hash` is the SHA-256 of the receipt's canonical JSON, without `hash` and `sig`. `prev` is the previous receipt's hash, and `seq` counts up with no gaps.
- **Signed:** `sig` is an Ed25519 signature over `hash`. The key is created on first use at `~/.weave/keys/ward-receipts.pem` (`$WEAVE_RECEIPT_KEY_FILE`, mode 0600). A header line names the public key. If the key changes, a new header continues the chain.
- **No arguments:** `argsDigest` is an HMAC under a key derived from the signing key. The key holder can prove which arguments were decided, but the log can't be used to guess short secrets. Reasons are stored without the argument they name.
- **Never in the way:** a receipt that can't be written doesn't change or delay the decision. Set `WEAVE_RECEIPTS_DEBUG=1` to see why one failed.

```bash
weave-ward receipts verify                       # ~/.weave/receipts/default.jsonl, or --agent=NAME, or a path
weave-ward receipts verify log.jsonl --key=pub.txt   # also require this signing key
weave-ward receipts key                          # print this machine's public key
```

Verification recomputes every hash and checks every link, sequence number, timestamp order and signature. It reports the line of each problem. Removing the newest receipts leaves a shorter chain that is still valid. Checkpoints catch that. Signatures prove which key wrote a receipt, not that the machine holding the key was uncompromised.

#### Checkpoints and anchoring (0.3.9+)

A checkpoint is a signed statement that a log had reached receipt `seq` with hash `head`:

```bash
weave-ward receipts checkpoint --agent=my-agent                          # print one
weave-ward receipts checkpoint --agent=my-agent --append=/mnt/audit/my-agent.checkpoints.jsonl
weave-ward receipts verify --agent=my-agent --checkpoints=/mnt/audit/my-agent.checkpoints.jsonl
```

Verification against checkpoints fails in these cases:
- a checkpoint's receipt is missing (the log was cut short);
- its hash differs (the log was rewritten, even with the same key);
- the checkpoint was signed by a key that never signed the log.

Checkpoints help only if they are stored where the log's machine can't rewrite them: another host, a write-once bucket, or a public chain. To anchor one on Solana or Ethereum, pass checkpoints from any number of agents to Dōmere's `domere_anchor_receipts`. It returns a bundle that commits to all of them in one Merkle root, plus an unsigned transaction to sign with your wallet. `--checkpoints` accepts that bundle file directly. Run `weave-ward receipts checkpoint` from cron, or at the end of each CI job, to bound how much can be lost.

`appendReceipt`, `verifyReceiptLog`, `createCheckpoint`, `verifyCheckpoint`, `readCheckpoints`, `loadReceiptKeys` and `canonicalJson` are exported from `@weave_protocol/ward/receipts`.

### Reporting decisions to the dashboard (0.3.0+)

`reportEvent()` sends an enforcement decision to a local Weave API (`@weave_protocol/api`), which shows it on its dashboard. The Weave adapters, browser guard and Hundredmen call it for you. Its surfaces are `mcp`, `claude-code`, `antigravity`, `msaf`, `browser`, `gemini-cli`, `codex`, `opencode` and `cursor` (the last four from 0.3.1).

```bash
export WEAVE_DASHBOARD_URL=http://localhost:3000   # where the API runs
export WEAVE_API_KEY=...                            # the API's key
```

- **Off by default.** Nothing is sent unless `WEAVE_DASHBOARD_URL` is set.
- **Sent:** the surface, the decision, the tool name or a URL with its query string removed, and a truncated reason with any argument value stripped. Command text and argument contents are never sent.
- **Never in the way.** A report never changes a decision and never throws. It gives up after 250 ms; on a slow machine or network, raise that with `WEAVE_DASHBOARD_TIMEOUT_MS` (up to 5000) so events aren't dropped.

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
weave-ward sign <file>        Sign a WARD.md (0.3.8+); weave-ward verify <file> checks it
weave-ward receipts verify    Verify a receipt log (--checkpoints=FILE to check against checkpoints)
weave-ward receipts checkpoint  Sign a log's head, to keep or anchor elsewhere (0.3.9+)
weave-ward receipts key       Print the public key that signs this machine's receipts
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

**Shipped:**
- the parser, validator, type system and CLI;
- the check primitives: `checkFilesystem`, `checkNetwork`, `checkCapability`, `checkDataEgress` and `checkBehavioral`;
- `evaluateToolCall` with self-protection, outbound-data checks and the payment guard;
- session and spend limits (`@weave_protocol/ward/ledger`);
- signed, hash-chained decision receipts (`@weave_protocol/ward/receipts`), with checkpoints that Dōmere can anchor on-chain;
- signed policies with a per-machine trust list (`@weave_protocol/ward/signing`);
- dashboard reporting;
- adapters for seven agent harnesses, plus MCP (Hundredmen) and Playwright (Browser).

**Next:**
- reading anchors back from the chain, so verification can finish without a block explorer.

---

## 🕸️ Part of Weave Protocol

One [WARD.md](https://github.com/Tyox-all/Weave_Protocol) policy for every agent you run, locally or at scale, plus the tools around it.

| Package | What it does |
|---|---|
| [Ward](https://www.npmjs.com/package/@weave_protocol/ward) | The WARD.md policy standard and the tool-call evaluator every adapter shares |
| [Mund](https://www.npmjs.com/package/@weave_protocol/mund) | Scans content for prompt injection, secrets, PII and exfiltration |
| [Hord](https://www.npmjs.com/package/@weave_protocol/hord) | Encrypted vaults, PII tokenization, sandboxes, capability tokens, attestations |
| [Dōmere](https://www.npmjs.com/package/@weave_protocol/domere) | Audit threads, compliance checkpoints, GDPR and CCPA records, anchoring |
| [Witan](https://www.npmjs.com/package/@weave_protocol/witan) | Multi-agent consensus and spending caps |
| [Hundredmen](https://www.npmjs.com/package/@weave_protocol/hundredmen) | MCP proxy that enforces WARD.md on tool calls |
| [Tollere](https://www.npmjs.com/package/@weave_protocol/tollere) | Supply-chain checks: typosquats, CVEs, suspicious version diffs |
| [Browser](https://www.npmjs.com/package/@weave_protocol/browser) | WARD.md and injection scanning for Playwright browser agents |
| Adapters | WARD.md in [Claude Code](https://www.npmjs.com/package/@weave_protocol/adapter-claudecode), [Antigravity](https://www.npmjs.com/package/@weave_protocol/adapter-antigravity), [MSAF](https://www.npmjs.com/package/@weave_protocol/adapter-msaf), [Gemini CLI](https://www.npmjs.com/package/@weave_protocol/adapter-geminicli), [Codex](https://www.npmjs.com/package/@weave_protocol/adapter-codex), [OpenCode](https://www.npmjs.com/package/@weave_protocol/adapter-opencode) and [Cursor](https://www.npmjs.com/package/@weave_protocol/adapter-cursor) |
| [Adversary](https://www.npmjs.com/package/@weave_protocol/adversary) · [AgentSecBench](https://www.npmjs.com/package/@weave_protocol/agentsecbench) | Red-team engine and locked benchmark |
| [API](https://www.npmjs.com/package/@weave_protocol/api) · [CLI](https://www.npmjs.com/package/@weave_protocol/cli) · [LangChain](https://www.npmjs.com/package/@weave_protocol/langchain) | REST API and dashboard, setup CLI, LangChain.js integration |
| [full](https://www.npmjs.com/package/@weave_protocol/full) | Every defensive package in one install |
| [Yoxallismus](https://www.npmjs.com/package/@weave_protocol/yoxallismus) | Post-quantum hybrid cipher (experimental beta) |

---

## License

Apache 2.0 — see [LICENSE](../LICENSE).
