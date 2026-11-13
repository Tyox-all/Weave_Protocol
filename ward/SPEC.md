# WARD.md Specification

Version 1.0 · April 2026

This document specifies the WARD.md file format: a portable, version-controlled standard for declaring AI agent security policies.

> Implementation details of how WARD.md policies are enforced at runtime, attested, or cross-validated against other harness layers are intentionally not published here. This document covers the file format only.

---

## 1. File location

A WARD.md file is named `WARD.md` (case-insensitive in practice; the canonical form is uppercase). It typically sits at the root of an agent's directory, alongside `AGENTS.md` and `SKILL.md`:

```
my-agent/
├── AGENTS.md
├── SKILL.md
└── WARD.md
```

For multi-agent harnesses, each agent may have its own WARD.md in its own subdirectory, plus optionally a top-level WARD.md governing the harness as a whole.

---

## 2. Structure

A WARD.md file has two parts:

1. **YAML frontmatter** between two `---` lines. Contains metadata about the policy itself.
2. **Markdown body** containing one or more **policy sections**, each introduced by an H2 heading (`##`).

```markdown
---
ward: "1.0"
agent: my-agent
name: Optional human name
description: Optional description
---

# WARD.md

## Filesystem
...

## Network
...
```

The body may contain prose for human readers. Only H2 sections are interpreted as policy.

---

## 3. Frontmatter

| Field | Type | Required | Description |
|---|---|---|---|
| `ward` | string | yes | Spec version. `"1.0"` for this document. |
| `agent` | string | no | Identifier or relative path referencing an AGENTS.md file. |
| `name` | string | no | Human-readable policy name. |
| `description` | string | no | One-line description. |

---

## 4. Section format

Section bodies are interpreted as a YAML-like block. Each section has a fixed schema documented below. Sections may appear in any order. Unknown sections are preserved as opaque text — they don't break parsing, but they don't enforce anything either.

For each rule-based section (Filesystem, Network, Capabilities), the schema is:

```yaml
allow:
  - <rule>
  - <rule>
deny:
  - <rule>
  - <rule>
default: allow | deny
```

**Evaluation order:** deny rules are checked first. If no deny rule matches, allow rules are checked. If no rule matches, the `default` is applied. If `default` is unspecified, it is `deny` for hard-security sections (Filesystem, Network, Capabilities) and `allow` for soft sections.

---

## 5. The sections

### 5.1 `## Filesystem`

```yaml
allow:
  - read: /workspace/**
  - write: /workspace/output/**
  - list: /workspace/**
deny:
  - read: ~/.ssh/**
  - read: /workspace/secrets/**
  - execute: "**"
default: deny
```

**Operations:** `read`, `write`, `execute`, `delete`, `list`.

**Paths:** glob patterns. `*` matches any character except `/`. `**` matches across `/`. `?` matches a single character.

### 5.2 `## Network`

```yaml
allow:
  - url: "https://api.company.com/**"
    methods: [GET, POST]
deny:
  - url: "**"
default: deny
```

**`url`:** glob pattern matched against the full URL.
**`methods`:** optional list of HTTP methods this rule applies to. Omit to apply to all.

**`model_jurisdictions`:** optional `allow` and/or `deny` lists of jurisdiction codes (`us`, `cn`, `eu`, `ca`). The enforcing host knows the major model API endpoints and the jurisdiction of the company behind each. It denies a request to a known model endpoint whose jurisdiction is in `deny`, or not in `allow` when `allow` is given, unless an allow rule names that exact host. Hosts it doesn't recognize as model endpoints are unaffected. (Ward 0.3.10)

### 5.3 `## Capabilities`

```yaml
allow:
  - file_read
  - file_write
  - http_request
requireApproval:
  - secrets_read
  - code_exec
deny:
  - shell_exec
  - ssh
  - sudo
default: deny
```

Tool names are strings. They may use glob patterns.

`requireApproval` produces a `require_approval` decision at runtime — hosts decide how to gather approval (chat prompt, webhook, etc).

### 5.4 `## Data Boundaries`

```yaml
egressAllow: [public, internal]
egressDeny: [confidential, secret, pii, phi, pci, credentials]
redact:
  - type: pii
    replacement: "[REDACTED]"
```

**Classifications:** `public`, `internal`, `confidential`, `secret`, `pii`, `phi`, `pci`, `credentials`. Custom classifications are permitted; hosts may ignore unrecognized ones.

**Enforcement.** A host classifies the data a tool call sends and applies these rules to every destination, including hosts the Network section allows. A class in `egressDeny` is denied. When `egressAllow` is non-empty, a class it doesn't list is denied. A credential sent only to its own issuer (a GitHub token to `api.github.com`) is not egress of that credential. Hosts may add stricter defaults. The reference implementation (Ward 0.3.5) asks for approval before credentials go anywhere but their issuer, and before sensitive data goes to a model API that the Network section doesn't name.

### 5.5 `## Behavioral Limits`

```yaml
maxIterations: 50
maxRuntimeSeconds: 300
maxCostUSD: 5.00
maxTokens: 100000
maxToolCalls: 30
maxExternalServices: 3
```

All fields are optional. A missing field means the limit is unenforced.

**Enforcement.** `maxToolCalls`, `maxRuntimeSeconds` and `maxExternalServices` apply per session. The session is the harness's conversation or session id, and runtime counts from the session's first tool call. A host that can't keep history across calls may ignore them. `maxIterations`, `maxCostUSD` and `maxTokens` need model usage, which tool hooks don't see.

### 5.5.1 `spending_limits:`

```yaml
spending_limits:
  - window: day            # run | hour | day | week | month
    budget:
      usd: 5.00            # LLM spend
      tokens: 200000       # LLM tokens
      tool_calls: 100
      tools:
        send_payment:
          max_amount_usd: 500
          max_calls: 5
    on_exceeded: require_approval   # block | require_approval | notify
    label: daily budget
```

The block may appear in its own `## Spending Limits` section or anywhere in the body. `run` is one session, and the other windows are rolling. Hosts that see tool calls enforce `tool_calls` and `tools`; hosts that see model usage enforce `usd` and `tokens`.

**Payments.** A host should ask for approval before a tool call that moves money, unless the Capabilities section allows that capability by name or allows `payments`.

### 5.6 `## Multi-Agent`

```yaml
isolation: strict
maxSemanticDrift: 0.3
trustChain:
  upstream: [data-fetcher]
  downstream: [report-generator]
```

**`isolation`:** `none`, `soft`, `strict`, `sandboxed`.
**`maxSemanticDrift`:** number 0–1. The interpretation is host-specific.
**`trustChain`:** which other agents may hand work to / receive work from this one.

### 5.7 `## Compliance`

```yaml
frameworks: [soc2, hipaa, gdpr]
backend: domere
```

Declaring a framework signals that the agent operates under that regime. Hosts may auto-inject additional constraints (e.g., HIPAA implies certain data classifications must be in `egressDeny`).

### 5.8 `## Verification`

```yaml
required: true
backend: domere
blockchain: solana
frequency: every_action
attestor: <pubkey or DID>
```

**`frequency`:** `every_action`, `every_handoff`, `every_iteration`, `session_end`, `manual`.

**Receipts.** With `required: true` and `frequency: every_action` (or unset), a host records every tool-call decision as a receipt. A receipt holds the decision, the tool and capability, the reasons, and digests of the arguments and the policy. It is chained by hash to the previous receipt and signed. `attestor` names the public key that verifiers should expect. The reference implementation (Ward 0.3.7) uses Ed25519 over SHA-256 hashes of canonical JSON, and stores arguments only as a keyed HMAC. A chain can't show that its newest receipts were removed, so a host should periodically commit the head elsewhere as a signed **checkpoint** (agent, sequence number, head hash, time, key), stored where the host can't rewrite it, and verifiers should check the log against every checkpoint they hold. Ward 0.3.9 signs checkpoints with the receipt key (`ward-checkpoint/v1:` + SHA-256 of the canonical checkpoint). Dōmere 1.7.0 anchors batches of them on-chain under one Merkle root.

### 5.8.1 Signed policies

A WARD.md may end with a signature line:

```
<!-- ward-signature v1 keyId=<16 hex> publicKey=<base64 SPKI> signedAt=<ISO 8601> sig=<base64> -->
```

`sig` is an Ed25519 signature over the ASCII string `ward-policy/v1:` followed by the hex SHA-256 of the file without that line. Before hashing, line endings are normalized to `\n`, trailing whitespace is removed, and one final `\n` is added. `keyId` is the first 16 hex characters of the SHA-256 of the public key.

A host decides which keys it trusts outside the policy file. When it has trusted keys, it must not enforce a policy unless that policy carries a valid signature from one of them. A host should never enforce a signed policy whose signature doesn't verify. The reference implementation (Ward 0.3.8) denies every call in both cases.

### 5.9 `## Threat Model`

```yaml
inScope:
  - prompt_injection
  - data_exfil
  - credential_theft
outOfScope:
  - physical_attack
  - side_channel
```

Informational. Documents what the policy is designed to defend against. Hosts may use this to tune scanner sensitivity.

### 5.10 `## Incident Response`

```yaml
onViolation:
  - log
  - alert
  - terminate
  - attest_violation
severityThreshold: medium
```

**Actions:** `log`, `alert`, `terminate`, `rollback`, `attest_violation`, `notify_human`, `block_further`.
**`severityThreshold`:** minimum severity at which actions fire. `low` | `medium` | `high` | `critical`.

---

## 6. Validation

A WARD.md file is **valid** if it parses and contains no semantic errors. It may still produce **warnings** for missing recommended sections (e.g., no behavioral limits, no verification).

CI integrations should treat `weave-ward validate` exit code `1` as a failed check.

---

## 7. Versioning

This document specifies `ward: "1.0"`. Future minor versions will add sections or fields and remain backwards compatible. Major version bumps may change the semantics of existing fields and will require explicit migration.

---

## 8. Extensions

The format is intentionally extensible. Unknown sections are preserved by parsers and may be interpreted by host-specific tooling. Hosts wishing to add proprietary sections should namespace them (e.g., `## X-CompanyName-Policy`).

---

## 9. Reference implementation

The reference parser, validator, and runtime check primitives are published as [`@weave_protocol/ward`](https://www.npmjs.com/package/@weave_protocol/ward). All other implementations must produce equivalent results for any well-formed WARD.md file.

---

## 10. License

This specification is published under [Apache 2.0](../LICENSE). The format is free to adopt without restriction.
