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
