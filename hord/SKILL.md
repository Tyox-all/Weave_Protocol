---
name: encrypting-data
description: Store secrets and agent memory in encrypted vaults, redact or tokenize PII, run code in a sandbox, issue capability tokens, and record signed attestations with Hord. Use when protecting credentials, storing secrets securely, redacting PII, or when the user mentions vault, secret storage, tokenization, capability tokens, or attestation. For encrypting a message or file to someone, use @weave_protocol/yoxallismus instead.
---

# Protecting Data with Hord

## Overview

Hord keeps agent secrets and memory in encrypted vaults (AES-256-GCM), redacts or tokenizes PII, issues scoped capability tokens, and signs attestations of agent actions.

**Not for message or file encryption.** To encrypt something to a recipient, use `seal()` / `open()` from `@weave_protocol/yoxallismus`. Hord's old `YoxallismusCipher` is deprecated because its output can't be decrypted (advisory YOXALL-2026-003). Never use it to protect data.

## MCP Tools

| Area | Tool | Purpose |
|------|------|---------|
| Vaults | `hord_create_vault` | Create an encrypted vault for agent state, memories and credentials |
| | `hord_open_vault` / `hord_seal_vault` | Open a vault for use / close and re-encrypt it |
| | `hord_store_secret` / `hord_retrieve_secret` | Store / retrieve an encrypted credential |
| | `hord_store_memory` / `hord_retrieve_memories` | Store / retrieve agent memories |
| | `hord_list_vaults` | List vaults an agent can access |
| Redaction | `hord_redact_content` | Redact sensitive data from content |
| | `hord_tokenize_pii` / `hord_detokenize` | Replace PII with reversible tokens / restore it |
| | `hord_create_redaction_policy` / `hord_list_redaction_policies` | Manage redaction policies |
| Capabilities | `hord_request_capability` / `hord_verify_capability` | Get a scoped, expiring capability token / check it |
| | `hord_delegate_capability` / `hord_revoke_capability` / `hord_list_capabilities` | Delegate (depth-limited), revoke, list |
| Sandbox | `hord_create_sandbox` / `hord_execute_in_sandbox` / `hord_get_sandbox_results` | Run code in an isolated process: no network, writes only to its workdir, scrubbed env, memory/CPU limits |
| | `hord_promote_sandbox_result` / `hord_destroy_sandbox` | Promote a result for real execution / clean up |
| Attestation | `hord_attest_action` / `hord_verify_attestation` | Sign an action record / verify it |
| | `hord_get_attestations` / `hord_get_attestation_chain` / `hord_export_audit_log` | Query and export the hash-chained record |

## When to Use

1. Store credentials and API keys with `hord_store_secret`, never in plain files or prompts.
2. Run PII through `hord_tokenize_pii` before sending it to a model, and `hord_detokenize` only where the real value is needed.
3. Give agents scoped capability tokens instead of standing credentials.
4. Attest consequential actions so there's a verifiable audit trail.

## Caveats

- Sandbox isolation uses what the host OS provides: `sandbox-exec` on macOS, `bwrap` (or `unshare`, network only) on Linux. Every result includes an `isolation` report. Where a layer is missing, the run still happens but gets an `isolation_unavailable` warning and a REVIEW recommendation; pass `enforcement: "strict"` to refuse instead.
- This is process-level isolation, not a VM. Kernel exploits and side channels are out of scope; for hostile code, run Hord inside a container or VM as well.

## Links

- npm: https://www.npmjs.com/package/@weave_protocol/hord
- Encryption to a recipient: https://www.npmjs.com/package/@weave_protocol/yoxallismus
