---
ward: "1.0"
agent: healthcare-records-assistant
name: HIPAA-Compliant Records Agent
description: Agent that handles patient records. HIPAA + SOC2. All PII/PHI access attested.
---

# WARD.md

Compliance-first policy for an agent operating in a regulated healthcare
context. PHI access is permitted within strict boundaries, but every read,
write, and transfer is attested to the blockchain.

## Filesystem

allow:
  - read: /records/active/**
  - read: /workspace/templates/**
  - write: /workspace/output/**
deny:
  - read: /records/archived/**
  - read: ~/.ssh/**
  - write: /records/**
  - execute: "**"
default: deny

## Network

allow:
  - url: "https://ehr.hospital.internal/**"
    methods: [GET, POST]
  - url: "https://api.openai.com/v1/chat/**"
    methods: [POST]
deny:
  - url: "**"
default: deny

## Capabilities

allow:
  - file_read
  - file_write
  - ehr_query
requireApproval:
  - phi_export
  - record_modify
deny:
  - shell_exec
  - http_request
default: deny

## Data Boundaries

egressAllow:
  - public
  - internal
egressDeny:
  - phi
  - pii
  - credentials
  - secret
redact:
  - type: phi
    replacement: "[REDACTED PHI]"
  - type: pii
    replacement: "[REDACTED PII]"

## Behavioral Limits

maxIterations: 30
maxRuntimeSeconds: 180
maxCostUSD: 3.00
maxTokens: 50000
maxToolCalls: 25

## Compliance

frameworks:
  - hipaa
  - soc2
  - gdpr
backend: domere

## Verification

required: true
backend: domere
blockchain: ethereum
frequency: every_action

## Threat Model

inScope:
  - prompt_injection
  - data_exfil
  - credential_theft
  - tool_misuse
  - semantic_drift

## Incident Response

onViolation:
  - log
  - alert
  - terminate
  - attest_violation
  - notify_human
severityThreshold: low
