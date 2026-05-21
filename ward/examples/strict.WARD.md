---
ward: "1.0"
agent: production-deployer
name: Strict Production Deployment Agent
description: Locked-down policy for an agent that deploys code to production. Approval required for all elevated actions. Mandatory blockchain attestation.
---

# WARD.md

Strict policy for a production deployment agent. Default-deny across the
board. Any action that could affect production goes through human approval.
Every action is cryptographically attested.

## Filesystem

allow:
  - read: /workspace/build/**
  - read: /workspace/config/**
  - write: /workspace/logs/**
deny:
  - read: ~/.ssh/**
  - read: ~/.aws/**
  - read: ~/.kube/**
  - write: /etc/**
  - write: /usr/**
  - execute: "**"
  - delete: "**"
default: deny

## Network

allow:
  - url: "https://api.github.com/**"
    methods: [GET]
  - url: "https://registry.npmjs.org/**"
    methods: [GET]
default: deny

## Capabilities

allow:
  - file_read
  - file_write
  - log_write
requireApproval:
  - deploy
  - rollback
  - http_request
  - secrets_read
deny:
  - shell_exec
  - ssh
  - sudo
  - kubectl
  - terraform_apply
default: deny

## Data Boundaries

egressAllow:
  - public
egressDeny:
  - internal
  - confidential
  - secret
  - pii
  - phi
  - pci
  - credentials

## Behavioral Limits

maxIterations: 20
maxRuntimeSeconds: 600
maxCostUSD: 1.00
maxTokens: 25000
maxToolCalls: 15
maxExternalServices: 2

## Multi-Agent

isolation: strict
maxSemanticDrift: 0.2
trustChain:
  upstream:
    - ci-orchestrator
  downstream:
    - notification-agent

## Compliance

frameworks:
  - soc2
  - iso27001
backend: domere

## Verification

required: true
backend: domere
blockchain: solana
frequency: every_action

## Threat Model

inScope:
  - prompt_injection
  - data_exfil
  - credential_theft
  - tool_misuse
  - semantic_drift
  - emergent_behavior
  - supply_chain
outOfScope:
  - physical_attack
  - side_channel

## Incident Response

onViolation:
  - log
  - alert
  - terminate
  - attest_violation
  - notify_human
  - block_further
severityThreshold: low
