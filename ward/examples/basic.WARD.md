---
ward: "1.0"
agent: my-data-analyzer
name: Data Analyzer Security Policy
description: Read-only analytics agent that produces summary reports. No external network, no credential access.
---

# WARD.md

Security policy for a basic read-only data analyzer.

## Filesystem

allow:
  - read: /workspace/input/**
  - write: /workspace/output/**
  - list: /workspace/**
deny:
  - read: /workspace/secrets/**
  - read: ~/.ssh/**
  - read: ~/.aws/**
default: deny

## Network

default: deny

## Capabilities

allow:
  - file_read
  - file_write
  - code_exec
deny:
  - shell_exec
  - ssh
  - http_request
default: deny

## Behavioral Limits

maxIterations: 50
maxRuntimeSeconds: 300
maxCostUSD: 5.00
maxTokens: 100000

## Data Boundaries

egressDeny:
  - credentials
  - secret
  - pii

## Verification

required: true
backend: domere
blockchain: solana
frequency: session_end

## Threat Model

inScope:
  - prompt_injection
  - data_exfil
  - tool_misuse

## Incident Response

onViolation:
  - log
  - alert
  - terminate
severityThreshold: medium
