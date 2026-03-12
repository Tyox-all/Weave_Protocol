---
name: weave-api-calling
description: Access Weave Protocol functionality via REST API. Use when MCP tools are unavailable and HTTP access is needed, or when integrating Weave into web applications.
---

# Weave Protocol REST API

## Overview

HTTP endpoints for all Mund, Hord, Domere, and Witan functionality. Use when MCP is unavailable or for web integration.

## Start Server

```bash
npx @weave_protocol/api
# or
docker run -p 3000:3000 weave-protocol/api
```

## Endpoints

### Mund (Security)
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/mund/scan` | Scan content |
| POST | `/mund/scan-mcp-server` | Vet MCP server |
| POST | `/mund/check-secret` | Check for secret |
| POST | `/mund/check-pii` | Detect PII |

### Hord (Encryption)
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/hord/encrypt` | Encrypt data |
| POST | `/hord/decrypt` | Decrypt data |
| POST | `/hord/yoxallismus/lock` | Yoxallismus lock |
| POST | `/hord/yoxallismus/unlock` | Yoxallismus unlock |

### Domere (Compliance)
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/domere/checkpoint` | Create checkpoint |
| POST | `/domere/compliance/report` | Generate report |
| POST | `/domere/anchor` | Blockchain anchor |

### Witan (Governance)
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/witan/propose` | Create proposal |
| POST | `/witan/vote` | Cast vote |
| POST | `/witan/escalate` | Escalate decision |

## Quick Examples

### Scan content
```bash
curl -X POST http://localhost:3000/mund/scan \
  -H "Content-Type: application/json" \
  -d '{"content": "sk-abc123..."}'
```

### Encrypt data
```bash
curl -X POST http://localhost:3000/hord/encrypt \
  -H "Content-Type: application/json" \
  -d '{"data": "secret", "key": "my-key"}'
```

### Create checkpoint
```bash
curl -X POST http://localhost:3000/domere/checkpoint \
  -H "Content-Type: application/json" \
  -d '{"action": "data_access", "actor": "agent-001"}'
```

## When to Use

1. Web application integration
2. Environments without MCP support
3. Microservice architectures
4. CI/CD pipelines

## Links

- npm: https://www.npmjs.com/package/@weave_protocol/api
