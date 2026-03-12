---
name: weave-api
description: "Use this skill when accessing Weave Protocol functionality via REST API. Triggers: making HTTP requests to Weave services, integrating Weave into web applications, using curl/fetch to call security/encryption/compliance endpoints, or any request involving 'REST API', 'HTTP endpoint', 'API call', 'curl', or 'fetch weave'. Use this when MCP tools are not available but HTTP access is."
license: Apache 2.0
---

# 🔌 Weave Protocol API Guide

## Overview

The Weave Protocol API provides HTTP endpoints for all Mund, Hord, Domere, and Witan functionality. Use it when integrating Weave into web applications, microservices, or environments without MCP support.

## Quick Start

```bash
# Start the API server
npx @weave_protocol/api

# Or with Docker
docker run -p 3000:3000 weave-protocol/api
```

```typescript
// Example: Scan content via API
const response = await fetch('http://localhost:3000/mund/scan', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ content: 'Check this for secrets...' })
});
const result = await response.json();
```

## Endpoints Reference

### 🛡️ Mund - Security Scanning

| Method | Path | Description |
|--------|------|-------------|
| POST | `/mund/scan` | Scan content for security issues |
| POST | `/mund/scan-conversation` | Scan conversation history |
| POST | `/mund/check-secret` | Check if string is a secret |
| POST | `/mund/check-pii` | Detect PII in content |
| POST | `/mund/scan-mcp-server` | Vet MCP server manifest |
| POST | `/mund/check-typosquatting` | Detect name squatting |
| POST | `/mund/audit-permissions` | Audit MCP permissions |
| GET | `/mund/stats` | Get scanning statistics |

### 🏛️ Hord - Encryption

| Method | Path | Description |
|--------|------|-------------|
| POST | `/hord/encrypt` | Encrypt data with AES-256-GCM |
| POST | `/hord/decrypt` | Decrypt data |
| POST | `/hord/yoxallismus/lock` | Lock with Yoxallismus cipher |
| POST | `/hord/yoxallismus/unlock` | Unlock Yoxallismus data |
| POST | `/hord/vault/store` | Store secret in vault |
| POST | `/hord/vault/retrieve` | Retrieve secret from vault |
| GET | `/hord/vault/list` | List vault contents |
| DELETE | `/hord/vault/:name` | Delete vault secret |
| POST | `/hord/generate-key` | Generate secure random key |

### ⚖️ Domere - Compliance

| Method | Path | Description |
|--------|------|-------------|
| POST | `/domere/checkpoint` | Create audit checkpoint |
| POST | `/domere/verify-intent` | Verify action matches intent |
| POST | `/domere/compliance/report` | Generate compliance report |
| GET | `/domere/compliance/frameworks` | List available frameworks |
| POST | `/domere/anchor` | Anchor to blockchain |
| POST | `/domere/orchestrate` | Schedule multi-agent task |
| POST | `/domere/register-agent` | Register agent |

### 👥 Witan - Governance

| Method | Path | Description |
|--------|------|-------------|
| POST | `/witan/propose` | Create consensus proposal |
| POST | `/witan/vote` | Vote on proposal |
| GET | `/witan/proposal/:id` | Check proposal status |
| POST | `/witan/policy` | Create governance policy |
| POST | `/witan/enforce` | Check policy enforcement |
| POST | `/witan/broadcast` | Broadcast to all agents |
| POST | `/witan/escalate` | Escalate to authority |

---

## Common API Calls

### Scan Content for Secrets

```bash
curl -X POST http://localhost:3000/mund/scan \
  -H "Content-Type: application/json" \
  -d '{"content": "My API key is sk-abc123..."}'
```

```json
{
  "safe": false,
  "issue_count": 1,
  "issues": [{
    "rule_id": "openai_api_key",
    "severity": "critical",
    "match": "sk-a****123"
  }]
}
```

### Encrypt Data

```bash
curl -X POST http://localhost:3000/hord/encrypt \
  -H "Content-Type: application/json" \
  -d '{"data": "sensitive info", "key": "my-secret-key"}'
```

```json
{
  "ciphertext": "base64-encoded...",
  "iv": "initialization-vector",
  "tag": "auth-tag"
}
```

### Lock with Yoxallismus

```bash
curl -X POST http://localhost:3000/hord/yoxallismus/lock \
  -H "Content-Type: application/json" \
  -d '{"data": "top secret", "key": "master-key"}'
```

```json
{
  "locked": "yox1:tumbler:deadbolt:payload",
  "metadata": {
    "algorithm": "yoxallismus-v1"
  }
}
```

### Create Compliance Checkpoint

```bash
curl -X POST http://localhost:3000/domere/checkpoint \
  -H "Content-Type: application/json" \
  -d '{
    "action": "data_access",
    "resource": "customer_records",
    "actor": "agent-001"
  }'
```

```json
{
  "checkpoint_id": "chk_abc123",
  "timestamp": "2024-01-15T10:30:00Z",
  "hash": "sha256:..."
}
```

### Propose Consensus

```bash
curl -X POST http://localhost:3000/witan/propose \
  -H "Content-Type: application/json" \
  -d '{
    "action": "deploy_to_production",
    "required_approvals": ["security-agent", "qa-agent"],
    "protocol": "unanimous"
  }'
```

```json
{
  "proposal_id": "prop_xyz789",
  "status": "pending",
  "votes": {
    "required": 2,
    "received": 0
  }
}
```

---

## Authentication

```bash
# With API key header
curl -X POST http://localhost:3000/mund/scan \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"content": "..."}'
```

Environment variables:
```bash
WEAVE_API_KEY=your-api-key
WEAVE_API_PORT=3000
WEAVE_API_HOST=0.0.0.0
```

---

## Error Handling

```json
{
  "error": true,
  "code": "VALIDATION_ERROR",
  "message": "Missing required field: content",
  "details": {
    "field": "content",
    "expected": "string"
  }
}
```

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `VALIDATION_ERROR` | 400 | Invalid request body |
| `UNAUTHORIZED` | 401 | Missing/invalid API key |
| `NOT_FOUND` | 404 | Resource not found |
| `RATE_LIMITED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Server error |

---

## Rate Limits

| Tier | Requests/min | Burst |
|------|--------------|-------|
| Free | 60 | 10 |
| Pro | 600 | 100 |
| Enterprise | Unlimited | Unlimited |

---

## SDK Usage

```typescript
import { WeaveClient } from '@weave_protocol/api/client';

const client = new WeaveClient({
  baseUrl: 'http://localhost:3000',
  apiKey: 'your-api-key'
});

// Scan content
const scan = await client.mund.scan({ content: '...' });

// Encrypt data
const encrypted = await client.hord.encrypt({ data: '...', key: '...' });

// Create checkpoint
const checkpoint = await client.domere.createCheckpoint({
  action: 'data_access',
  resource: 'records',
  actor: 'agent-001'
});

// Propose consensus
const proposal = await client.witan.propose({
  action: 'deploy',
  requiredApprovals: ['agent-1', 'agent-2']
});
```

---

## Docker Deployment

```bash
# Pull and run
docker run -p 3000:3000 \
  -e WEAVE_API_KEY=your-key \
  weave-protocol/api

# With docker-compose
version: '3.8'
services:
  weave-api:
    image: weave-protocol/api
    ports:
      - "3000:3000"
    environment:
      - WEAVE_API_KEY=${WEAVE_API_KEY}
```

---

## Best Practices

1. **Always use HTTPS** in production
2. **Store API keys** in environment variables
3. **Handle rate limits** with exponential backoff
4. **Log API responses** with Domere checkpoints
5. **Validate inputs** before sending to API

---

## Links

- **npm:** https://www.npmjs.com/package/@weave_protocol/api
- **GitHub:** https://github.com/Tyox-all/Weave_Protocol
