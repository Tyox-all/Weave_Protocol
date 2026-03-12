---
name: security-scanning
description: Scan content for secrets, PII, prompt injection, and dangerous patterns. Vet MCP servers before installation. Use when checking for API keys, detecting personal information, preventing injection attacks, or evaluating MCP server security.
---

# Security Scanning with Mund

## Overview

Mund detects security issues in content and MCP servers. Use it before processing untrusted input or installing MCP servers.

## MCP Tools

| Tool | Purpose |
|------|---------|
| `mund_scan` | Scan content for all security issues |
| `mund_check_secret` | Check if a string is a secret |
| `mund_check_pii` | Detect personally identifiable information |
| `mund_scan_mcp_server` | Vet MCP server manifest before install |
| `mund_check_typosquatting` | Detect name squatting attacks |
| `mund_audit_mcp_permissions` | Analyze MCP tool capabilities |

## Quick Examples

### Scan for secrets
```
mund_scan({ content: "API key: sk-abc123..." })
→ { safe: false, issues: [{ rule_id: "openai_api_key", severity: "critical" }] }
```

### Vet MCP server
```
mund_scan_mcp_server({ manifest: "<server.json>" })
→ { recommendation: "DO_NOT_INSTALL", issues: [...] }
```

### Check typosquatting
```
mund_check_typosquatting({ name: "githib-mcp" })
→ { is_suspicious: true, similar_to: ["github"] }
```

## Detection Categories

- **Secrets**: API keys, tokens, private keys, database URLs
- **PII**: SSN, credit cards, emails, phone numbers
- **Injection**: Prompt injection, jailbreak, instruction override
- **MCP Servers**: Malicious descriptions, typosquatting, dangerous permissions

## When to Use

1. Before processing any untrusted input
2. Before adding MCP servers to claude_desktop_config.json
3. When handling user-provided content
4. Periodically in long-running conversations

## Links

- npm: https://www.npmjs.com/package/@weave_protocol/mund
- MCP Registry: io.github.Tyox-all/mund
