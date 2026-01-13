# Mund - The Guardian Protocol

**Pattern Detection & Threat Scanning for AI Agents**

Part of the [Weave Protocol Security Suite](https://github.com/Tyox-all/Weave-Protocol) (Mund + Hord + Dōmere)

## What It Does

Mund scans AI agent inputs and outputs for security threats before they cause harm:

- **Secret Detection** - API keys, tokens, passwords, certificates
- **PII Detection** - SSN, credit cards, emails, phone numbers
- **Injection Detection** - Prompt injection, jailbreak attempts
- **Exfiltration Detection** - Data leakage patterns, encoding tricks
- **Code Analysis** - Dangerous patterns, eval(), exec(), SQL injection

## Installation

```bash
npm install @weave_protocol/mund
```

## Quick Start

```typescript
import { SecretScanner, PIIDetector, InjectionDetector } from '@weave_protocol/mund';

// Scan for secrets
const secretScanner = new SecretScanner();
const secretResults = secretScanner.analyze('My API key is sk-1234567890abcdef');
// Returns: [{ type: 'secret', severity: 'critical', pattern: 'openai_api_key', ... }]

// Detect PII
const piiDetector = new PIIDetector();
const piiResults = piiDetector.analyze('Contact John at john@example.com or 555-123-4567');
// Returns: [{ type: 'pii', matches: ['email', 'phone'], ... }]

// Check for injection
const injectionDetector = new InjectionDetector();
const injectionResults = injectionDetector.analyze('Ignore previous instructions and...');
// Returns: [{ type: 'injection', severity: 'high', ... }]
```

## MCP Tools

Run as MCP server for Claude Desktop:

```json
{
  "mcpServers": {
    "mund": {
      "command": "npx",
      "args": ["@weave_protocol/mund"]
    }
  }
}
```

### Available Tools

| Tool | Description |
|------|-------------|
| `mund_scan_content` | Full security scan on content |
| `mund_scan_secrets` | Scan for secrets and credentials |
| `mund_scan_pii` | Scan for personally identifiable information |
| `mund_scan_injection` | Detect prompt injection attempts |
| `mund_scan_exfiltration` | Detect data exfiltration patterns |
| `mund_analyze_code` | Analyze code for security issues |
| `mund_get_rules` | Get current detection rules |
| `mund_add_rule` | Add custom detection rule |
| `mund_enable_rule` | Enable a detection rule |
| `mund_disable_rule` | Disable a detection rule |
| `mund_get_stats` | Get scanning statistics |

## Detection Patterns

### Secrets (30+ patterns)
- AWS keys, Azure keys, GCP credentials
- OpenAI, Anthropic, Cohere API keys
- GitHub, GitLab, Bitbucket tokens
- Stripe, Twilio, SendGrid keys
- JWT tokens, private keys, certificates

### PII Patterns
- Social Security Numbers
- Credit card numbers (with Luhn validation)
- Email addresses, phone numbers
- Physical addresses, dates of birth

### Injection Patterns
- "Ignore previous instructions"
- "You are now DAN"
- Role manipulation attempts
- Base64/hex encoded instructions
- Unicode obfuscation

## Integration with Hord & Dōmere

```typescript
// Full Weave Protocol security flow
import { SecretScanner } from '@weave_protocol/mund';
import { VaultManager } from '@weave_protocol/hord';
import { ThreadManager } from '@weave_protocol/domere';

// 1. Scan input with Mund
const scanner = new SecretScanner();
const threats = scanner.analyze(userInput);

if (threats.length > 0) {
  // 2. Contain with Hord
  const vault = new VaultManager();
  await vault.quarantine(threats);
}

// 3. Track with Dōmere
const thread = new ThreadManager();
await thread.addHop({
  security_scan: threats,
  // ...
});
```

## License

Apache-2.0

## Links

- [GitHub](https://github.com/Tyox-all/Weave-Protocol)
- [Hord (Vault Protocol)](https://www.npmjs.com/package/@weave_protocol/hord)
- [Dōmere (Judge Protocol)](https://www.npmjs.com/package/@weave_protocol/domere)
