# Mund: The Guardian Protocol

## Executive Summary

**Mund** (from Old English meaning "guardian, protector") is an open-source MCP-based security monitoring protocol designed to watch agentic AI systems for security vulnerabilities, code leaks, and policy violations. It sits as an MCP service that intercepts, analyzes, and reports on AI agent activities.

## Project Vision

### Core Problem
As AI agents become more autonomous, they interact with codebases, APIs, databases, and external services. This creates risks:
- **Code/Secret Leaks**: Agents may inadvertently expose API keys, credentials, or proprietary code
- **Security Violations**: Agents may access unauthorized resources or execute dangerous commands
- **Policy Violations**: Agents may violate organizational policies around data handling
- **Prompt Injection**: Malicious inputs may manipulate agent behavior
- **Exfiltration Attempts**: Agents may be tricked into sending data to unauthorized destinations

### Solution
Mund acts as a transparent proxy/observer that:
1. Monitors all tool calls made by AI agents
2. Analyzes inputs/outputs for security concerns
3. Alerts via multiple channels (Slack, Teams, Email, Browser)
4. Provides a dashboard for security oversight
5. Can block dangerous operations in real-time

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AI AGENT (Claude, Gemini, GPT, etc.)         │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         MUND MCP SERVER                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐  │
│  │   Analyzer  │  │   Scanner   │  │   Rules     │  │   Logger   │  │
│  │   Engine    │  │   (Secrets) │  │   Engine    │  │            │  │
│  └─────────────┘  └─────────────┘  └─────────────┘  └────────────┘  │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │                    NOTIFICATION HUB                              ││
│  │  [Slack] [Teams] [Email] [Webhook] [Browser Extension]          ││
│  └─────────────────────────────────────────────────────────────────┘│
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │                    API / DASHBOARD                               ││
│  └─────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    ACTUAL MCP TOOLS/SERVICES                        │
│         (File System, Git, Database, APIs, etc.)                    │
└─────────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Analyzer Engine
- **Secret Detection**: Identifies API keys, tokens, passwords, certificates
- **PII Detection**: Finds personal identifiable information
- **Code Pattern Analysis**: Detects suspicious code patterns
- **Injection Detection**: Identifies prompt injection attempts
- **Exfiltration Detection**: Monitors for data leaving to unauthorized destinations

### 2. Rules Engine
- **Built-in Rules**: Common security patterns
- **Custom Rules**: YAML/JSON configurable rules
- **Severity Levels**: Critical, High, Medium, Low, Info
- **Action Types**: Alert, Block, Log, Quarantine

### 3. Notification Hub
- **Slack Integration**: Real-time alerts to channels
- **Microsoft Teams**: Webhook-based notifications
- **Email**: SMTP-based alerts with configurable templates
- **Webhooks**: Generic webhook support
- **Browser Extension**: Chrome/Firefox extension for desktop notifications

### 4. API & Dashboard
- **REST API**: Query events, configure rules, manage alerts
- **Web Dashboard**: Real-time monitoring interface
- **Event Stream**: WebSocket for live updates

## Security Detectors

### Secret Patterns
```yaml
detectors:
  - name: aws_access_key
    pattern: 'AKIA[0-9A-Z]{16}'
    severity: critical
    
  - name: github_token
    pattern: 'gh[pousr]_[A-Za-z0-9_]{36}'
    severity: critical
    
  - name: gemini_api_key
    pattern: 'AIza[0-9A-Za-z_-]{35}'
    severity: critical
    
  - name: private_key
    pattern: '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
    severity: critical
```

### Behavioral Patterns
```yaml
behavioral_rules:
  - name: mass_file_access
    trigger: file_read_count > 50 in 60s
    severity: medium
    
  - name: network_exfiltration
    trigger: outbound_data > 10MB to unknown_host
    severity: critical
    
  - name: privilege_escalation
    trigger: sudo_attempt OR chmod_777
    severity: high
```

## MCP Tools Exposed

### Monitoring Tools
1. `mund_scan_content` - Scan text/code for security issues
2. `mund_check_url` - Validate URL safety before access
3. `mund_validate_command` - Check shell command safety
4. `mund_get_events` - Retrieve recent security events
5. `mund_get_status` - Get current monitoring status

### Configuration Tools
6. `mund_add_rule` - Add custom detection rule
7. `mund_remove_rule` - Remove a detection rule
8. `mund_list_rules` - List all active rules
9. `mund_configure_notification` - Set up notification channel
10. `mund_set_policy` - Configure security policies

### Response Tools
11. `mund_acknowledge_alert` - Mark alert as reviewed
12. `mund_block_pattern` - Add pattern to blocklist
13. `mund_allowlist_pattern` - Add pattern to allowlist

## Technology Stack

### Primary Implementation (TypeScript)
- **Runtime**: Node.js 20+
- **MCP SDK**: @modelcontextprotocol/sdk
- **HTTP Server**: Express
- **Validation**: Zod
- **Database**: SQLite (embedded) or PostgreSQL (production)
- **Queue**: In-memory or Redis for high-volume

### Alternative Implementation (Python)
- **Runtime**: Python 3.11+
- **MCP SDK**: mcp (FastMCP)
- **Validation**: Pydantic
- **HTTP**: FastAPI
- **Database**: SQLite/PostgreSQL via SQLAlchemy

## Directory Structure

```
mund-mcp/
├── README.md
├── LICENSE (MIT)
├── CONTRIBUTING.md
├── SECURITY.md
├── package.json
├── tsconfig.json
├── docker-compose.yml
├── Dockerfile
│
├── src/
│   ├── index.ts              # Main entry point
│   ├── server.ts             # MCP server setup
│   ├── types.ts              # TypeScript interfaces
│   ├── constants.ts          # Configuration constants
│   │
│   ├── analyzers/
│   │   ├── index.ts
│   │   ├── secret-scanner.ts # Secret detection
│   │   ├── pii-detector.ts   # PII detection
│   │   ├── code-analyzer.ts  # Code pattern analysis
│   │   ├── injection-detector.ts
│   │   └── exfiltration-detector.ts
│   │
│   ├── rules/
│   │   ├── index.ts
│   │   ├── engine.ts         # Rules engine
│   │   ├── built-in.ts       # Default rules
│   │   └── parser.ts         # Rule parser
│   │
│   ├── tools/
│   │   ├── index.ts
│   │   ├── monitoring.ts     # Monitoring tools
│   │   ├── configuration.ts  # Config tools
│   │   └── response.ts       # Response tools
│   │
│   ├── notifications/
│   │   ├── index.ts
│   │   ├── slack.ts
│   │   ├── teams.ts
│   │   ├── email.ts
│   │   └── webhook.ts
│   │
│   ├── storage/
│   │   ├── index.ts
│   │   ├── sqlite.ts
│   │   └── memory.ts
│   │
│   └── api/
│       ├── index.ts
│       ├── routes.ts
│       └── dashboard.ts
│
├── rules/
│   ├── default.yaml          # Default detection rules
│   └── examples/
│       ├── strict.yaml
│       └── permissive.yaml
│
├── dashboard/
│   └── (React dashboard - future)
│
├── extensions/
│   ├── chrome/
│   └── firefox/
│
└── tests/
    ├── analyzers/
    ├── rules/
    └── integration/
```

## Configuration

### Environment Variables
```bash
# Core Settings
MUND_PORT=3000
MUND_HOST=127.0.0.1
MUND_LOG_LEVEL=info
MUND_STORAGE=sqlite  # sqlite | memory | postgres

# Database (if using postgres)
MUND_DATABASE_URL=postgresql://user:pass@localhost/mund

# Notifications
MUND_SLACK_WEBHOOK=https://hooks.slack.com/...
MUND_TEAMS_WEBHOOK=https://outlook.office.com/webhook/...
MUND_EMAIL_SMTP_HOST=smtp.example.com
MUND_EMAIL_SMTP_PORT=587
MUND_EMAIL_FROM=mund@example.com

# Security
MUND_API_KEY=your-api-key
MUND_BLOCK_MODE=alert  # alert | block
```

### Rules Configuration (rules/default.yaml)
```yaml
version: "1.0"
name: "Default Security Rules"

secrets:
  - id: aws_access_key
    name: "AWS Access Key"
    pattern: 'AKIA[0-9A-Z]{16}'
    severity: critical
    action: alert
    
  - id: gemini_api_key
    name: "Gemini API Key"
    pattern: 'AIza[0-9A-Za-z_-]{35}'
    severity: critical
    action: alert

behaviors:
  - id: mass_deletion
    name: "Mass File Deletion"
    condition: "delete_count > 10 within 60s"
    severity: high
    action: block
    
policies:
  - id: no_external_urls
    name: "Block External URLs"
    type: url_allowlist
    allowed:
      - "*.example.com"
      - "api.openai.com"
      - "api.anthropic.com"
      - "generativelanguage.googleapis.com"
    action: block
```

## Usage Examples

### As MCP Server (stdio)
```json
// In claude_desktop_config.json
{
  "mcpServers": {
    "mund": {
      "command": "npx",
      "args": ["mund-mcp"],
      "env": {
        "MUND_SLACK_WEBHOOK": "https://hooks.slack.com/..."
      }
    }
  }
}
```

### As HTTP Server
```bash
# Start Mund as HTTP server
npx mund-mcp --transport http --port 3000

# Or with Docker
docker run -p 3000:3000 mund/mund-mcp
```

### Programmatic Usage
```typescript
import { MundClient } from 'mund-mcp';

const mund = new MundClient({
  notifications: {
    slack: { webhook: 'https://hooks.slack.com/...' }
  }
});

// Scan content before sending
const result = await mund.scanContent(suspiciousCode);
if (result.issues.length > 0) {
  console.log('Security issues found:', result.issues);
}
```

## Roadmap

### Phase 1 (MVP) - Current
- [x] Core analyzer engine
- [x] Secret detection (30+ patterns including Gemini/Google)
- [x] Basic rules engine
- [x] MCP server implementation
- [x] Slack notifications
- [x] CLI interface

### Phase 2
- [ ] PII detection
- [ ] Teams integration
- [ ] Email notifications
- [ ] SQLite persistence
- [ ] Web dashboard (basic)

### Phase 3
- [ ] Browser extensions
- [ ] Prompt injection detection
- [ ] Behavioral analysis
- [ ] PostgreSQL support
- [ ] Advanced dashboard

### Phase 4
- [ ] ML-based detection
- [ ] Custom model training
- [ ] Enterprise features
- [ ] SSO/SAML integration
- [ ] Audit logging

## Why "Mund"?

In Old English (Anglo-Saxon), **"Mund"** (pronounced like "moond") meant:
- **Protection**: The guardianship extended by a lord to those under their care
- **Guardian**: A protector, especially of family or property
- **The King's Peace**: The protection afforded to subjects

The word survives in modern English in:
- "Mundane" (originally "worldly protection")
- Related to Latin "mundus" (world, protection)

This Anglo-Saxon heritage connects to the values of protection, guardianship, and vigilance - perfect for a security protocol.

## Contributing

See CONTRIBUTING.md for guidelines on:
- Adding new detectors
- Creating notification integrations
- Writing custom rules
- Testing requirements

## License

MIT License - See LICENSE file
