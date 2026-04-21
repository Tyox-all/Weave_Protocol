# 🔗 Weave Protocol - LlamaIndex Integration

[![PyPI version](https://badge.fury.io/py/weave-protocol-llamaindex.svg)](https://badge.fury.io/py/weave-protocol-llamaindex)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Security scanning and monitoring for LlamaIndex applications. Part of the [Weave Protocol](https://github.com/Tyox-all/Weave_Protocol) AI security suite.

## Features

- 🛡️ **Security Callback Handler** - Monitor all LlamaIndex events for threats
- 🔧 **Secure Tools** - Wrap FunctionTools with input/output scanning
- 📚 **Secure Retriever** - Scan and filter retrieved documents
- 🔍 **PII Detection & Redaction** - Automatically detect and redact sensitive data
- ⚡ **Local & Remote Scanning** - Use local patterns or connect to Weave Protocol API
- 🎯 **Configurable Severity** - Block, warn, or log based on threat severity

## Installation

```bash
pip install weave-protocol-llamaindex
```

For remote scanning support:
```bash
pip install weave-protocol-llamaindex[remote]
```

## Quick Start

### 1. Security Callback Handler

Monitor all LlamaIndex operations:

```python
from weave_protocol_llamaindex import WeaveSecurityHandler
from llama_index.core.callbacks import CallbackManager
from llama_index.core import Settings

# Create security handler
handler = WeaveSecurityHandler()

# Attach to LlamaIndex globally
Settings.callback_manager = CallbackManager([handler])

# All LlamaIndex operations are now monitored!
# Prompts, responses, embeddings, retrievals - everything is scanned
```

### 2. Secure Tools

Wrap your tools with security scanning:

```python
from weave_protocol_llamaindex import SecureFunctionTool

def search_database(query: str) -> str:
    """Search the company database."""
    # Your implementation
    return results

# Create secure version
secure_tool = SecureFunctionTool.from_defaults(
    fn=search_database,
    name="search_database",
    description="Search the company database"
)

# Use with an agent
from llama_index.core.agent import ReActAgent
agent = ReActAgent.from_tools([secure_tool])
```

### 3. Secure Retriever

Scan and filter retrieved documents:

```python
from weave_protocol_llamaindex import SecureRetriever
from llama_index.core import VectorStoreIndex

# Create your index
index = VectorStoreIndex.from_documents(documents)
base_retriever = index.as_retriever()

# Wrap with security
secure_retriever = SecureRetriever(
    retriever=base_retriever,
    filter_unsafe=True,   # Remove documents with high-severity threats
    redact_pii=True       # Redact PII from retrieved content
)

# Use in queries
query_engine = index.as_query_engine(retriever=secure_retriever)
```

## Configuration

### Security Config

```python
from weave_protocol_llamaindex import SecurityConfig, WeaveSecurityHandler

config = SecurityConfig(
    # What to block
    block_on_critical=True,
    block_on_high=True,
    block_on_medium=False,
    block_on_low=False,
    
    # What to scan
    scan_inputs=True,
    scan_outputs=True,
    scan_tool_calls=True,
    scan_retrieved_docs=True,
    
    # PII handling
    redact_pii=True,
    pii_types_to_redact=["email", "phone", "ssn", "credit_card"],
    
    # Callbacks
    on_threat_detected=lambda event: print(f"Threat: {event}"),
)

handler = WeaveSecurityHandler(config=config)
```

### Preset Handlers

```python
from weave_protocol_llamaindex import (
    create_strict_handler,      # Blocks medium+ severity
    create_warning_handler,     # Only logs, never blocks
    create_production_handler,  # Blocks high+ severity
)

# For development - see all threats
handler = create_warning_handler()

# For production - block dangerous content
handler = create_production_handler()
```

### Custom Scanner

Use remote Weave Protocol API for advanced scanning:

```python
from weave_protocol_llamaindex import RemoteScanner, WeaveSecurityHandler

scanner = RemoteScanner(
    api_url="https://api.weaveprotocol.dev",
    api_key="your-api-key"
)

handler = WeaveSecurityHandler(scanner=scanner)
```

## Threat Detection

The scanner detects:

| Category | Threats |
|----------|---------|
| **Injection** | Prompt injection, jailbreak attempts, role override |
| **PII** | Emails, phone numbers, SSN, credit cards |
| **Secrets** | API keys, AWS keys, private keys, passwords |
| **Code Injection** | SQL injection, command injection, path traversal |

### Adding Custom Patterns

```python
from weave_protocol_llamaindex import LocalScanner, PatternDefinition, ThreatType, Severity

custom_pattern = PatternDefinition(
    name="internal_id",
    pattern=r"INTERNAL-[A-Z]{3}-\d{6}",
    threat_type=ThreatType.PII_EXPOSURE,
    severity=Severity.MEDIUM,
    description="Internal ID detected"
)

scanner = LocalScanner(additional_patterns=[custom_pattern])
```

## Handling Security Events

```python
from weave_protocol_llamaindex import (
    WeaveSecurityHandler,
    SecurityBlockError,
    SecurityConfig
)

def on_threat(event):
    # Log to your security system
    log_security_event(
        threat_type=event.scan_result.findings[0].threat_type,
        severity=event.scan_result.findings[0].severity,
        content_preview=event.content_preview,
    )

config = SecurityConfig(on_threat_detected=on_threat)
handler = WeaveSecurityHandler(config=config)

# Handle blocked content
try:
    response = query_engine.query("malicious query...")
except SecurityBlockError as e:
    print(f"Blocked: {e.result.findings[0].description}")
```

## Statistics

```python
# Get security stats
stats = handler.get_stats()
print(f"Total scans: {stats['total_scans']}")
print(f"Blocked: {stats['blocked_count']}")
print(f"Threats by type: {stats['threats_by_type']}")

# Get recent threats
threats = handler.get_recent_threats(limit=10)
for threat in threats:
    print(f"{threat.severity}: {threat.description}")
```

## Integration with Weave Protocol

This package is part of the Weave Protocol suite:

| Package | Purpose |
|---------|---------|
| **🛡️ Mund** | Threat scanning, authentication |
| **🏛️ Hord** | Secure storage, context integrity |
| **⚖️ Domere** | Compliance (GDPR, CCPA, SOC2) |
| **👥 Witan** | Consensus and governance |
| **🔍 Hundredmen** | MCP security inspection |

## Requirements

- Python >= 3.9
- llama-index-core >= 0.10.0
- httpx >= 0.24 (for remote scanning)

## License

Apache 2.0 - See [LICENSE](LICENSE)

## Links

- [GitHub](https://github.com/Tyox-all/Weave_Protocol)
- [npm packages](https://www.npmjs.com/org/weave_protocol)
- [Documentation](https://github.com/Tyox-all/Weave_Protocol/tree/main/llamaindex-py)
