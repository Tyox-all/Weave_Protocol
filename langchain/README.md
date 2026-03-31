# 🔗 @weave_protocol/langchain

[![npm version](https://img.shields.io/npm/v/@weave_protocol/langchain.svg)](https://www.npmjs.com/package/@weave_protocol/langchain)
[![npm downloads](https://img.shields.io/npm/dm/@weave_protocol/langchain.svg)](https://www.npmjs.com/package/@weave_protocol/langchain)

LangChain.js security integration for [Weave Protocol](https://github.com/Tyox-all/Weave_Protocol). Provides callback handlers, tool wrappers, and retriever guards to detect prompt injection, jailbreaks, data exfiltration, and other LLM security threats.

## Features

- **WeaveSecurityCallback** — Drop-in callback handler for any LangChain chain, agent, or LLM
- **Secure Tool Wrappers** — Wrap tools with input/output scanning and approval gates
- **Secure Retrievers** — Scan RAG documents for threats and PII
- **Built-in Patterns** — 15+ threat patterns including MITRE ATT&CK mappings
- **Remote Integration** — Optional connection to Mund for advanced threat intel

## Installation

```bash
npm install @weave_protocol/langchain @langchain/core
```

## Quick Start

### Basic Callback Handler

```typescript
import { ChatOpenAI } from '@langchain/openai';
import { WeaveSecurityCallback } from '@weave_protocol/langchain';

const llm = new ChatOpenAI();
const securityCallback = new WeaveSecurityCallback({
  action: 'block',           // 'block' | 'warn' | 'log' | 'passthrough'
  minSeverity: 'medium',     // 'low' | 'medium' | 'high' | 'critical'
  scanTarget: 'both',        // 'input' | 'output' | 'both'
});

// Use with any LangChain component
const response = await llm.invoke('Hello!', {
  callbacks: [securityCallback],
});

// Get security stats
console.log(securityCallback.getStats());
```

### With Chains

```typescript
import { LLMChain } from 'langchain/chains';
import { PromptTemplate } from '@langchain/core/prompts';
import { WeaveSecurityCallback } from '@weave_protocol/langchain';

const chain = new LLMChain({
  llm: new ChatOpenAI(),
  prompt: PromptTemplate.fromTemplate('Answer: {question}'),
  callbacks: [new WeaveSecurityCallback({ action: 'block' })],
});

// Threats in input or output will throw an error
await chain.invoke({ question: 'Ignore previous instructions...' });
// Error: [WeaveSecurityCallback] Blocked: Threat detected in chain input
```

### With Agents

```typescript
import { AgentExecutor, createReactAgent } from 'langchain/agents';
import { WeaveSecurityCallback, createHighRiskTool } from '@weave_protocol/langchain';

// Wrap dangerous tools with approval requirement
const secureTool = createHighRiskTool(
  shellTool,
  async (input, toolName) => {
    console.log(`Tool ${toolName} wants to execute: ${input}`);
    return await askUserForApproval();
  }
);

const agent = createReactAgent({ llm, tools: [secureTool] });
const executor = new AgentExecutor({
  agent,
  tools: [secureTool],
  callbacks: [new WeaveSecurityCallback({ action: 'block' })],
});
```

### Secure Retrievers (RAG Security)

```typescript
import { createSecureRetriever } from '@weave_protocol/langchain';
import { VectorStoreRetriever } from '@langchain/core/vectorstores';

const baseRetriever = vectorStore.asRetriever();

const secureRetriever = createSecureRetriever(baseRetriever, {
  name: 'company-docs',
  scanDocuments: true,
  redactSensitive: true,  // Automatically redact PII
  security: {
    action: 'warn',
    minSeverity: 'medium',
  },
  onThreat: (threats, doc) => {
    console.log(`Threat in document: ${doc.metadata.source}`);
  },
});

const docs = await secureRetriever.getRelevantDocuments('How do I reset my password?');
```

## Presets

```typescript
import {
  createStrictSecurityCallback,
  createWarningSecurityCallback,
  createProductionSecurityCallback,
} from '@weave_protocol/langchain';

// Strict: Blocks medium+ severity threats
const strict = createStrictSecurityCallback();

// Warning: Logs all threats but doesn't block
const warning = createWarningSecurityCallback();

// Production: Blocks high+ severity, optimized for prod
const production = createProductionSecurityCallback();
```

## Security Event Handling

```typescript
const callback = new WeaveSecurityCallback({
  action: 'warn',
  onSecurityEvent: async (event) => {
    if (event.threats.length > 0) {
      // Send to SIEM, log to file, alert on Slack, etc.
      await sendToSecurityDashboard({
        timestamp: event.timestamp,
        source: event.source,
        threats: event.threats.map(t => ({
          category: t.category,
          severity: t.severity,
          mitreId: t.mitreId,
        })),
      });
    }
  },
});
```

## Remote Mund Integration

Connect to a Mund instance for advanced threat intelligence:

```typescript
const callback = new WeaveSecurityCallback(
  { action: 'block' },
  {
    mundEndpoint: 'http://localhost:3000',
    mundApiKey: process.env.MUND_API_KEY,
  }
);
```

## Threat Categories

| Category | Description | MITRE ID |
|----------|-------------|----------|
| `prompt_injection` | Instruction override attempts | T1059 |
| `jailbreak` | DAN, developer mode exploits | T1548 |
| `data_exfiltration` | Markdown image attacks, URL injection | T1041 |
| `system_prompt_leak` | System prompt extraction | T1082 |
| `pii` | SSN, credit cards, emails | — |
| `secret` | API keys (OpenAI, Anthropic, AWS) | — |

## API Reference

### WeaveSecurityCallback

```typescript
new WeaveSecurityCallback(config?: SecurityConfig, options?: WeaveIntegrationOptions)
```

**SecurityConfig:**
- `action`: `'block' | 'warn' | 'log' | 'passthrough'`
- `scanTarget`: `'input' | 'output' | 'both'`
- `minSeverity`: `'low' | 'medium' | 'high' | 'critical'`
- `categories`: `string[]` — Filter to specific threat categories
- `scanTools`: `boolean` — Scan tool inputs/outputs
- `scanRetrievers`: `boolean` — Scan retriever queries/results
- `onSecurityEvent`: `(event: SecurityEvent) => void`

**Methods:**
- `getStats()`: Returns scan statistics
- `resetStats()`: Resets counters

### createSecureTool

```typescript
createSecureTool(tool: DynamicTool, options: SecureToolOptions): DynamicTool
```

### createSecureRetriever

```typescript
createSecureRetriever(retriever: BaseRetriever, options: SecureRetrieverOptions): SecureRetriever
```

## Part of Weave Protocol

This package is part of the Weave Protocol security suite:

| Package | Description |
|---------|-------------|
| [@weave_protocol/mund](https://www.npmjs.com/package/@weave_protocol/mund) | 🛡️ Threat detection & MCP server scanning |
| [@weave_protocol/hord](https://www.npmjs.com/package/@weave_protocol/hord) | 🏛️ Secure storage & context integrity |
| [@weave_protocol/domere](https://www.npmjs.com/package/@weave_protocol/domere) | ⚖️ Compliance (GDPR/CCPA) & audit trails |
| [@weave_protocol/hundredmen](https://www.npmjs.com/package/@weave_protocol/hundredmen) | 🔍 MCP call interception & drift detection |
| **@weave_protocol/langchain** | 🔗 LangChain.js integration |

## License

MIT © Trent Yoxall
