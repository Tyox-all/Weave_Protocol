---
name: langchain-security
description: Integrating Weave Protocol security into LangChain.js applications. Use when building secure LangChain chains, agents, or RAG pipelines with threat detection, prompt injection protection, or PII redaction.
---

# LangChain Security Integration

Add security scanning to LangChain.js applications using Weave Protocol.

## When to Use

- Building LangChain chains or agents that handle untrusted input
- Implementing RAG pipelines that need document scanning
- Protecting against prompt injection in production LLM apps
- Adding approval gates for dangerous tool operations
- Redacting PII from retrieved documents

## Installation

```bash
npm install @weave_protocol/langchain @langchain/core
```

## Core Patterns

### 1. Callback Handler (Recommended)

```typescript
import { WeaveSecurityCallback } from '@weave_protocol/langchain';

const callback = new WeaveSecurityCallback({
  action: 'block',        // block | warn | log
  minSeverity: 'medium',  // low | medium | high | critical
});

// Works with any LangChain component
const chain = new LLMChain({
  llm,
  prompt,
  callbacks: [callback],
});
```

### 2. Secure Tools

```typescript
import { createSecureTool, createHighRiskTool } from '@weave_protocol/langchain';

// Basic security scanning
const secureTool = createSecureTool(myTool, {
  name: 'my-tool',
  security: { action: 'block' },
});

// Require user approval
const approvedTool = createHighRiskTool(dangerousTool, async (input) => {
  return await askUser(`Execute: ${input}?`);
});
```

### 3. Secure Retrievers

```typescript
import { createSecureRetriever } from '@weave_protocol/langchain';

const secureRetriever = createSecureRetriever(vectorStore.asRetriever(), {
  name: 'docs',
  scanDocuments: true,
  redactSensitive: true,  // Auto-redact PII
});
```

## Presets

```typescript
import {
  createStrictSecurityCallback,    // Blocks medium+
  createWarningSecurityCallback,   // Logs only
  createProductionSecurityCallback // Blocks high+
} from '@weave_protocol/langchain';
```

## Event Handling

```typescript
new WeaveSecurityCallback({
  onSecurityEvent: (event) => {
    if (event.threats.length > 0) {
      logger.warn('Threat detected', {
        category: event.threats[0].category,
        mitreId: event.threats[0].mitreId,
      });
    }
  },
});
```

## Threat Categories

- `prompt_injection` — Instruction override (T1059)
- `jailbreak` — DAN, developer mode (T1548)
- `data_exfiltration` — Markdown attacks (T1041)
- `system_prompt_leak` — Prompt extraction (T1082)
- `pii` — SSN, credit cards, emails
- `secret` — API keys

## Remote Mund Connection

```typescript
new WeaveSecurityCallback(
  { action: 'block' },
  { mundEndpoint: 'http://localhost:3000' }
);
```
