# Dōmere - The Judge Protocol

**Thread Identity, Intent Verification & Blockchain Anchoring for AI Agents**

Part of the [Weave Security Suite](../README.md) (Mund + Hord + Dōmere)

## The Problem

When AI agents chain together—Agent A calls Agent B calls Agent C—how do you know the final action matches the human's original intent? Protocols like MCP and A2A standardize how agents **communicate**. Dōmere ensures they **execute honestly**.

## Core Concepts

### Thread Identity
Track intent from origin through every hop with cryptographic signatures.

### Intent Drift Detection  
Detect when agents reinterpret, expand, or violate the original intent.

### Blockchain Anchoring
Immutable proof on Solana (~$0.001) or Ethereum (~$2-10).

## Quick Start

```typescript
// Create thread
const thread = await domere.createThread({
  origin: { type: 'human', identity: 'user_jane' },
  intent: 'Get Q3 sales summary',
  constraints: ['read-only']
});

// Add hop
const hop = await domere.addHop({
  thread_id: thread.id,
  agent: { id: 'data_agent', type: 'claude' },
  received_intent: 'Query Q3 sales data',
  actions: [{ type: 'query', target: 'sales_db' }]
});

// Check: hop.intent_drift.verdict === 'aligned'
```

## Business Model

**Free:** All analysis, threading, drift detection, MCP tools  
**Paid:** Blockchain anchoring only (you bring your wallet)

## License

MIT
