# Dōmere: The Judge Protocol

## Executive Summary

**Dōmere** (Old English for "judge, arbiter") is the verification and anchoring layer for AI agent security. While Mund watches and Hord contains, Dōmere verifies the weave of intent through agent chains and anchors proof immutably to blockchain.

## Core Philosophy: Weave-First Security

Traditional identity systems ask "who is this agent?" - a point-in-time question.

Dōmere asks "what is the thread of intent, how does it weave through agents, and does that pattern comply?" - a continuous verification question.

**The weave matters more than the identity.**

## Core Concepts

### Thread Identity

A thread represents the complete lifecycle of a human intent as it propagates through multiple AI agents:

```
Human Intent → Agent A → Agent B → Agent C → Result
     ↓            ↓          ↓          ↓        ↓
  [origin]    [hop 1]    [hop 2]    [hop 3]  [complete]
     └────────────────────┬────────────────────┘
                    Thread Identity
```

Each thread has:
- **Origin**: Where did this start? (human, system, scheduled)
- **Intent**: What was requested? What constraints apply?
- **Hops**: Each agent interaction with full context
- **Weave Signature**: Rolling cryptographic proof of the entire chain

### Intent Drift

As intent passes through agents, it can "drift" - each agent may reinterpret slightly. Dōmere detects when drift exceeds acceptable bounds:

- Semantic similarity (embedding comparison)
- Action alignment (are actions consistent with original intent)
- Scope creep (has scope expanded beyond original request)
- Constraint violations (explicit constraints broken)

### Language Analysis

Understanding what agents are processing is critical:

- **Language Detection**: Is this English? Python? SQL? JSON?
- **Semantic Analysis**: What does this content mean? What entities are referenced?
- **Code Analysis**: What does this code do? Is it dangerous?
- **NL Analysis**: Is there manipulation? Hidden instructions?

### Blockchain Anchoring

Local proofs are useful but can be modified. Blockchain anchoring provides:

- **Immutability**: Cannot be changed by anyone
- **Third-party Verification**: Anyone can verify
- **Legal Standing**: Timestamped, cryptographic proof
- **Audit Trail**: Permanent record

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DŌMERE                                         │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         THREAD MANAGER                               │   │
│  │                                                                       │   │
│  │  • Create/manage thread lifecycle                                    │   │
│  │  • Track hops through agent chain                                    │   │
│  │  • Compute weave signatures                                          │   │
│  │  • Detect intent drift                                               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│         ┌──────────────────────────┼──────────────────────────┐            │
│         ▼                          ▼                          ▼            │
│  ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐    │
│  │    LANGUAGE     │      │   COMPLIANCE    │      │   ARBITRATION   │    │
│  │    ANALYZER     │      │     ENGINE      │      │     ENGINE      │    │
│  │                 │      │                 │      │                 │    │
│  │ • Detection     │      │ • Policy eval   │      │ • Case mgmt     │    │
│  │ • Semantics     │      │ • ZK proofs     │      │ • Resolution    │    │
│  │ • Code analysis │      │ • Violations    │      │ • Precedent     │    │
│  │ • NL analysis   │      │                 │      │                 │    │
│  └─────────────────┘      └─────────────────┘      └─────────────────┘    │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       ANCHORING CLIENT                               │   │
│  │                                                                       │   │
│  │  • Solana (real-time, cheap)                                         │   │
│  │  • Ethereum (settlement, authoritative)                              │   │
│  │  • Merkle tree generation                                            │   │
│  │  • Verification                                                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## MCP Tools

### Thread Management
| Tool | Description |
|------|-------------|
| `domere_create_thread` | Initialize thread from human intent |
| `domere_add_hop` | Record agent hop in thread |
| `domere_verify_thread` | Verify thread integrity |
| `domere_get_thread` | Retrieve thread details |
| `domere_close_thread` | Mark thread complete |
| `domere_list_threads` | List active/recent threads |

### Language Analysis
| Tool | Description |
|------|-------------|
| `domere_detect_language` | Detect language/code type |
| `domere_analyze_content` | Full semantic analysis |
| `domere_analyze_code` | Code-specific analysis |
| `domere_check_injection` | Detect prompt injection |
| `domere_extract_entities` | Extract entities from content |

### Intent & Drift
| Tool | Description |
|------|-------------|
| `domere_analyze_intent` | Deep analysis of stated intent |
| `domere_check_drift` | Check intent drift at current hop |
| `domere_compare_intents` | Compare two intent statements |

### Compliance
| Tool | Description |
|------|-------------|
| `domere_check_policy` | Check thread against policy |
| `domere_generate_proof` | Generate compliance proof |
| `domere_list_violations` | List policy violations |

### Anchoring
| Tool | Description |
|------|-------------|
| `domere_anchor_solana` | Anchor to Solana |
| `domere_anchor_ethereum` | Anchor to Ethereum |
| `domere_verify_anchor` | Verify on-chain anchor |
| `domere_get_anchor_status` | Check anchoring status |

### Arbitration
| Tool | Description |
|------|-------------|
| `domere_open_dispute` | Open arbitration case |
| `domere_submit_evidence` | Add evidence to case |
| `domere_resolve_dispute` | Resolve dispute |

## Pricing Model

### Free (100% Open Source)
- All language analysis
- All thread management
- All compliance checking
- All proof generation
- All MCP tools
- All local operations

### Paid (Blockchain Network Fees + Protocol Fee)
- Solana anchoring: ~$0.001 per anchor
- Ethereum anchoring: ~$2-10 per anchor
- Protocol fee: 5% of gas cost

## Technology Stack

- **Runtime**: Node.js 20+
- **Language**: TypeScript
- **Protocol**: MCP (Model Context Protocol)
- **Blockchain**: Solana (Anchor framework), Ethereum (Solidity)
- **Crypto**: Native Node.js crypto, ethers.js, @solana/web3.js

## Directory Structure

```
domere/
├── src/
│   ├── index.ts              # MCP server entry
│   ├── types.ts              # Type definitions
│   ├── constants.ts          # Configuration
│   │
│   ├── thread/               # Thread identity
│   │   ├── index.ts
│   │   ├── manager.ts
│   │   ├── intent.ts
│   │   ├── drift.ts
│   │   └── weave.ts
│   │
│   ├── language/             # Language analysis
│   │   ├── index.ts
│   │   ├── detector.ts
│   │   ├── semantic.ts
│   │   ├── code-analyzer.ts
│   │   └── nl-analyzer.ts
│   │
│   ├── compliance/           # Compliance engine
│   │   ├── index.ts
│   │   ├── engine.ts
│   │   ├── proof.ts
│   │   └── policies/
│   │
│   ├── arbitration/          # Arbitration
│   │   ├── index.ts
│   │   ├── case-manager.ts
│   │   └── resolution.ts
│   │
│   ├── anchoring/            # Blockchain
│   │   ├── index.ts
│   │   ├── merkle.ts
│   │   ├── solana.ts
│   │   └── ethereum.ts
│   │
│   ├── tools/                # MCP tools
│   │   └── index.ts
│   │
│   └── storage/              # Persistence
│       ├── index.ts
│       └── memory.ts
│
├── package.json
├── tsconfig.json
└── README.md
```

## License

MIT - Free to use, modify, distribute. Forever.

Blockchain anchoring uses deployed contracts with protocol fees that fund development.
