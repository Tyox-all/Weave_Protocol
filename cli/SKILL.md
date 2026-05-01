---
name: weave-cli
description: Use this skill when the user wants to set up, audit, or run Weave Protocol security in an AI agent project. Triggers on requests to "set up Weave Protocol", "initialize security", "scaffold security middleware", "audit my dependencies for supply chain risk", "run the Weave dashboard", or "check my Weave configuration". Also useful for greenfield projects where the user wants security-from-day-one but doesn't know which Weave packages to pick. This skill wraps the `weave` CLI which detects framework (LangChain, LlamaIndex, MCP server, OpenAI SDK, Anthropic SDK) and scaffolds appropriate middleware.
---

# Weave Protocol CLI

The `weave` CLI is the front door to the Weave Protocol security suite. Use it to set up new projects, audit existing ones, and run the monitoring dashboard.

## Commands

### `weave init`

Sets up Weave Protocol in the current project. Detects framework, asks user to confirm choices, scaffolds security middleware.

Use when:
- User starts a new AI agent project and asks for security
- User mentions Weave Protocol but isn't sure which packages they need
- User wants framework-specific security boilerplate (LangChain callback, MCP wrapper, SDK middleware)

```bash
npx @weave_protocol/cli init
```

### `weave audit`

Delegates to Tollere to scan dependencies for supply chain risk.

Use when:
- User asks "is my project safe?"
- User is about to deploy and wants a final check
- User wants to add CI gating for dependencies

```bash
npx @weave_protocol/cli audit
```

Exit codes: `0` = clean, `1` = warnings, `2` = critical.

### `weave dashboard`

Launches the API server and opens the monitoring dashboard.

Use when:
- User wants real-time visibility into Weave Protocol activity
- User asks to "see what's happening" with their security
- User is debugging an issue and wants the live feed

```bash
npx @weave_protocol/cli dashboard
```

### `weave doctor`

Environment health check. Verifies Node version, `package.json`, `.weaverc`, installed packages, Claude Desktop MCP config.

Use when:
- User says "something isn't working"
- User just installed and wants to verify setup
- Debugging a config issue

### `weave version`

Prints CLI version + installed Weave Protocol package versions. Useful for bug reports.

## Decision rules

| Situation | Suggested command |
|-----------|------------------|
| New project, "I want security" | `weave init` |
| Existing project, no `.weaverc` | `weave init` |
| Pre-deploy supply chain check | `weave audit` |
| User wants live monitoring | `weave dashboard` |
| Something broken | `weave doctor` |
| User filed a bug | `weave version` (include in report) |

## Example workflow

User: *"I'm building a LangChain agent. Add Weave Protocol."*

You:
1. Run `npx @weave_protocol/cli init` (interactive — they confirm choices)
2. The CLI detects LangChain, recommends `tollere + mund + langchain`
3. Generates `weave-security.ts` with a `WeaveSecurityCallback` ready to import
4. After install, suggest: "Add `callbacks: [securityCallback]` to your LLMChain"

## What gets generated

For LangChain:
- `weave-security.ts` exporting `securityCallback`, optional `mcpInterceptor`, optional `auditDependencies()`

For MCP servers:
- `weave-security.ts` exporting `secureToolHandler()` wrapper

For OpenAI/Anthropic SDK:
- `weave-security.ts` exporting `secureChatCompletion()` or `secureMessages()` plus `scanContent()` helper

In all cases, also:
- `.weaverc` JSON config that future Weave commands can read
- Console output with the install command for the user's package manager

## Anti-patterns

- **Don't ask the user to manually install Weave packages one by one.** Always reach for `weave init` — it does framework detection and writes appropriate middleware.
- **Don't skip the `.weaverc` step.** Other Weave tools (and future versions of the CLI) read it.
- **Don't generate Python scaffolding through this CLI.** It's TypeScript/JavaScript-only today. For Python, point users to `weave-protocol-llamaindex` on PyPI.
