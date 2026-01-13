# Contributing to Mund

Thank you for your interest in contributing to Mund! This document provides guidelines and information for contributors.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## How to Contribute

### Reporting Bugs

Before creating a bug report, please check existing issues to avoid duplicates. When creating a bug report, include:

- A clear, descriptive title
- Steps to reproduce the issue
- Expected behavior vs actual behavior
- Your environment (OS, Node.js version, etc.)
- Any relevant logs or error messages

### Suggesting Features

Feature suggestions are welcome! Please include:

- A clear description of the feature
- The problem it solves or use case it addresses
- Any implementation ideas you have

### Pull Requests

1. Fork the repository and create your branch from `main`
2. Install dependencies: `npm install`
3. Make your changes
4. Add or update tests as needed
5. Ensure all tests pass: `npm test`
6. Ensure the build succeeds: `npm run build`
7. Update documentation if needed
8. Submit a pull request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/mund-mcp.git
cd mund-mcp

# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Run in development mode
npm run dev
```

## Project Structure

```
src/
├── index.ts              # Main entry point
├── types.ts              # TypeScript interfaces
├── constants.ts          # Default rules and configuration
├── analyzers/            # Security analyzers
├── notifications/        # Notification integrations
├── storage/              # Event storage implementations
└── tools/                # MCP tool implementations
```

## Adding New Detection Rules

### Adding a Secret Pattern

1. Add the pattern to `src/constants.ts` in the `SECRET_PATTERNS` array:

```typescript
{
  id: 'my_service_api_key',
  name: 'My Service API Key',
  description: 'API key for My Service',
  type: DetectorType.SECRET,
  pattern: 'my_[a-zA-Z0-9]{32}',
  severity: Severity.CRITICAL,
  action: ActionType.ALERT,
  enabled: true
}
```

2. Test your pattern with various inputs
3. Add tests in `tests/analyzers/`

### Adding a New Analyzer

1. Create a new file in `src/analyzers/`
2. Implement the `IAnalyzer` interface
3. Export from `src/analyzers/index.ts`
4. Add tests

```typescript
import { IAnalyzer, DetectorType, SecurityIssue, DetectionRule } from '../types.js';

export class MyAnalyzer implements IAnalyzer {
  name = 'MyAnalyzer';
  type = DetectorType.MY_TYPE;

  async analyze(content: string, rules: DetectionRule[]): Promise<SecurityIssue[]> {
    // Implementation
  }
}
```

### Adding a Notification Channel

1. Create a new file in `src/notifications/`
2. Implement the `INotifier` interface
3. Export from `src/notifications/index.ts`
4. Add configuration options to `types.ts` and `index.ts`

## Code Style

- Use TypeScript strict mode
- Follow existing code patterns
- Use meaningful variable and function names
- Add JSDoc comments for public APIs
- Keep functions focused and small

## Testing

- Write tests for new features
- Ensure existing tests pass
- Test edge cases and error conditions
- Test with realistic inputs

## Documentation

- Update README.md for user-facing changes
- Add JSDoc comments to new functions
- Update PLANNING.md for architectural changes
- Include examples in documentation

## Commit Messages

Use clear, descriptive commit messages:

```
feat: add detection for Azure storage keys
fix: correct false positive in JWT detection
docs: update installation instructions
test: add tests for PII detector
refactor: simplify notification hub logic
```

## Review Process

1. All changes require a pull request
2. PRs need at least one approval
3. CI checks must pass
4. Documentation must be updated

## Security Issues

**Do not open public issues for security vulnerabilities.**

Please email security@example.com with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes

## Questions?

Feel free to open a discussion or reach out to maintainers.

Thank you for contributing to Mund! 🛡️
