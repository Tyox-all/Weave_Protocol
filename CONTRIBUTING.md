# Contributing to Weave Protocol

Thanks for your interest in contributing to the Weave Protocol Security Suite! 

## How to Contribute

### Reporting Bugs

1. Check existing [Issues](https://github.com/Tyox-all/Weave_Protocol/issues) to avoid duplicates
2. Create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Package name and version (`@weave_protocol/domere@1.2.1`)

### Suggesting Features

Open an issue with the `enhancement` label describing:
- The problem you're trying to solve
- Your proposed solution
- Which package it affects (Mund, Hord, Dōmere, Witan, API)

### Pull Requests

1. **Fork** the repository
2. **Clone** your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Weave_Protocol.git
   cd Weave_Protocol
   ```
3. **Create a branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```
4. **Make your changes** in the appropriate package directory
5. **Build and test**:
   ```bash
   cd domere  # or mund, hord, witan, api
   npm install
   npm run build
   ```
6. **Commit** with a clear message:
   ```bash
   git commit -m "Add: description of your change"
   ```
7. **Push** to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```
8. **Open a Pull Request** against `main`

### Commit Message Format

- `Add:` New feature
- `Fix:` Bug fix
- `Update:` Updating existing functionality
- `Docs:` Documentation only
- `Refactor:` Code restructuring

### Code Style

- TypeScript with strict mode
- Use meaningful variable names
- Add JSDoc comments for public APIs
- Keep functions focused and small

## Package Structure

```
Weave_Protocol/
├── mund/       # Guardian Protocol - Threat scanning
├── hord/       # Vault Protocol - Secure storage
├── domere/     # Judge Protocol - Orchestration & compliance
├── witan/      # Council Protocol - Consensus & governance
└── api/        # REST API
```

## Questions?

Open an issue with the `question` label.

---

Thanks for helping make AI agents safer! 🛡️
