# Contributing to Weave Protocol

Thank you for your interest in Weave Protocol. This is an enterprise security suite for AI agents, and we take contributions seriously.

## How to contribute

### 🐛 Bug reports

Please file all bug reports through [GitHub Issues](https://github.com/Tyox-all/Weave_Protocol/issues).

When filing a bug, include:
- Which package(s) are affected (e.g., `@weave_protocol/tollere`)
- Version number
- Minimal reproduction steps
- Expected vs actual behavior
- Environment details (Node.js version, OS, etc.)

### 💡 Feature requests

Open a [GitHub Issue](https://github.com/Tyox-all/Weave_Protocol/issues) with the `enhancement` label and describe:
- The problem you're trying to solve
- Why existing tools don't address it
- A sketch of the proposed API or behavior

Before opening a feature request for a new package, check the [Roadmap](./README.md#-roadmap) to see if it's already planned.

### 🔒 Security issues

**Do not file security issues publicly.** See [SECURITY.md](./SECURITY.md) for our responsible disclosure process.

### 📬 Other inquiries

For partnership, integration, licensing, or anything else not covered above:

📧 **TYox-all@tutamail.com**

## Pull requests

At this stage of the project, **we are not accepting unsolicited pull requests**. The codebase is evolving quickly and architectural decisions are being made centrally to keep the security model coherent.

If you have a fix you believe is critical, please open an issue first describing what you'd change and why. If we agree it should land, we'll invite a PR.

## Development setup

```bash
git clone https://github.com/Tyox-all/Weave_Protocol.git
cd Weave_Protocol

# Each package is independent
cd <package>
npm install
npm run build
npm test
```

## Code of conduct

Be kind, be technical, be honest. Harassment of any kind is not tolerated.

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
