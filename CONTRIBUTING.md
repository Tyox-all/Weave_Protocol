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

## Why we test everything, on every commit

The packages depend on each other. `api` and `full` use Mund, and Ward is used by Hundredmen, the browser guard and all seven adapters. Each package's own CI job installs its Weave dependencies from npm. So it tests what's already published, not the change in front of it.

That gap shipped a real bug. Mund 0.6.0 added a classifier finding that returned the text it scored as its `match`, and that text could contain secrets and email addresses. They reached logs, Mund's event store and notification webhooks unmasked. Mund's own tests checked what the classifier detected, not what it output. `api` already had a test asserting that scan results never contain a secret, and it would have failed. But `api` was only tested against Mund 0.6.0 after 0.6.0 was on npm. The fix shipped as 0.6.1, and 0.6.0 is deprecated.

So, for every package:
- **Test what it outputs, not just what it detects.** A new kind of finding needs a test that it never echoes secrets or personal data (see `mund/tests/analyzers/redaction.test.ts`).
- **Test its dependents against the change.** On every push and pull request, the [Dependents](.github/workflows/dependents.yml) workflow builds each changed package. It then runs the tests of every package that depends on it, directly or through another Weave package, against that build. It checks that every copy in the dependent's tree is the local build, so a pass can't come from the npm version.

Run it yourself before you open a PR:

```bash
node scripts/test-dependents.mjs --base=origin/main     # packages changed on your branch
node scripts/test-dependents.mjs --changed=mund,ward    # or name them
```

It edits each dependent's `package.json` and lockfile while it runs, and restores both afterwards. Run `npm ci` in a dependent to get its `node_modules` back to the lockfile.

## Code of conduct

Be kind, be technical, be honest. Harassment of any kind is not tolerated.

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
