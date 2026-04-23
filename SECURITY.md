# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in any Weave Protocol package, **please do not open a public GitHub issue**.

Instead, email:

📧 **TYox-all@tutamail.com**

Please include:
- Which package is affected and at what version
- A description of the vulnerability and its potential impact
- Steps to reproduce (or a proof-of-concept if you have one)
- Whether you've shared this with anyone else
- Whether you'd like credit if a CVE is published

We aim to acknowledge receipt within **48 hours** and provide an initial assessment within **7 days**. Critical vulnerabilities affecting published packages will be patched and released within **30 days** under coordinated disclosure.

## Supported versions

Only the latest minor version of each package receives security updates. As of April 2026:

| Package | Supported version |
|---------|-------------------|
| `@weave_protocol/mund` | 0.2.x |
| `@weave_protocol/hord` | 0.1.x |
| `@weave_protocol/domere` | 1.3.x |
| `@weave_protocol/witan` | 1.0.x |
| `@weave_protocol/hundredmen` | 1.0.x |
| `@weave_protocol/tollere` | 0.2.x |
| `@weave_protocol/langchain` | 1.0.x |
| `@weave_protocol/api` | 1.0.x |
| `weave-protocol-llamaindex` | 0.1.x |

## Scope

Vulnerabilities in scope:

- Bypasses of any security control (e.g., scanner evasion in Mund, integrity bypass in Hord, gate bypass in Hundredmen)
- Cryptographic weaknesses in Hord (Yoxallismus, AES, Argon2 implementation)
- Supply chain attack vectors that Tollere fails to detect
- Privilege escalation in any package
- Sensitive data exposure (logs, error messages, stack traces)
- Authentication or authorization issues in the API package

Out of scope:

- Issues in dependencies (please report upstream and notify us so we can pin)
- Theoretical attacks without a working proof-of-concept
- Issues requiring physical access to the developer's machine
- Self-XSS that requires the user to paste attacker-controlled content into their own browser console

## Security architecture

For background on the defense-in-depth model and how the packages interact, see the [Security Model section in README.md](./README.md#-security-model).

## Dependency security

Tollere itself is the canonical answer for "is this package safe to install?" For the Weave Protocol monorepo's own dependencies:

- All published packages use **npm provenance** (Sigstore / OIDC)
- The publish pipeline runs through GitHub Actions trusted publishing — **no long-lived npm tokens**
- Dependency updates are reviewed before merge

## Hall of Fame

Researchers who responsibly disclose vulnerabilities will be credited here (with permission) once fixes are released.
