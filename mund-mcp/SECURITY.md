# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take the security of Mund seriously. If you have discovered a security vulnerability, please follow these steps:

### DO NOT

- Open a public GitHub issue
- Disclose the vulnerability publicly before it's fixed
- Exploit the vulnerability beyond what's necessary to demonstrate it

### DO

1. **Email us directly** at security@example.com with:
   - A description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Any suggested fixes (optional)

2. **Expect a response** within 48 hours acknowledging receipt

3. **Work with us** to understand and address the issue

### What to Expect

1. **Acknowledgment**: We'll acknowledge your report within 48 hours
2. **Assessment**: We'll investigate and assess the severity
3. **Fix Development**: We'll develop a fix if the issue is confirmed
4. **Disclosure**: We'll coordinate with you on public disclosure timing
5. **Credit**: We'll credit you in our security advisories (unless you prefer anonymity)

### Scope

The following are in scope for security reports:

- Mund MCP server
- Detection rule bypass methods
- Notification system vulnerabilities
- Storage system vulnerabilities
- Authentication/authorization issues

The following are out of scope:

- Third-party dependencies (report to upstream)
- Social engineering attacks
- Physical attacks
- Denial of service attacks

## Security Best Practices for Users

### Deployment

1. **Use environment variables** for sensitive configuration
2. **Restrict network access** to the Mund server
3. **Enable block mode** for production environments with critical data
4. **Monitor alerts** and respond promptly

### Configuration

1. **Use strong API keys** if authentication is enabled
2. **Configure minimum severity** for notifications appropriately
3. **Review custom rules** before deployment
4. **Keep Mund updated** to the latest version

### Integration

1. **Validate inputs** before passing to Mund
2. **Handle blocked content** appropriately
3. **Log all security events** for audit purposes
4. **Test your integration** thoroughly

## Vulnerability Response Process

1. Security team receives and acknowledges report
2. Issue is investigated and severity assessed
3. Fix is developed and tested
4. Security advisory is prepared
5. Fix is released
6. Advisory is published
7. Reporter is credited

## Security Updates

Security updates are released as patch versions and announced via:

- GitHub Security Advisories
- Release notes
- Email to registered users (if applicable)

Always update to the latest patch version promptly.

## Contact

- Security issues: security@example.com
- General questions: Open a GitHub discussion

Thank you for helping keep Mund secure! 🛡️
