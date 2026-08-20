# Security Policy — @weave_protocol/yoxallismus

## Reporting a vulnerability

**Do not open a public GitHub issue for security reports.**

Send security reports to: **<TYox-all@tutamail.com>**

Include:
1. Version affected (start of subject line: `[YOXALL SECURITY vX.Y.Z]`)
2. Vulnerability class (cryptographic, implementation, side-channel, supply-chain, other)
3. Reproducer — ideally a runnable test case
4. Impact assessment — what an attacker can achieve
5. Suggested fix (optional)

Expect an acknowledgement within 72 hours. Response times vary — this is a solo-maintained beta.

---

## Responsible disclosure program

**Status:** Active as of v0.1.0-beta.0

This library is deliberately unaudited. Community verification is the only safety net. We commit to fast triage, coordinated disclosure, and public recognition of researchers who report responsibly.

### What reporters receive

- **Acknowledgement in the advisory** — every fixed vulnerability publishes an entry in [SECURITY_ADVISORIES.md](SECURITY_ADVISORIES.md) crediting the reporter (with permission, or anonymously by request)
- **CVE assignment** where warranted, via GitHub Security Advisories
- **Coordinated disclosure timeline** — reporter and maintainer agree on publication timing
- **A direct communication channel** with the maintainer, not a support queue
- **First-report priority** — if two people report the same issue, the earlier report gets credited

There is no monetary bounty program at this time. If that changes, this document will be updated with the terms.

### Scope

**In scope:**
- Any file in the `@weave_protocol/yoxallismus` npm package
- Wire-format ambiguity or parsing vulnerabilities
- Composition flaws in the PQ-hybrid KEM
- Ratchet state confusion, chain-key reuse, message-key derivation errors
- KDF misuse, HKDF domain-separation errors
- AEAD misuse, nonce-reuse patterns
- Documentation claims that don't match code behavior

**Out of scope:**
- Vulnerabilities in `@noble/post-quantum` (report to that project directly)
- Vulnerabilities in Node.js crypto module (report to Node)
- Attacks requiring endpoint compromise, physical access, or side channels
- Attacks on the theoretical strength of ML-KEM-768 or X25519 that assume advances not currently known (report as research, not as vulnerability)
- Regulatory-compliance findings (this library is explicitly not compliance-ready)
- Any behavior explicitly noted in THREAT_MODEL.md as out of scope

### Severity classification

Every accepted report is classified for the public advisory:

| Severity | Definition |
|---|---|
| **Critical** | Confidentiality break — attacker recovers plaintext or key material without holding the private key |
| **High** | Integrity break — attacker forges valid ciphertexts, or bypasses AEAD authentication |
| **Medium** | Denial-of-service, algorithm confusion, wire-format ambiguity that could enable attacks |
| **Low** | Documentation errors that could mislead users into insecure usage |

### Rules of engagement

1. **No public disclosure** before a fix is released (or 90 days from acknowledgment, whichever is sooner)
2. **No attacks on users' data** — only against your own test infrastructure
3. **No social engineering** or attacks on the maintainer's accounts
4. **One vulnerability per report** — chained vulnerabilities credited as the highest-severity link

---

## Disclosure process

1. Report received → acknowledgment within 72 hours
2. Triage → severity assignment within 7 days
3. Fix development → target 30 days for high/critical; 90 days for medium/low
4. Coordinated disclosure — reporter and maintainer agree on public advisory timing
5. Fix released with corresponding entry in SECURITY_ADVISORIES.md
6. CVE assignment via GitHub Security Advisories, where warranted

---

## What we won't do

- **We won't sue researchers who follow this policy in good faith.** Reports made in good faith under this policy are considered authorized testing under DMCA § 1201(j) and CFAA safe harbors.
- **We won't retaliate** against reporters, even for reports we ultimately reject.
- **We won't gag researchers** after 90 days from acknowledgment. Coordinated disclosure is a request, not a permanent obligation.

---

## Cryptographic questions that are NOT security reports

If you have questions about:
- Algorithm choices (Why ML-KEM-768 not 1024?)
- Wire format decisions (Why JSON not CBOR?)
- Missing features (When is threshold coming?)
- Design tradeoffs

...open a regular GitHub discussion or issue. These aren't security-sensitive and belong in public conversation.

---

## Beta software reminder

This is beta. It is NOT audited. Reports about *its beta status* are not vulnerabilities — that's stated policy.

Reports about **cryptographic correctness**, **composition safety**, **wire format flaws**, and **implementation bugs** are exactly what the disclosure program is for.
