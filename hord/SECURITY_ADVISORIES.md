# Security Advisories — @weave_protocol/hord

_This document is the public record of security advisories issued for Hord. Entries use the same format as [Yoxallismus' advisories](https://github.com/Tyox-all/Weave_Protocol/blob/main/yoxallismus/SECURITY_ADVISORIES.md)._

---

## Advisories

### HORD-2026-001: non-hex master keys all derived the same vault master key

- **Severity:** High
- **Affects:** @weave_protocol/hord ≤ 0.1.11
- **Fixed in:** @weave_protocol/hord 0.2.0
- **Reporter:** found in an internal audit
- **CVE:** none assigned

**Description:** `KeyStore.initialize()` hex-decoded string master keys. Node's hex decoder stops at the first non-hex character, so any key that wasn't pure hex decoded to an empty buffer, and every such key derived the same master key. That includes the README's `HORD_MASTER_KEY=my-secure-key` example and the built-in default used when no key was set (`hord-default-master-key-…`). Separately, `HORD_MASTER_KEY_FILE` was used as the key itself: the file path string, not the file's contents.

**Impact:** Vault encryption keys are wrapped with the master key. For affected configurations the master key was a constant shared by every install, so anyone with access to stored vault data could unwrap the keys and decrypt it. Only master keys given as exactly 64 hex characters (or a 32-byte buffer) were unaffected. Hord's storage is in-memory only in these versions, so exposure requires access to the running process's memory or to data exported from it.

**Root cause:** `Buffer.from(masterKey, 'hex')` applied to arbitrary strings, with no check that the result was non-empty.

**Fix:** A string is used as raw key material only when it is exactly 64 hex characters; anything else is treated as a UTF-8 passphrase and run through PBKDF2. Empty keys are rejected. `HORD_MASTER_KEY_FILE` now reads the file. With no key configured, the server generates a random key for the process and says so, instead of falling back to a guessable default. Regression tests: `hord/tests/master-key.test.ts`.

**Mitigation for users on older versions:** set `HORD_MASTER_KEY` to 64 random hex characters (`openssl rand -hex 32`), or upgrade to 0.2.0.
