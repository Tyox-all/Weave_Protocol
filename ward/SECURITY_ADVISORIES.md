# Security Advisories — @weave_protocol/ward and the harness adapters

_This document is the public record of security advisories issued for Ward and the WARD harness adapters (Claude Code, Antigravity, Microsoft Agent Framework). Entries use the same format as [Hord's advisories](https://github.com/Tyox-all/Weave_Protocol/blob/main/hord/SECURITY_ADVISORIES.md)._

---

## Advisories

### WARD-2026-001: harness adapters checked only part of each tool call

- **Severity:** High
- **Affects:**
  - @weave_protocol/adapter-claudecode ≤ 0.2.0
  - @weave_protocol/adapter-antigravity ≤ 0.2.1
  - @weave_protocol/adapter-msaf ≤ 0.1.0
- **Fixed in:**
  - @weave_protocol/ward 0.2.0, together with:
  - adapter-claudecode 0.3.0
  - adapter-antigravity 0.3.0
  - adapter-msaf 0.2.0
- **Reporter:** found in an internal audit
- **CVE:** none assigned

**Description:** Each adapter decided tool calls with its own copy of the same evaluator. Calls a WARD policy denies were allowed when:

| Gap | Example |
|---|---|
| A path or URL was in an argument other than the tool's one mapped field | a custom or MCP tool's `dest: "/etc/passwd"`, or `WebFetch { uri }` |
| A shell command contained more than one URL | `curl https://allowed… && curl https://evil…`; only the first URL was checked |
| A shell command read a denied path not on a short hard-coded list | `cat /workspace/secrets/key` |
| A path used `..` traversal | `/workspace/out/../secrets/key`, because the adapters were locked to Ward 0.1.2, before Ward 0.1.3's normalization |
| A recursive tool was pointed at a denied directory itself | `grep` over `/workspace/secrets`, where a `secrets/**` rule didn't cover the directory |
| A WARD.md existed but didn't parse | the Claude Code and Antigravity hooks allowed every call by default |
| MSAF was given an explicit `wardPath` that didn't exist | MSAF allowed every call by default |

**Impact:** An agent, or content steering an agent through prompt injection, could read, write or send data that the WARD policy denies. Policies that gate `shell_exec` or the tools themselves (`requireApproval` or `deny`) were not affected for those tools. The capability check was correct.

**Root cause:** The adapters didn't share an evaluator. Each one checked a single named argument per tool and the first URL in a command. Each also treated a policy that failed to load the same as having no policy.

**Fix:** Ward 0.2.0 adds `evaluateToolCall`, and all three adapters now use it. It checks:
- every path and URL argument, in any casing, including arrays, with `dest`, `target` and `output` treated as writes;
- every URL in a shell command;
- every absolute or `~` path in a shell command, plus relative paths that match an explicit rule. Redirect targets and copy destinations count as writes;
- relative paths, resolved against the working directory.

A `dir/**` rule now also covers `dir`. An invalid WARD.md now blocks (hooks) or throws (MSAF) instead of switching enforcement off, and so does a missing explicit MSAF `wardPath`.

Regression tests:
- `ward/tests/toolcall.test.mjs`
- `adapter-claudecode/test/ward-hook.test.mjs`
- `adapter-antigravity/test/ward-2026-001.test.mjs`
- `adapter-msaf/test/middleware.test.mjs`

**Mitigation for users on older versions:** Upgrade the adapter. Until then, gate `shell_exec` (and any tool that takes arbitrary paths) with `requireApproval` in WARD.md.
