# Mund detection claims

Every claim below is backed by a fixture in this repository and a test that checks Mund returns the stated verdict. If a claim stops holding, CI fails.

```bash
cd mund && npm ci && npx vitest run tests/preinstall.test.ts tests/fixtures.test.ts
```

Verdicts: **block** (deny), **warn** (ask the user), **allow**. All fixture content is benign: the checks look at *how* something is built (hidden characters, package names, URLs), so no real attack payloads are needed to prove them.

## Skills: checked before install

| Claim: Mund catches… | Fixture | Verdict |
|---|---|---|
| Invisible Unicode tag characters (ASCII smuggling: text the model reads but a reviewer can't see) | [`skills/hidden-tag-characters`](tests/fixtures/preinstall/skills/hidden-tag-characters/SKILL.md) | **block** |
| Bidirectional override characters that reorder what a reviewer sees | [`skills/bidi-override`](tests/fixtures/preinstall/skills/bidi-override/SKILL.md) | **block** |
| A credential embedded in a skill | [`skills/embedded-secret`](tests/fixtures/preinstall/skills/embedded-secret/SKILL.md) | **block** |
| Instructions to POST data to a collection service | [`skills/exfil-url`](tests/fixtures/preinstall/skills/exfil-url/SKILL.md) | **block** |
| `curl … \| bash` installers | [`skills/curl-bash-installer`](tests/fixtures/preinstall/skills/curl-bash-installer/SKILL.md) | warn |
| …and leaves a plain skill alone | [`skills/clean`](tests/fixtures/preinstall/skills/clean/SKILL.md) | allow |

## MCP servers: how they're launched (static, nothing is started)

| Claim: Mund catches… | Fixture | Verdict |
|---|---|---|
| A package scope imitating `@modelcontextprotocol` | [`scope-typosquat`](tests/fixtures/preinstall/mcp-config/scope-typosquat.json) | **block** |
| A server URL pointing at a data-collection service | [`exfil-service-url`](tests/fixtures/preinstall/mcp-config/exfil-service-url.json) | **block** |
| A package name within two edits of a known server (`githbu`) | [`name-typosquat`](tests/fixtures/preinstall/mcp-config/name-typosquat.json) | warn |
| A remote server over plain HTTP | [`plain-http-remote`](tests/fixtures/preinstall/mcp-config/plain-http-remote.json) | warn |
| A token written into the config instead of `${ENV_VAR}` | [`inline-token`](tests/fixtures/preinstall/mcp-config/inline-token.json) | warn |
| A launcher that pipes a download into a shell | [`shell-pipeline-launcher`](tests/fixtures/preinstall/mcp-config/shell-pipeline-launcher.json) | warn |
| An unpinned package (flagged, low severity) | [`unpinned-package`](tests/fixtures/preinstall/mcp-config/unpinned-package.json) | allow |
| …and accepts `${ENV_VAR}` references and pinned official packages | [`env-reference`](tests/fixtures/preinstall/mcp-config/env-reference.json), [`clean-pinned`](tests/fixtures/preinstall/mcp-config/clean-pinned.json) | allow |

## MCP servers: live checks and rug pulls

Tested against a local fake MCP server ([`fake-mcp-server.mjs`](tests/fixtures/preinstall/fake-mcp-server.mjs)) in [`tests/preinstall.test.ts`](tests/preinstall.test.ts) and [`tests/fixtures/rugpull/`](tests/fixtures/rugpull):

| Claim | Verdict |
|---|---|
| A tool description that changes after approval (a rug pull) is flagged until you accept it | warn |
| A rug pull that adds a command-execution tool | **block** |
| Mund never starts a project server you haven't approved; it checks it statically | — |
| Mund never starts a server whose package or URL it already distrusts | — |

## Limits

Detection is pattern-based. These claims cover the attack shapes listed, not every variant: a paraphrased instruction with no hidden characters, URL or secret won't be caught by these checks. See the [OWASP coverage tables](README.md#️-owasp-coverage) for what is and isn't covered.
