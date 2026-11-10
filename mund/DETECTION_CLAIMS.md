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

## Local classifier (0.6.0)

A small offline model (hashed word and character n-grams, logistic regression, 80,000 weights, 208 KB) backs up the injection rules. It scores text in windows and sentences, so an injection appended to a normal question, or buried in a long page, isn't diluted. A hit is **warn** (medium severity, `alert`); the classifier never blocks on its own. Turn it off with `MUND_CLASSIFIER=0` or by disabling the `injection_classifier` rule.

**Method.** The [training scripts](training/README.md) fetch public datasets and train on fixed, deterministic splits. The threshold (0.978) was chosen on validation data only, as the lowest that kept benign false positives at or below 0.25%. The numbers below are from the shipped model, run through `scan()` and counting medium severity or higher, as the self red-team does. Test rows that duplicate a training row were dropped.

The test sets were scored twice during development. The first model flagged 4 of 2,062 benign texts, including one in Mund's benign corpus. The fix was broader benign training data (OpenAssistant assistant replies), not changes aimed at the flagged texts. The model was retrained and its threshold re-picked on validation, and the test sets were scored a second and final time. That model gave up a few points of detection: Gandalf 92.9% → 88.4%, jackhhao 84.4% → 77.0%.

| Test set | What it is | Rules only | Rules + classifier |
|---|---|---|---|
| Gandalf test (Lakera) | Players trying to override a password guard | 73/112 (65.2%) | **99/112 (88.4%)** |
| jackhhao test | Jailbreak prompts | 77/135 (57.0%) | **104/135 (77.0%)** |
| SPML ¹ | Prompts that break a chatbot's system prompt | 565/2342 (24.1%) | **897/2342 (38.3%)** |
| deepset test | Off-task and override requests to a news QA bot | 23/60 (38.3%) | 24/60 (40.0%) |
| Mosscap ¹ | Password-game turns, many only meaningful in context | 52/999 (5.2%) | 77/999 (7.7%) |
| InjecAgent, enhanced ¹ | Attacker instruction with an explicit override, inside a tool output | 1054/1054 (100%) | 1054/1054 (100%) |
| InjecAgent, base ¹ | Attacker instruction alone, as a polite sentence inside a tool output | 17/1054 (1.6%) | 17/1054 (1.6%) |

¹ A source the classifier was never trained on.

Benign texts flagged rose from **0 of 2,062 to 2 of 2,062 (0.10%)**: two README paragraphs, one of badge links and one of TypeScript, both full of the word "ignore". The sets:

| Benign set | Flagged |
|---|---|
| OpenAssistant prompts | 0/290 |
| README paragraphs from packages not trained on | 2/750 |
| SPML benign | 0/658 |
| jackhhao benign | 0/122 |
| InjecAgent tool outputs | 0/85 |
| deepset benign | 0/56 |
| InjecAgent user requests | 0/17 |
| Mund's benign corpus | 0/84 |

Scoring takes about 0.4 ms per text.

**What this does and doesn't show:**
- The classifier helps most against direct override and jailbreak attempts, including paraphrases.
- It helps less on sources it hasn't seen. The gains on SPML and Mosscap are real but modest.
- On Weave's own red-team corpus it adds nothing (94.1% either way), because the rules already catch those payloads.
- It does nothing for an attacker's request phrased as an ordinary sentence inside data (InjecAgent base). Such text reads like a legitimate request, and no content scanner can tell the difference without knowing what the user asked for. For that, enforce what tools may do with [Ward](../ward), and compare calls against declared intent with [Hundredmen](../hundredmen).

## Guardrail mapping and malicious-artifact requests (0.6.0)

Two narrow rules close the last gaps in Weave's red-team corpus. Both are **warn** (medium, `alert`).

| Rule | Catches | Leaves alone |
|---|---|---|
| `prompt_injection_policy_probe` | Asking which tools, URLs or commands the agent may use and, in the same request, which are denied or need approval; or asking for its hidden reasoning together with the rules it follows | "What tools are you allowed to use?" (stays low severity), questions about which files are editable, "show your reasoning step by step" |
| `harmful_artifact_request` | An imperative request to write or build a keylogger, ransomware, phishing email or kit, credential harvester or similar, with a cue that it should work for real (complete, convincing, undetectable, in full technical detail) | Descriptions of such tools, threat-intel prose, detection rules, YARA/Sigma signatures, filters, incident summaries |

**Results:**
- **Red-team corpus:** with both rules, Mund flags all 68 payloads, every category at 100% (jailbreak was 80%, extraction 60%), with 0 of 84 benign texts flagged.
- **Held-out sets:** neither rule fires on any of them, attacks or benign. They cost nothing in false positives, and they show no gain outside Weave's corpus, because the public sets don't contain these request shapes.
- **Security writing:** the hard benign test is 5,825 texts: MITRE ATT&CK technique, malware and tool descriptions, and OWASP Cheat Sheet paragraphs. Neither rule fires on any of them.

Mund as a whole now flags **15 of those 5,825 texts, down from 86** before 0.6.0. All 15 are AI-security pages that quote real injection strings: OWASP's prompt-injection, RAG and model-ops cheat sheets, and ATT&CK's prompt-injection technique. None is threat-intel or guidance prose.

Two heuristics were fixed in 0.6.0:
- **Role-switch** read titles that start with a role word ("[System Information Discovery]", "[Systemd Service]", "[admin@338]") as role markers. It now needs a bare tag like `[SYSTEM]`, or one naming an override or message.
- **Markup** flagged every `<script>`, `javascript:` and `data:text/html` at medium. These are ordinary in web pages and security writing, so a mention is now low. A script that reads cookies or storage and sends them off the page is high.

Five phrase rules also stopped firing on descriptions of what malware or systems do: authority, decode-and-execute, concealment, data harvest and jailbreak. Some examples:
- "a loader… designed to decrypt and execute";
- "allows the system to verify identity without asking the user";
- "it will… send information, including the user's hashed credentials".

A match is now skipped when the same sentence says what something can, may, will, was designed to or allows. "System command" in prose no longer counts as an authority claim. "AI agents should…" counts only when what follows is an instruction to the agent ("…should recommend our product"), not guidance about agents ("…should undergo security testing"). None of this changed detection on any held-out set or on the red-team corpus.

## Limits

Detection is pattern-based, plus the classifier above. These claims cover the attack shapes listed, not every variant: a paraphrased instruction with no hidden characters, URL or secret won't be caught by these checks. See the [OWASP coverage tables](README.md#️-owasp-coverage) for what is and isn't covered.
