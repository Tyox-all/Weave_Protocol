# Mund classifier: training and evaluation

These scripts produce `src/analyzers/injection-model.ts` and the numbers in [DETECTION_CLAIMS.md](../DETECTION_CLAIMS.md#local-classifier-060). They are not part of the published package.

```bash
cd mund && npm run build
node training/fetch.mjs                     # ~10 MB of public datasets into training/data (git-ignored)
node training/hardneg.mjs training/data/hardneg.json
node training/normalize.mjs training/data ..
node training/train.mjs --l2=1e-4 --epochs=12 --maxfp=0.0025 --prune=80000 --out=training/data/final.json
node training/final.mjs                     # rules alone vs rules + classifier, on every test set
node training/secset.mjs training/data/sec  # benign security writing: ATT&CK + OWASP
node training/secfp.mjs injection           # what Mund flags in it, by rule
```

**Splits** (`split.mjs`, deterministic) are as follows. Nothing in a test set is used for training or for choosing the threshold.

| | Sources |
|---|---|
| Train | deepset/prompt-injections train, Lakera/gandalf_ignore_instructions train, jackhhao/jailbreak-classification train, OpenAssistant/oasst1 prompts and assistant replies, README paragraphs from 60% of installed npm packages, template-generated benign developer text (`hardneg.mjs`) |
| Validation (threshold only) | 15% held out of each of those, plus the Gandalf validation split |
| Test | deepset, Gandalf and jackhhao test splits; SPML and Mosscap (sources never trained on); InjecAgent tool outputs (indirect injection); oasst1 validation; README paragraphs from the other 40% of packages; Mund's benign corpus |

Test rows that duplicate a training row are dropped before scoring. Fetched data comes from the Hugging Face datasets API and from GitHub, and is used as text only.

**Licenses:**
- deepset, jackhhao and oasst1: Apache-2.0;
- Gandalf, Mosscap, SPML and InjecAgent: MIT;
- OWASP Cheat Sheet Series: CC BY-SA 4.0;
- MITRE ATT&CK: MITRE's ATT&CK terms of use.

The security texts are used for evaluation only.
