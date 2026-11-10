# Mund classifier: training and evaluation

These scripts produce `src/analyzers/injection-model.ts` and the numbers in [DETECTION_CLAIMS.md](../DETECTION_CLAIMS.md#local-classifier-060). They are not part of the published package.

```bash
cd mund && npm run build
node training/fetch.mjs                     # ~10 MB of public datasets into training/data (git-ignored)
node training/hardneg.mjs training/data/hardneg.json
node training/normalize.mjs training/data ..
node training/train.mjs --l2=1e-4 --epochs=12 --maxfp=0.0025 --prune=80000 --out=training/data/final.json
node training/final.mjs                     # rules alone vs rules + classifier, on every test set
node training/zh-robustness.mjs             # Chinese filter-dodging tricks, on held-out rows
node training/build-hanzi.mjs               # regenerate src/analyzers/hanzi.ts from OpenCC and pinyin-data
node training/secset.mjs training/data/sec  # benign security writing: ATT&CK + OWASP
node training/secfp.mjs injection           # what Mund flags in it, by rule
```

**Splits** (`split.mjs`, deterministic) are as follows. Nothing in a test set is used for training or for choosing the threshold.

| | Sources |
|---|---|
| Train | deepset/prompt-injections train, Lakera/gandalf_ignore_instructions train, jackhhao/jailbreak-classification train, OpenAssistant/oasst1 prompts and assistant replies, README paragraphs from 60% of installed npm packages, template-generated benign developer text (`hardneg.mjs`). Since 0.7.0 also Shuangsuo train and OpenAssistant Chinese, though the shipped classifier is still 0.6.1's (see DETECTION_CLAIMS.md) |
| Validation (threshold only) | 15% held out of each of those, plus the Gandalf validation split |
| Test | deepset, Gandalf and jackhhao test splits; SPML and Mosscap (sources never trained on); InjecAgent tool outputs (indirect injection); Shuangsuo test (Chinese, held-out phrasings); Safety-Prompts goal hijacking and benign questions; OpenAssistant Chinese validation; Chinese Wikipedia; oasst1 validation; README paragraphs from the other 40% of packages; Mund's benign corpus |

Test rows that duplicate a training row are dropped before scoring. Fetched data comes from the Hugging Face datasets API and from GitHub, and is used as text only.

**Licenses:**
- deepset, jackhhao and oasst1: Apache-2.0;
- Gandalf, Mosscap, SPML and InjecAgent: MIT;
- OWASP Cheat Sheet Series: CC BY-SA 4.0;
- Shuangsuo bilingual prompts: CC BY 4.0;
- Safety-Prompts (Tsinghua): Apache-2.0;
- Chinese Wikipedia: CC BY-SA;
- OpenCC: Apache-2.0, and pinyin-data: MIT, for `hanzi.ts` (see [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md));
- MITRE ATT&CK: MITRE's ATT&CK terms of use.

The security texts are used for evaluation only.
