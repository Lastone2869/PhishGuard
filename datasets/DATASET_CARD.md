# Dataset Card — PhishGuard Pilot Dataset

## 1. Summary

A multilingual-ready (English-only in this pilot) binary dataset for detecting
phishing messages aimed at university students, with the Q5 VIT account-suspension
scenario as the anchor case. It combines real public phishing email, real public
legitimate email including hard negatives, and a hand-authored VIT corpus.

- **Rows:** 1290
- **Classes:** 670 legitimate / 620 phishing
- **Clusters:** 937 near-duplicate groups
- **Synthetic rows:** 240 (hand-authored VIT corpus)
- **Seed:** 42
- **Frozen test SHA-256:** `79d3d92c3dfe10ef872c8a2fd7c2ef1e14060522a7d9441bdc77729c3f5c00f3`

## 2. Sources and licences

| Source | Rows | Train | Val | Test | Licence |
|---|---:|---:|---:|---:|---|
| `constructed_vit` | 240 | 172 | 34 | 34 | `project-owned` |
| `nazario` | 500 | 352 | 75 | 73 | `CC-BY-4.0` |
| `spamassassin` | 550 | 362 | 53 | 135 | `public-research` |

- **Nazario Phishing Corpus** (Jose Nazario, <https://monkey.org/~jose/phishing/>):
  real phishing emails, hand-classified, **CC-BY-4.0**. Attribution required.
- **SpamAssassin public mail corpus** (<https://spamassassin.apache.org/old/publiccorpus/>):
  real legitimate and hard-negative email used for spam-filter testing. The corpus
  readme states that **copyright remains with the original senders**; raw archives
  are not redistributed in this repository, and the processed sample is used for
  non-commercial educational research with attribution.
- **Constructed VIT corpus** (`datasets/constructed/vit_messages.csv`): authored for
  this project, project-owned, marked `is_synthetic=True`. It contains both
  phishing lures and genuine institutional notices, including hard negatives.

## 3. Schema

```text
id, text, subject, sender, label, category, source, campaign, cluster_id, language, is_synthetic, license, split, notes
```

| Column | Meaning |
|---|---|
| `id` | Stable deterministic identifier. |
| `text` | Cleaned message body (HTML stripped, quotes/signatures trimmed, PII redacted). |
| `subject` | Cleaned subject line, or null. |
| `sender` | Sender domain only (`***@domain`) for public corpora; full synthetic sender for constructed rows. |
| `label` | `1` phishing, `0` legitimate. |
| `category` | `phishing` or `legit`. Generic promo spam is out of scope for this pilot. |
| `source` | `nazario`, `spamassassin`, or `constructed_vit`. |
| `campaign` | Coarse provenance (`nazario:2023`, `sa:hard_ham`, `vit:P01`). |
| `cluster_id` | Leakage-prevention group; never crosses a split. |
| `language` | `en` in this pilot. |
| `is_synthetic` | `True` only for the constructed VIT corpus. |
| `license` | Per-source licence tag. |
| `split` | `train`, `val`, or `test`. |
| `notes` | Cleaning warnings or scenario/tactic label. |

## 4. Preprocessing

1. MIME payloads decoded with the declared charset (base64 and quoted-printable supported).
2. HTML converted to text; anchor text is preserved and `(anchor, href)` pairs are kept during extraction.
3. Quoted replies, forwarded header blocks, and `-- ` signatures trimmed.
4. Email addresses and 10-digit Indian mobile numbers redacted to `<EMAIL>` / `<PHONE>`.
5. Sender local-parts masked for public corpora; only the domain is retained.
6. Exact duplicates removed; near-duplicates clustered with character 3–5-gram TF-IDF cosine
   at a 0.75 threshold, so the 0.85 leakage gate has margin.

## 5. Split methodology

For each source independently, groups are assigned with `StratifiedGroupKFold`
(7 folds; `GroupKFold` for single-class sources) using `cluster_id` as the group.
Fold 0 is validation, fold 1 is test, and the remaining folds are training.
This guarantees:

- no `cluster_id` appears in more than one split;
- every source appears in the test set;
- the test set is frozen and hashed.

| Split | Rows |
|---|---:|
| train | 886 |
| val | 162 |
| test | 242 |

## 6. Quality gates measured at build time

| Gate | Value | Target |
|---|---:|---|
| URL-only shortcut accuracy | 0.5434 | < 0.70 |
| Hard-negative share of legit class | 0.3672 | >= 0.25 |
| Max test-to-train char similarity | 0.8290 | <= 0.85 |

The URL shortcut gate is the important one: in the previous 126-row dataset,
"contains a URL" predicted the label with 100% accuracy. This dataset deliberately
includes legitimate messages with links and security vocabulary.

## 7. Known biases and limitations

- **Temporal gap.** SpamAssassin ham is from 2002–2003; Nazario phishing is from
  2022–2024. The model may learn era-specific style. Report per-source results.
- **Label distribution.** The pilot is roughly balanced overall
  (670 legitimate / 620 phishing),
  but the test set is 153 legitimate /
  89 phishing because the public sources are
  label-specific: Nazario is all phishing and SpamAssassin is all legitimate. Per-source
  metrics are reported instead of one misleading overall number. Real inbox prevalence is
  far lower, so the false-positive rate matters more than accuracy.
- **Synthetic VIT rows.** The VIT scenario is authored, not observed. It is marked
  synthetic and its test performance is reported separately.
- **English only.** Hindi and Tamil are deferred to the multilingual pass; the
  `language` column is ready.
- **Public-corpus bias.** Nazario is one researcher's inbox; SpamAssassin is a
  spam-filter corpus. Neither represents student email.
- **Small pilot.** ~1,200 rows is enough to validate the pipeline and catch leakage,
  not enough for a final claim. The next pass adds SMS and expands the VIT corpus.

## 8. Reproduction

```bash
python -m training.fetch_sources --dest datasets/raw/external --extract
python -m training.build_dataset
python -m training.build_dataset --check
```

`--check` recomputes the frozen test hash and exits non-zero on drift.

## 9. Demo fixtures

`datasets/fixtures/demo_messages.csv` holds the original 126 hand-written rows
from the first prototype. They are retained for UI samples and smoke tests and
are **not** part of train/val/test. Regenerate them with
`python -m training.prepare_data`.
