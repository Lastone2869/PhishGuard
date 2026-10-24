# PhishGuard — Pilot Model Evaluation Report

**Evaluation date:** 2026-10-24
**Test set:** 242 held-out rows
(153 legitimate,
89 phishing)
**Frozen test SHA-256:** `79d3d92c3dfe10ef872c8a2fd7c2ef1e14060522a7d9441bdc77729c3f5c00f3`
**Decision threshold:** 0.50 (tuned on validation only)
**scikit-learn:** 1.6.1

---

## 1. Overall results

| Metric | Baseline (TF-IDF + MultinomialNB) | Core (word + char TF-IDF + LogisticRegression) |
|---|---:|---:|
| Accuracy | 0.9298 | 0.9545 |
| Precision | 0.8673 | 0.9535 |
| Recall | 0.9551 | 0.9213 |
| F1-score | 0.9091 | 0.9371 |
| False-positive rate | 0.0850 | 0.0261 |

**Core vs baseline:** F1 delta +0.0281. The core model improved on the baseline.

### Confusion matrices

**Baseline** (rows = truth, columns = prediction):

| | Predicted legit | Predicted phishing |
|---|---:|---:|
| Actual legit | 140 | 13 |
| Actual phishing | 4 | 85 |

**Core model:**

| | Predicted legit | Predicted phishing |
|---|---:|---:|
| Actual legit | 149 | 4 |
| Actual phishing | 7 | 82 |

---

## 2. Per-source results (core model)

The public sources are label-specific: Nazario contains only phishing and
SpamAssassin contains only legitimate mail. Metrics that need both classes are
therefore reported as `n/a` for those sources. The constructed VIT source has
both classes. This is the honest view of performance; a single overall number
would hide the source confound.

| Source | n | Precision | Recall | F1 | FPR | Baseline F1 |
|---|---:|---:|---:|---:|---:|---:|
| `constructed_vit` | 34 | 0.7647 | 0.8125 | 0.7879 | 0.2222 | 0.6818 |
| `nazario` | 73 | 1.0000 | 0.9452 | 0.9718 | n/a | 0.9790 |
| `spamassassin` | 135 | n/a | n/a | n/a | 0.0000 | n/a |

---

## 3. Final-label behaviour (model + rules)

The user-facing label combines the model probability with the rule signals.
High Risk and Suspicious are hard false positives. Uncertain is the intended
"review manually" route, reported separately rather than counted as a hard FP.
This is the metric that matters for a student, and it is separate from the
model-only table above.

| Source | n | High-risk FPs | Suspicious FPs | Uncertain | Missed phishing |
|---|---:|---:|---:|---:|---:|
| `constructed_vit` | 34 | 0 | 2 | 1 | 0 |
| `nazario` | 73 | 0 | 0 | 0 | 5 |
| `spamassassin` | 135 | 12 | 42 | 0 | 0 |

---

## 4. Sanity baseline: the URL shortcut

A single rule — "the message contains a URL" — scores
**0.4256** accuracy on this test set.
It is reported so the model's result can be judged against a trivial feature.
The dataset was rebuilt specifically to stop this shortcut from working, so a
score near chance here is expected and desirable.

---

## 5. Limitations

- **Temporal gap.** The SpamAssassin legitimate mail is from 2002–2003, while the
  Nazario phishing mail is from 2022–2024. Era-specific style can influence the
  model; per-source results are the honest comparison.
- **Source/label confound.** Nazario supplies only phishing and SpamAssassin only
  legitimate mail. A model can learn source style rather than phishing intent.
  The constructed VIT source is the only source with both classes.
- **Synthetic VIT rows.** The VIT scenario is hand-authored, not observed in a
  real student inbox. Its
  34 test rows
  are marked `is_synthetic=True` and its result should be read as a scenario
  check, not field evidence.
- **Class prevalence.** The test set is
  153 legitimate /
  89 phishing, which is not the
  prevalence in a real inbox. False positives matter more than raw accuracy.
- **English only.** Hindi and Tamil are deferred to the multilingual pass.
- **No SMS yet.** The cross-source (SMS ↔ email) test is deferred.
- **Small pilot.** 242 test rows are enough to catch
  leakage and gross errors, not enough for a final claim.
- **Public-corpus bias.** Nazario is one researcher's inbox; SpamAssassin is a
  spam-filter corpus. Neither represents Indian student email.

---

## 6. Reproduction

```bash
python -m training.evaluate
python -m training.build_dataset --check
```

The test set is frozen by SHA-256. Rebuilding the dataset changes the hash and
invalidates this report until evaluation is rerun.
