"""
evaluate.py
Evaluates the baseline and core models on the frozen pilot test set.

Outputs:
  - reports/metrics.json      machine-readable, including per-source results
  - reports/evaluation_report.md

The report is deliberately honest: it reports per-source performance, the
URL-only sanity baseline, and the pilot's limitations.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import joblib
import pandas as pd
import sklearn
from sklearn.metrics import confusion_matrix

from backend.detector import detect_signals
from backend.explainability import compute_risk_verdict
from training.normalise import normalise_text
from training.schema import compose_text

PROCESSED = os.path.join("datasets", "processed")
MODELS = "models"
REPORTS = "reports"


def _binary_metrics(y_true, predictions) -> dict:
    """Compute metrics without inventing values when a class is absent."""
    matrix = confusion_matrix(y_true, predictions, labels=[0, 1]).tolist()
    tn, fp, fn, tp = matrix[0][0], matrix[0][1], matrix[1][0], matrix[1][1]

    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    if precision is None or recall is None:
        f1 = None
    elif precision + recall == 0:
        f1 = 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)
    fpr = fp / (fp + tn) if (fp + tn) else None
    accuracy = (tp + tn) / max(tp + tn + fp + fn, 1)

    return {
        "accuracy": float(accuracy),
        "precision": None if precision is None else float(precision),
        "recall": None if recall is None else float(recall),
        "f1": None if f1 is None else float(f1),
        "false_positive_rate": None if fpr is None else float(fpr),
        "confusion_matrix": matrix,
        "support": {"legit": int(tn + fp), "phishing": int(fn + tp)},
    }


def _fmt(value) -> str:
    return "n/a" if value is None else f"{value:.4f}"


def _verdict_counts(frame: pd.DataFrame) -> dict:
    """Count user-facing outcomes: High Risk, any flag, and missed phishing."""
    legit = frame[frame["label"] == 0]
    phishing = frame[frame["label"] == 1]
    high_fp = int((legit["verdict_label"] == "High Risk").sum())
    suspicious_fp = int((legit["verdict_label"] == "Suspicious").sum())
    uncertain = int((legit["verdict_label"] == "Uncertain / Review Manually").sum())
    flagged_fp = high_fp + suspicious_fp
    missed = int((phishing["verdict_label"] == "Low Risk").sum())
    return {
        "n": int(len(frame)),
        "legit_n": int(len(legit)),
        "high_risk_fp": high_fp,
        "suspicious_fp": suspicious_fp,
        "uncertain_routed": uncertain,
        "flagged_fp": flagged_fp,
        "missed_phishing": missed,
        "high_risk_fp_rate": (high_fp / len(legit)) if len(legit) else None,
        "suspicious_fp_rate": (suspicious_fp / len(legit)) if len(legit) else None,
        "flagged_fp_rate": (flagged_fp / len(legit)) if len(legit) else None,
        "missed_rate": (missed / len(phishing)) if len(phishing) else None,
    }


def _load_artifacts():
    base_clf = joblib.load(os.path.join(MODELS, "baseline_model.pkl"))
    base_vec = joblib.load(os.path.join(MODELS, "baseline_vectorizer.pkl"))
    core_clf = joblib.load(os.path.join(MODELS, "core_model.pkl"))
    core_vec = joblib.load(os.path.join(MODELS, "tfidf_vectorizer.pkl"))
    with open(os.path.join(MODELS, "metadata.json"), "r", encoding="utf-8") as handle:
        metadata = json.load(handle)
    return base_clf, base_vec, core_clf, core_vec, metadata


def evaluate_models() -> dict:
    os.makedirs(REPORTS, exist_ok=True)

    test_df = pd.read_csv(os.path.join(PROCESSED, "test.csv"))
    texts = [normalise_text(text) for text in compose_text(test_df)]
    y_true = test_df["label"].values

    base_clf, base_vec, core_clf, core_vec, metadata = _load_artifacts()
    threshold = float(metadata.get("decision_threshold", 0.5))

    base_preds = base_clf.predict(base_vec.transform(texts))
    core_probs = core_clf.predict_proba(core_vec.transform(texts))[:, 1]
    core_preds = (core_probs >= threshold).astype(int)

    baseline = _binary_metrics(y_true, base_preds)
    core_model = _binary_metrics(y_true, core_preds)

    verdict_labels = []
    for (_, row), probability in zip(test_df.iterrows(), core_probs):
        sender = row["sender"] if pd.notna(row["sender"]) else None
        signals = detect_signals(row["text"], sender)
        verdict_labels.append(
            compute_risk_verdict(float(probability), signals, [])["label"]
        )
    test_df = test_df.copy()
    test_df["verdict_label"] = verdict_labels

    verdict_evaluation = {
        "overall": _verdict_counts(test_df),
        "per_source": {
            str(source): _verdict_counts(frame)
            for source, frame in test_df.groupby("source")
        },
    }

    per_source: dict[str, dict] = {}
    for source, frame in test_df.groupby("source"):
        indices = frame.index
        source_metrics = _binary_metrics(
            test_df.loc[indices, "label"].values, core_preds[indices]
        )
        source_baseline = _binary_metrics(
            test_df.loc[indices, "label"].values, base_preds[indices]
        )
        source_metrics["n"] = int(len(frame))
        source_metrics["baseline"] = source_baseline
        source_metrics["label_distribution"] = {
            "legit": int((frame["label"] == 0).sum()),
            "phishing": int((frame["label"] == 1).sum()),
        }
        per_source[str(source)] = source_metrics

    has_url = test_df["text"].str.contains(r"http|www\.", case=False)
    url_shortcut_accuracy = float((has_url == test_df["label"].astype(bool)).mean())

    with open(os.path.join(PROCESSED, "test.csv"), "rb") as handle:
        dataset_sha256 = hashlib.sha256(handle.read()).hexdigest()

    metrics = {
        "evaluation_date": datetime.now(timezone.utc).date().isoformat(),
        "dataset_sha256": dataset_sha256,
        "sklearn_version": sklearn.__version__,
        "decision_threshold": threshold,
        "test_sample_count": int(len(test_df)),
        "test_class_distribution": {
            "legit": int((y_true == 0).sum()),
            "phishing": int((y_true == 1).sum()),
        },
        "url_shortcut_accuracy": url_shortcut_accuracy,
        "baseline": baseline,
        "core_model": core_model,
        "per_source": per_source,
        "verdict_evaluation": verdict_evaluation,
    }

    with open(os.path.join(REPORTS, "metrics.json"), "w", encoding="utf-8") as handle:
        json.dump(metrics, handle, indent=2)
        handle.write("\n")

    _write_report(metrics, test_df)
    return metrics


def _write_report(metrics: dict, test_df: pd.DataFrame) -> None:
    base = metrics["baseline"]
    core = metrics["core_model"]
    delta = core["f1"] - base["f1"]
    comparison = (
        "The core model improved on the baseline."
        if delta >= 0
        else "The core model did not improve on the baseline on this pilot test set; "
        f"the gap is {-delta:.4f} F1 and is based on only {metrics['test_sample_count']} rows."
    )

    source_rows = "\n".join(
        f"| `{source}` | {row['n']} | {_fmt(row['precision'])} | {_fmt(row['recall'])} | "
        f"{_fmt(row['f1'])} | {_fmt(row['false_positive_rate'])} | "
        f"{_fmt(row['baseline']['f1'])} |"
        for source, row in sorted(metrics["per_source"].items())
    )
    verdict_rows = "\n".join(
        f"| `{source}` | {row['n']} | {row['high_risk_fp']} | "
        f"{row['suspicious_fp']} | {row['uncertain_routed']} | "
        f"{row['missed_phishing']} |"
        for source, row in sorted(metrics["verdict_evaluation"]["per_source"].items())
    )

    report = f"""# PhishGuard — Pilot Model Evaluation Report

**Evaluation date:** {metrics['evaluation_date']}
**Test set:** {metrics['test_sample_count']} held-out rows
({metrics['test_class_distribution']['legit']} legitimate,
{metrics['test_class_distribution']['phishing']} phishing)
**Frozen test SHA-256:** `{metrics['dataset_sha256']}`
**Decision threshold:** {metrics['decision_threshold']:.2f} (tuned on validation only)
**scikit-learn:** {metrics['sklearn_version']}

---

## 1. Overall results

| Metric | Baseline (TF-IDF + MultinomialNB) | Core (word + char TF-IDF + LogisticRegression) |
|---|---:|---:|
| Accuracy | {_fmt(base['accuracy'])} | {_fmt(core['accuracy'])} |
| Precision | {_fmt(base['precision'])} | {_fmt(core['precision'])} |
| Recall | {_fmt(base['recall'])} | {_fmt(core['recall'])} |
| F1-score | {_fmt(base['f1'])} | {_fmt(core['f1'])} |
| False-positive rate | {_fmt(base['false_positive_rate'])} | {_fmt(core['false_positive_rate'])} |

**Core vs baseline:** F1 delta {delta:+.4f}. {comparison}

### Confusion matrices

**Baseline** (rows = truth, columns = prediction):

| | Predicted legit | Predicted phishing |
|---|---:|---:|
| Actual legit | {base['confusion_matrix'][0][0]} | {base['confusion_matrix'][0][1]} |
| Actual phishing | {base['confusion_matrix'][1][0]} | {base['confusion_matrix'][1][1]} |

**Core model:**

| | Predicted legit | Predicted phishing |
|---|---:|---:|
| Actual legit | {core['confusion_matrix'][0][0]} | {core['confusion_matrix'][0][1]} |
| Actual phishing | {core['confusion_matrix'][1][0]} | {core['confusion_matrix'][1][1]} |

---

## 2. Per-source results (core model)

The public sources are label-specific: Nazario contains only phishing and
SpamAssassin contains only legitimate mail. Metrics that need both classes are
therefore reported as `n/a` for those sources. The constructed VIT source has
both classes. This is the honest view of performance; a single overall number
would hide the source confound.

| Source | n | Precision | Recall | F1 | FPR | Baseline F1 |
|---|---:|---:|---:|---:|---:|---:|
{source_rows}

---

## 3. Final-label behaviour (model + rules)

The user-facing label combines the model probability with the rule signals.
High Risk and Suspicious are hard false positives. Uncertain is the intended
"review manually" route, reported separately rather than counted as a hard FP.
This is the metric that matters for a student, and it is separate from the
model-only table above.

| Source | n | High-risk FPs | Suspicious FPs | Uncertain | Missed phishing |
|---|---:|---:|---:|---:|---:|
{verdict_rows}

---

## 4. Sanity baseline: the URL shortcut

A single rule — "the message contains a URL" — scores
**{metrics['url_shortcut_accuracy']:.4f}** accuracy on this test set.
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
  {metrics['verdict_evaluation']['per_source']['constructed_vit']['n']} test rows
  are marked `is_synthetic=True` and its result should be read as a scenario
  check, not field evidence.
- **Class prevalence.** The test set is
  {metrics['test_class_distribution']['legit']} legitimate /
  {metrics['test_class_distribution']['phishing']} phishing, which is not the
  prevalence in a real inbox. False positives matter more than raw accuracy.
- **English only.** Hindi and Tamil are deferred to the multilingual pass.
- **No SMS yet.** The cross-source (SMS ↔ email) test is deferred.
- **Small pilot.** {metrics['test_sample_count']} test rows are enough to catch
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
"""
    with open(os.path.join(REPORTS, "evaluation_report.md"), "w", encoding="utf-8") as handle:
        handle.write(report)


if __name__ == "__main__":
    result = evaluate_models()
    print(
        f"Baseline F1={_fmt(result['baseline']['f1'])} "
        f"Core F1={_fmt(result['core_model']['f1'])} "
        f"URL-only={result['url_shortcut_accuracy']:.3f}"
    )
