# Models Directory

Trained artifacts produced by the training pipeline:

- `core_model.pkl` — LogisticRegression on word (1–2) + character (3–5) n-gram TF-IDF.
- `tfidf_vectorizer.pkl` — fitted `FeatureUnion` for the core model.
- `baseline_model.pkl` — MultinomialNB baseline.
- `baseline_vectorizer.pkl` — fitted word TF-IDF for the baseline.
- `metadata.json` — training provenance.

`metadata.json` records:

| Field | Meaning |
|---|---|
| `model_type`, `vectorizer` | Model and feature configuration. |
| `decision_threshold` | Validation-tuned threshold used for the core model. |
| `sklearn_version` | Exact scikit-learn version that produced the pickles. |
| `dataset_sha256` | SHA-256 of `datasets/processed/test.csv` at training time. |
| `trained_at` | UTC timestamp. |
| `train_rows`, `val_rows`, `sources` | Training provenance. |

## Retraining

```bash
python -m training.build_dataset
python -m training.train_baseline
python -m training.train
python -m training.evaluate
```

`scikit-learn` is pinned to `1.6.1` in both requirements files. The API compares
`metadata.json["sklearn_version"]` with the installed version and raises a clear
error instead of silently loading an incompatible pickle (the previous artifacts
were built with 1.9.1 and failed with `AttributeError: multi_class`).

Do not commit artifacts trained by a different scikit-learn version.
