# PhishGuard — AI-Based Phishing Awareness Tool for Students

PhishGuard analyses pasted message text (email, SMS, or chat) and an optional
sender, then returns a risk label, the strongest signals, defanged links, and
safe reporting advice. It never visits, resolves, or previews a submitted link.

Built for the Q5 scenario: students receive messages claiming their VIT account
will be suspended unless they click a link immediately.

## Status

| Area | State |
|---|---|
| Stage 1 core (API, UI, 4 signals, risk label, advice) | Working |
| Pilot dataset (~1,290 rows, grouped splits, quality gates) | Working |
| Baseline + core model, per-source evaluation | Working |
| Stage 2 (Bayesian net, HMM, multilingual, OCR/QR, quiz, dashboard) | Planned |

## Quick start (Windows PowerShell)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt

# The processed pilot dataset is committed, so this is optional:
python -m training.fetch_sources --dest datasets/raw/external --extract
python -m training.build_dataset

# Retrain (the committed artifacts already work):
python -m training.train_baseline
python -m training.train
python -m training.evaluate

python run.py
```

Open <http://127.0.0.1:8000>. API docs: <http://127.0.0.1:8000/docs>.

## Tests

```powershell
pytest tests/ -q
python -m training.build_dataset --check
```

`--check` recomputes the frozen test-set SHA-256 and fails on drift.

## API

- `POST /api/analyse` — `{"text": "...", "sender": "optional@example.com"}`.
  Returns the label, composite score, four signal groups, ranked explanations,
  defanged URLs, and reporting guidance.
- `GET /api/health` — model-load status.
- `/` — the analyser UI.

Links are treated as text only. There is no code path that fetches a submitted URL,
and `tests/test_url_analyser.py` blocks sockets to prove it.

## Dataset

The pilot dataset is rebuilt from real public corpora plus a constructed VIT set.
The full details, licences, split method, and limitations are in
[`datasets/DATASET_CARD.md`](datasets/DATASET_CARD.md).

| Source | Role | Rows | Licence |
|---|---|---:|---|
| Nazario Phishing Corpus (`phishing-2022/23/24`) | real phishing email | 500 | CC-BY-4.0 |
| SpamAssassin `easy_ham`, `easy_ham_2`, `hard_ham` | real legitimate email + hard negatives | 550 | public research corpus; copyright original senders |
| Constructed VIT corpus | VIT scenario + genuine notices | 240 | project-owned |

Quality gates enforced by tests:

| Gate | Value | Target |
|---|---:|---|
| "Contains a URL" shortcut accuracy | 0.543 | < 0.70 (was 1.00 in the old dataset) |
| Hard negatives as a share of legitimate mail | 0.367 | >= 0.25 |
| Maximum test-to-train character similarity | 0.829 | <= 0.85 |

Splits are assigned per source with `StratifiedGroupKFold` on near-duplicate
clusters, so no cluster crosses train/val/test and every source appears in test.

The original 126 hand-written rows live in `datasets/fixtures/demo_messages.csv`
for UI samples and smoke tests. They are **not** used for training.

## Project structure

```text
backend/
  main.py                 FastAPI routes + static hosting
  detector.py             urgency, credential, URL, sender rules
  explainability.py       composite score, labels, ranked explanations
  url_analyser.py         safe URL structure checks and defanging
  data/trusted_domains.json
frontend/
  index.html, app.js, styles.css
training/
  fetch_sources.py        download + checksum public corpora
  email_clean.py          HTML/decode/quote/signature/PII cleaning
  build_dataset.py        cluster, grouped split, manifest, dataset card
  schema.py               shared schema + model input composition
  normalise.py            Unicode, zero-width, homoglyph, leetspeak, URL masking
  train.py                word+char TF-IDF + LogisticRegression
  train_baseline.py       TF-IDF + MultinomialNB
  evaluate.py             overall + per-source metrics and report
  prepare_data.py         legacy demo-fixture generator
datasets/
  sources.json            URLs, licences, SHA-256
  manifest.json           frozen test hash, counts, quality metrics
  constructed/vit_messages.csv
  processed/{train,val,test}.csv
  fixtures/demo_messages.csv
models/                   trained artifacts + metadata.json
reports/                  metrics.json + evaluation_report.md
tests/
```

Planned Stage 2 modules (`header_analyser.py`, `language.py`, `ocr_qr.py`,
`campaigns.py`, `reporting.py`, `privacy.py`, `train_bayes_net.py`,
`train_hmm.py`, `fusion.py`, `robustness.py`, `ablation.py`, `quiz.html`,
`dashboard.html`) are not present yet.

## Known limitations

- The pilot is ~1,290 rows. It is enough to catch leakage and gross errors, not
  enough for a final performance claim.
- Public sources are label-specific: Nazario is all phishing, SpamAssassin is all
  legitimate. Per-source results are reported instead of one overall number.
- The VIT scenario rows are hand-authored and marked `is_synthetic=True`.
- English only. Hindi and Tamil are deferred to the multilingual pass.
- No SMS source yet, so the cross-source (SMS ↔ email) test is deferred.
- The core model beats the baseline on the pilot test set (F1 0.9371 vs 0.9091).
- On the 34 constructed-VIT test rows, the final labels produce **0 High Risk
  false positives**, 2 Suspicious false positives and 1 Uncertain routing out of
  18 legitimate rows, with 0 missed phishing. The remaining ambiguity is the
  intended "review manually" behaviour, not a silent wrong verdict.

## Dataset licences

- **Nazario Phishing Corpus** — CC-BY-4.0, attributed in the dataset card.
- **SpamAssassin public corpus** — used for non-commercial educational research;
  copyright remains with the original senders. Raw archives are not committed.
- **Constructed VIT corpus** — authored for this project.

Raw external archives are gitignored under `datasets/raw/external/`; only the
processed snapshot and the source manifest are committed.
