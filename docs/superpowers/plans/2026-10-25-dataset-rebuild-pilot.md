# Dataset Rebuild (Pilot) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the 126-row toy dataset with a ~1,200-row, leakage-resistant, licence-documented pilot dataset that breaks the "URL = phishing" shortcut, then retrain and honestly re-evaluate the model.

**Architecture:** A fetch → clean → cluster → group-split → card pipeline. Real phishing emails come from the Nazario corpus (CC-BY-4.0); real legitimate/hard-negative emails come from the SpamAssassin public corpus (public research corpus, copyright original senders); the VIT scenario and genuine institutional notices are constructed and marked synthetic. Splits are assigned per source with `StratifiedGroupKFold` so no near-duplicate cluster crosses train/val/test.

**Tech Stack:** Python 3.12, pandas, scikit-learn 1.6.1, joblib, pytest, stdlib `email`/`html.parser`, `curl` + `tar` for fetch.

**Spec:** `specs.md` §4.1 (dataset), §5 (preprocessing), §10 (non-functional); `implementation.md` §1.1–1.3; `DATASET_CARD.md`.

## Global Constraints

- Python 3.12; `scikit-learn==1.6.1` in both requirements files (installed version; stops the pickle drift).
- No network access at training, evaluation, API, or test time. Fetching is an explicit `--fetch` step.
- Never visit, resolve, or preview a URL. Links are text only.
- Dataset licences must be recorded per source in `datasets/sources.json` and `DATASET_CARD.md`.
- Raw external archives stay out of git (`datasets/raw/external/`); processed CSVs are committed.
- Every split is group-disjoint by `cluster_id`; the test file is frozen and hashed.
- PII in training text is redacted (`<EMAIL>`, `<PHONE>`); sender local-parts are masked.
- Language: English only for this pilot. `language` column stays so Stage 2 can add `hi`/`ta`.
- Old 126-row dataset becomes `datasets/fixtures/demo_messages.csv`; never trained on again.

## Pilot Composition (target)

| Source | Role | Rows | Licence |
|---|---|---|---|
| Nazario Phishing Corpus (`phishing-2022`, `-2023`, `-2024` mbox) | real phishing email | 500 | CC-BY-4.0 |
| SpamAssassin `easy_ham`, `easy_ham_2`, `hard_ham` | real legit + hard negatives | 550 (250/150/150) | public research corpus; copyright original senders |
| `datasets/constructed/vit_messages.csv` | VIT scenario + genuine notices | 120 (60 phish / 60 legit) | project-owned |

Total ~1,170 rows, ~50/50 classes, ~15% test (~175 rows).

## Review Focus

These are the input classes most likely to break the build. Each gets a test in the owning task.

1. **HTML-only emails** (99% of Nazario) — must yield readable text and links, never raw tags.
2. **Quoted replies / forwarded chains** — must not leak label or inflate length.
3. **Missing subject / sender / URL / body** — must not crash; `sender` and `subject` may be null.
4. **Near-duplicate campaign variants** — must never straddle train/val/test.
5. **Encoded payloads** (base64, quoted-printable, non-UTF-8 charset) — must decode or drop, never mojibake.

---

## Task 1: Source manifest and fetch

**Files:**
- Create: `datasets/sources.json`
- Create: `training/fetch_sources.py`
- Test: `tests/test_fetch_sources.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `fetch_sources(dest: Path, only: list[str] | None = None) -> list[Path]`; `sha256_file(path: Path) -> str`; `validate_manifest(manifest: dict) -> None`.

- [ ] **Step 1: Write the failing tests**

```python
def test_manifest_has_required_fields_for_every_source():
    m = json.loads(Path("datasets/sources.json").read_text())
    for s in m["sources"]:
        assert {"name", "url", "license", "sha256", "dest"} <= set(s)
        assert s["license"] in {"CC-BY-4.0", "public-research", "project-owned"}

def test_validate_manifest_rejects_missing_license():
    with pytest.raises(ValueError, match="license"):
        validate_manifest({"sources": [{"name": "x", "url": "u", "sha256": "s", "dest": "d"}]})

def test_sha256_file_matches_known_content(tmp_path):
    p = tmp_path / "a.txt"; p.write_text("phishguard")
    assert sha256_file(p) == hashlib.sha256(b"phishguard").hexdigest()
```

- [ ] **Step 2: Run tests, verify RED**

Run: `pytest tests/test_fetch_sources.py -v`
Expected: FAIL (`ModuleNotFoundError: training.fetch_sources`).

- [ ] **Step 3: Implement `sources.json` and `fetch_sources.py`**

Manifest entries (exact URLs):

```text
https://monkey.org/~jose/phishing/phishing-2022
https://monkey.org/~jose/phishing/phishing-2023
https://monkey.org/~jose/phishing/phishing-2024
https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2
https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham_2.tar.bz2
https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2
```

`fetch_sources` downloads only if the destination is missing, verifies SHA-256 (or records it on first fetch when `sha256` is `null`), and extracts `.tar.bz2` with `tarfile`. `only` filters by manifest `name`. No network calls at import time.

- [ ] **Step 4: Run tests, verify GREEN**

Run: `pytest tests/test_fetch_sources.py -v`
Expected: PASS.

- [ ] **Step 5: Fetch the pilot sources**

Run: `python -m training.fetch_sources --dest datasets/raw/external`
Expected: 6 files downloaded, hashes written back to `sources.json` if empty.

- [ ] **Step 6: Commit**

```bash
git add datasets/sources.json training/fetch_sources.py tests/test_fetch_sources.py
git commit -m "feat(dataset): add sourced fetch manifest with checksums"
```

---

## Task 2: Email cleaning and PII redaction

**Files:**
- Create: `training/email_clean.py`
- Test: `tests/test_email_clean.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `html_to_text(html: str) -> tuple[str, list[dict]]` — `links` items are `{"anchor": str, "href": str}`.
  - `decode_payload(part: email.message.Message) -> str`
  - `trim_quoted(text: str) -> str`
  - `trim_signature(text: str) -> str`
  - `parse_sender(raw: str) -> tuple[str | None, str | None]` — `(display_name, address)`.
  - `redact_pii(text: str) -> str`
  - `clean_message(subject: str | None, body: str) -> dict` — keys `text`, `subject`, `links`, `warnings`.

- [ ] **Step 1: Write the failing tests**

```python
def test_html_to_text_keeps_anchor_words_and_drops_tags():
    text, links = html_to_text('<p>Verify <a href="http://vit-fake.info/x">your account</a> now</p>')
    assert "Verify your account now" in text
    assert "<p>" not in text
    assert links == [{"anchor": "your account", "href": "http://vit-fake.info/x"}]

def test_trim_quoted_removes_reply_chain():
    raw = "Please pay now.\n\nOn Mon, 5 Oct 2026, VIT wrote:\n> old message\n> more"
    assert trim_quoted(raw) == "Please pay now."

def test_trim_signature_removes_signature_block():
    assert trim_signature("Body text.\n\n-- \nRegards, IT") == "Body text."

def test_parse_sender_display_name_and_address():
    assert parse_sender('"VIT Helpdesk" <helpdesk@vit.ac.in>') == ("VIT Helpdesk", "helpdesk@vit.ac.in")
    assert parse_sender("helpdesk@vit.ac.in") == (None, "helpdesk@vit.ac.in")
    assert parse_sender("") == (None, None)

def test_redact_pii_replaces_email_and_phone_but_keeps_url():
    out = redact_pii("Mail me at a.b@x.com or 9876543210, see http://vit.ac.in/help")
    assert "<EMAIL>" in out and "<PHONE>" in out
    assert "http://vit.ac.in/help" in out

def test_clean_message_handles_missing_fields():
    out = clean_message(None, "")
    assert out["text"] == "" and out["subject"] is None and out["links"] == []
```

- [ ] **Step 2: Run tests, verify RED**

Run: `pytest tests/test_email_clean.py -v`
Expected: FAIL (`ImportError`).

- [ ] **Step 3: Implement the module**

Use `html.parser.HTMLParser` subclass: collect data, record `(anchor_text, href)` on `<a>`, handle `<br>`/`<p>` as newlines. `decode_payload` handles `base64`/`quoted-printable` via `get_payload(decode=True)` and `get_content_charset() or "utf-8"` with `errors="replace"`. `trim_quoted` cuts at `On ... wrote:`, `-----Original Message-----`, `From: ...`, and strips leading `>`. `trim_signature` cuts at `\n-- \n`. `parse_sender` uses `email.utils.parseaddr`. `redact_pii` replaces email regex and 10-digit Indian phone numbers; URLs are protected by splitting on URL matches first.

- [ ] **Step 4: Run tests, verify GREEN**

Run: `pytest tests/test_email_clean.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add training/email_clean.py tests/test_email_clean.py
git commit -m "feat(dataset): add email html/quote/pii cleaning helpers"
```

---

## Task 3: Constructed VIT corpus

**Files:**
- Create: `datasets/constructed/vit_messages.csv`
- Test: `tests/test_constructed.py`

**Interfaces:**
- Consumes: nothing.
- Produces: CSV with columns `id, template_id, subject, text, sender, label, category, language, notes`.

- [ ] **Step 1: Write the failing tests**

```python
def test_constructed_schema_and_counts():
    df = pd.read_csv("datasets/constructed/vit_messages.csv")
    assert list(df.columns) == ["id","template_id","subject","text","sender","label","category","language","notes"]
    assert len(df) >= 120
    assert set(df.label) == {0, 1}
    assert df.template_id.nunique() >= 60

def test_constructed_has_hard_negatives():
    legit = df[df.label == 0]
    hard = legit.text.str.contains(r"http|https") & legit.text.str.contains(r"suspend|verify|password|expir|last date|deadline", case=False)
    assert hard.sum() >= 20

def test_constructed_phish_senders_are_not_official():
    phish = df[df.label == 1]
    assert not phish.sender.str.contains(r"@vit\.ac\.in$", regex=True).any()

def test_constructed_variants_share_template_id():
    df = pd.read_csv(...)
    assert (df.groupby("template_id").size() >= 2).all()
```

- [ ] **Step 2: Run tests, verify RED**

Run: `pytest tests/test_constructed.py -v`
Expected: FAIL (`FileNotFoundError`).

- [ ] **Step 3: Author 30 phishing templates × 2 variants and 30 legitimate templates × 2 variants**

Cover phishing: suspension/KYC, VTOP credential harvest, fee discrepancy, exam debarment, placement shortlist, library/hostel expiry, scholarship bank details, grade revision, WiFi re-auth, proctor complaint, QR/attachment, lookalike domain, IP-host URL, shortener, punycode-style domain.
Cover legit hard negatives: genuine password expiry (official portal), fee deadline (official portal), timetable/exam circular with link, hostel maintenance downtime, placement registration, library due date, scholarship deadline, OTP delivery ("do not share"), bank transaction alert ("if this was you, no action"), delivery tracking, Google/Microsoft security alert, event registration, bus route change, proctor meeting, health camp, alumni registration.
Rules: vary wording/length/links; no two rows identical; synthetic phish senders use non-`vit.ac.in` domains; official notices use `@vit.ac.in`; `language="en"`, `is_synthetic=True` is implied by source.

- [ ] **Step 4: Run tests, verify GREEN**

Run: `pytest tests/test_constructed.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add datasets/constructed/vit_messages.csv tests/test_constructed.py
git commit -m "feat(dataset): add constructed VIT phishing and hard-negative corpus"
```

---

## Task 4: Build, cluster, split, and write the dataset

**Files:**
- Create: `training/schema.py`
- Create: `training/build_dataset.py`
- Create: `datasets/processed/{train,val,test}.csv`
- Create: `datasets/manifest.json`
- Modify: `datasets/DATASET_CARD.md`
- Test: `tests/test_build_dataset.py`

**Interfaces:**
- Consumes: Task 1 paths, Task 2 `clean_message`, Task 3 CSV.
- Produces:
  - `REQUIRED_COLUMNS: list[str]` and `compose_text(df: pd.DataFrame) -> list[str]` in `training/schema.py`.
  - `load_nazario(paths: list[Path], limit: int, seed: int) -> list[dict]`
  - `load_spamassassin(dirs: list[Path], limit_per_group: dict[str, int], seed: int) -> list[dict]`
  - `load_constructed(path: Path) -> list[dict]`
  - `cluster_records(records: list[dict], threshold: float = 0.85) -> list[dict]`
  - `split_records(records: list[dict], n_splits: int = 7, seed: int = 42) -> list[dict]`
  - `build(out_dir: Path, raw_dir: Path, seed: int = 42) -> dict`

- [ ] **Step 1: Write the failing quality-gate tests**

```python
def test_every_row_has_schema_and_text(built):
    df = built
    assert list(df.columns) == REQUIRED_COLUMNS
    assert df.text.str.len().min() > 0
    assert set(df.label) == {0, 1}

def test_no_cluster_crosses_splits(built):
    assert (built.groupby("cluster_id").split.nunique() == 1).all()

def test_near_duplicates_do_not_cross_splits(built):
    train, test = built[built.split=="train"], built[built.split=="test"]
    vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3,5)).fit(train.text)
    sim = cosine_similarity(vec.transform(train.text), vec.transform(test.text)).max()
    assert sim <= 0.85

def test_test_set_is_large_and_balanced(built):
    test = built[built.split == "test"]
    assert len(test) >= 150
    assert test.label.value_counts().min() >= 60
    assert set(test.source) == {"nazario", "spamassassin", "constructed_vit"}

def test_url_is_not_a_shortcut(built):
    has_url = built.text.str.contains(r"http|www\.", case=False)
    assert (has_url == built.label.astype(bool)).mean() < 0.70

def test_hard_negatives_exist(built):
    legit = built[built.label == 0]
    hard = legit.text.str.contains(r"http") & legit.text.str.contains(
        r"suspend|verify|password|expir|last date|deadline", case=False)
    assert hard.mean() >= 0.25

def test_manifest_records_frozen_test_hash(built_manifest):
    assert len(built_manifest["test_sha256"]) == 64
```

- [ ] **Step 2: Run tests, verify RED**

Run: `pytest tests/test_build_dataset.py -v`
Expected: FAIL (`FileNotFoundError` / `ImportError`).

- [ ] **Step 3: Implement loaders and `cluster_records`**

`load_nazario`: `mailbox.mbox`, skip folder-internal subjects, `html_to_text`, `trim_quoted`, `trim_signature`, `redact_pii`, keep rows with `text >= 80` chars and ASCII ratio `>= 0.8`; sender = `parse_sender(msg["From"])`; `source="nazario"`, `label=1`, `category="phishing"`, `license="CC-BY-4.0"`, `is_synthetic=False`, `campaign=f"nazario:{year}"`, `id` = stable sha1 of source+subject+text.
`load_spamassassin`: iterate message files, decode, clean, drop empty; `label=0`, `category="legit"`, `source="spamassassin"`, `license="public-research"`, `is_synthetic=False`, `campaign=f"sa:{group}"`.
`load_constructed`: read CSV, map to schema, `source="constructed_vit"`, `license="project-owned"`, `is_synthetic=True`, `campaign=f"vit:{template_id}"`.
`cluster_records`: per label, TF-IDF char (3–5) cosine > 0.85, connected components; `cluster_id = f"{label}:{min_hash}"`. Per-label clustering keeps groups pure for stratification.

- [ ] **Step 4: Implement `split_records` per source**

For each `source`, run `StratifiedGroupKFold(n_splits=7, shuffle=True, random_state=seed)` on `(text, label, cluster_id)`; assign fold ids; pick fold 0 = val, fold 1 = test, rest = train. Concatenate sources, shuffle with seed. This guarantees every source appears in test.

- [ ] **Step 5: Implement `build` and write outputs**

Write `train.csv`, `val.csv`, `test.csv`; `datasets/manifest.json` with counts, source/licence table, seed, `test_sha256`; regenerate `DATASET_CARD.md` with: sources + licences + attribution, label definitions, class balance, split method, known biases (temporal gap, channel/length mix, synthetic VIT, SpamAssassin age), limitations, hash. Include a `--check` mode that recomputes the hash and exits non-zero on drift.

- [ ] **Step 6: Run the build**

Run: `python -m training.build_dataset --raw datasets/raw/external --out datasets/processed`
Expected: ~1,170 rows; prints per-source and per-split counts.

- [ ] **Step 7: Run tests, verify GREEN**

Run: `pytest tests/test_build_dataset.py -v`
Expected: PASS. If the URL-shortcut gate fails, increase `hard_ham` to 200 and rebuild before changing the threshold.

- [ ] **Step 8: Commit**

```bash
git add training/schema.py training/build_dataset.py datasets/processed datasets/manifest.json datasets/DATASET_CARD.md tests/test_build_dataset.py
git commit -m "feat(dataset): build grouped-split pilot dataset with quality gates"
```

---

## Task 5: Retrain and fix the model artifacts

**Files:**
- Modify: `training/train.py`, `training/train_baseline.py`
- Modify: `backend/requirements.txt`, `training/requirements.txt`
- Modify: `backend/explainability.py` (version guard only)
- Test: `tests/test_model_metadata.py`

**Interfaces:**
- Consumes: `training.schema.compose_text`, processed CSVs.
- Produces: `models/core_model.pkl`, `models/tfidf_vectorizer.pkl`, `models/baseline_model.pkl`, `models/baseline_vectorizer.pkl`, `models/metadata.json` with `sklearn_version`, `dataset_sha256`, `trained_at`, `train_rows`, `val_rows`, `sources`.

- [ ] **Step 1: Write the failing tests**

```python
def test_metadata_matches_installed_sklearn():
    meta = json.loads(Path("models/metadata.json").read_text())
    assert meta["sklearn_version"] == sklearn.__version__

def test_metadata_records_dataset_hash():
    meta = json.loads(Path("models/metadata.json").read_text())
    assert meta["dataset_sha256"] == hashlib.sha256(Path("datasets/processed/test.csv").read_bytes()).hexdigest()

def test_core_beats_baseline_on_test_f1():
    metrics = json.loads(Path("reports/metrics.json").read_text())
    assert metrics["core_model"]["f1"] >= metrics["baseline"]["f1"]
```

- [ ] **Step 2: Run tests, verify RED**

Run: `pytest tests/test_model_metadata.py -v`
Expected: FAIL (missing keys / stale pickles).

- [ ] **Step 3: Update training scripts**

Use `compose_text` (subject + body). Record metadata. Pin `scikit-learn==1.6.1`, `joblib>=1.3`. In `get_model_and_vec`, compare `metadata["sklearn_version"]` with `sklearn.__version__` and raise a clear `RuntimeError` on mismatch.

- [ ] **Step 4: Retrain**

Run: `python -m training.train_baseline && python -m training.train`
Expected: artifacts rewritten; validation F1 printed; no version warnings.

- [ ] **Step 5: Run tests, verify GREEN (includes the 13 previously failing tests)**

Run: `pytest tests/ -v`
Expected: `test_api.py`, `test_model.py`, `test_integration.py` now pass; no `InconsistentVersionWarning`.

- [ ] **Step 6: Commit**

```bash
git add training/train.py training/train_baseline.py backend/requirements.txt training/requirements.txt backend/explainability.py models tests/test_model_metadata.py
git commit -m "fix(model): retrain on pilot dataset and pin sklearn version"
```

---

## Task 6: Honest evaluation report

**Files:**
- Modify: `training/evaluate.py`
- Modify: `reports/evaluation_report.md`, `reports/metrics.json`
- Test: `tests/test_evaluation.py`

**Interfaces:**
- Consumes: processed test CSV + model artifacts.
- Produces: `metrics.json` with `overall`, `baseline`, `core_model`, `per_source` (`nazario`, `spamassassin`, `constructed_vit`), `dataset_sha256`.

- [ ] **Step 1: Write the failing tests**

```python
def test_metrics_include_per_source_breakdown():
    m = json.loads(Path("reports/metrics.json").read_text())
    assert set(m["per_source"]) == {"nazario", "spamassassin", "constructed_vit"}
    for row in m["per_source"].values():
        assert {"precision","recall","f1","false_positive_rate","n"} <= set(row)

def test_report_states_limitations_and_synthetic_data():
    text = Path("reports/evaluation_report.md").read_text().lower()
    assert "limitation" in text
    assert "synthetic" in text
    assert "100%" not in text
```

- [ ] **Step 2: Run tests, verify RED**

Run: `pytest tests/test_evaluation.py -v`
Expected: FAIL (missing `per_source` / overclaim).

- [ ] **Step 3: Implement per-source evaluation and rewrite the report**

Compute overall and per-source metrics; include confusion matrices; report the URL-single-feature accuracy as a sanity baseline; state the temporal gap (SpamAssassin 2002–03 vs Nazario 2022–24), balanced-test caveat, synthetic VIT caveat, and that the pilot is English-only.

- [ ] **Step 4: Run evaluation and tests, verify GREEN**

Run: `python -m training.evaluate && pytest tests/test_evaluation.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add training/evaluate.py reports tests/test_evaluation.py
git commit -m "docs(reports): per-source evaluation with honest limitations"
```

---

## Task 7: Fixtures, docs, and full verification

**Files:**
- Create: `datasets/fixtures/demo_messages.csv`
- Modify: `README.md`, `models/README.md`, `.gitignore`
- Test: full suite.

- [ ] **Step 1: Move the old dataset to fixtures**

Copy `datasets/raw/raw_messages.csv` → `datasets/fixtures/demo_messages.csv`; add a header note in `DATASET_CARD.md` that it is demo-only. Remove the old processed CSVs (now replaced).

- [ ] **Step 2: Update docs**

`README.md`: setup (`pip install -r backend/requirements.txt`), fetch (`python -m training.fetch_sources`), build, train, evaluate, test. `DATASET_CARD.md`: sources, licences, attribution, limitations, hash. `.gitignore`: `datasets/raw/external/`.

- [ ] **Step 3: Full verification**

Run: `pytest tests/ -v`
Expected: all pass; no warnings from scikit-learn version mismatch.

Run: `python -m training.build_dataset --check`
Expected: exit 0, hash matches.

Run: `python run.py` and POST the VIT suspension sample to `/api/analyse`
Expected: `High Risk`, defanged link, explanations present. POST a genuine VIT fee reminder
Expected: not `High Risk`.

- [ ] **Step 4: Commit**

```bash
git add datasets/fixtures README.md models/README.md .gitignore
git commit -m "docs(dataset): document pilot dataset, licences, and setup"
```

---

## Self-Review

- **Spec coverage:** labelled dataset (Task 1–4), preprocessing (Task 2), baseline + core model (Task 5), held-out precision/recall/confusion matrix (Task 6), sender field (schema), safety (unchanged, still tested), honest limitations (Task 6–7).
- **Leakage:** per-label clustering + per-source grouped split + hash + `--check`.
- **Shortcut:** explicit URL-shortcut gate and hard-negative gate.
- **Deferred (not this plan):** SMS source, multilingual, Stage 2 features, composite-score math, UI highlighting. These stay in the backlog.
