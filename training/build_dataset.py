"""
build_dataset.py
Builds the PhishGuard pilot dataset from the fetched public corpora plus the
constructed VIT corpus.

Pipeline: load -> clean -> per-label near-duplicate clustering -> per-source
grouped split -> write CSVs, manifest, and DATASET_CARD.md.

Usage:
    python -m training.build_dataset
    python -m training.build_dataset --check
"""

from __future__ import annotations

import argparse
import email
import hashlib
import json
import mailbox
import random
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix
from scipy.sparse.csgraph import connected_components
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.model_selection import GroupKFold, StratifiedGroupKFold

from training.email_clean import clean_message, decode_payload, parse_sender
from training.schema import REQUIRED_COLUMNS, compose_text

SEED = 42
NAZARIO_LIMIT = 500
SA_LIMITS = {"easy_ham": 250, "easy_ham_2": 150, "hard_ham": 150}
SIMILARITY_THRESHOLD = 0.75
N_SPLITS = 7

URL_RE = re.compile(r"https?://|www\.", re.I)
HARD_NEG_RE = re.compile(
    r"suspend|verify|password|otp|login|account|immediately|expir|"
    r"last date|deadline|click|renew|registration|security",
    re.I,
)


def _ascii_ratio(text: str) -> float:
    return sum(char.isascii() for char in text) / max(len(text), 1)


def _dedupe_key(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()[:400]


def _stable_id(prefix: str, *parts: str) -> str:
    payload = "|".join(str(part) for part in parts)
    return f"{prefix}-{hashlib.sha1(payload.encode('utf-8')).hexdigest()[:12]}"


def _with_links(cleaned: dict) -> str:
    """Append HTML hrefs to the text so links survive HTML-to-text extraction."""
    text = cleaned["text"]
    hrefs = " ".join(
        link["href"] for link in cleaned.get("links", []) if link.get("href")
    )
    if hrefs and hrefs not in text:
        text = f"{text}\n{hrefs}"
    return text


def _message_body(msg: email.message.Message) -> str:
    """Return the best text body: prefer the longest text/plain, fall back to HTML."""
    if not msg.is_multipart():
        return decode_payload(msg)

    plain: list[str] = []
    html: list[str] = []
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        content_type = part.get_content_type()
        if content_type == "text/plain":
            plain.append(decode_payload(part))
        elif content_type == "text/html":
            html.append(decode_payload(part))
    if plain:
        return max(plain, key=len)
    if html:
        return max(html, key=len)
    return ""


def mask_sender(raw: str | None) -> str | None:
    """Keep only the domain of a real sender: 'Name <a@b.com>' -> '***@b.com'."""
    _, address = parse_sender(raw)
    if not address or "@" not in address:
        return None
    return f"***@{address.split('@')[-1]}"


def load_nazario(paths: list[Path], limit: int = NAZARIO_LIMIT, seed: int = SEED) -> list[dict]:
    """Load real phishing emails from Nazario mbox files."""
    candidates: list[dict] = []
    seen: set[str] = set()

    for path in paths:
        year = path.name.split("-")[-1]
        try:
            box = mailbox.mbox(str(path))
        except Exception as exc:  # noqa: BLE001 - a bad source must not abort the build
            print(f"[warn] could not open {path}: {exc}")
            continue

        for msg in box:
            try:
                subject = msg.get("Subject")
                if subject and "FOLDER INTERNAL DATA" in subject.upper():
                    continue
                cleaned = clean_message(subject, _message_body(msg))
                text = _with_links(cleaned)
                if len(text) < 80 or _ascii_ratio(text) < 0.8:
                    continue
                key = _dedupe_key(text)
                if key in seen:
                    continue
                seen.add(key)
                sender = msg.get("From")
                candidates.append({
                    "id": _stable_id("nazario", path.name, str(subject), text),
                    "text": text,
                    "subject": cleaned["subject"],
                    "sender": mask_sender(sender),
                    "label": 1,
                    "category": "phishing",
                    "source": "nazario",
                    "campaign": f"nazario:{year}",
                    "cluster_id": "",
                    "language": "en",
                    "is_synthetic": False,
                    "license": "CC-BY-4.0",
                    "split": "",
                    "notes": ",".join(cleaned["warnings"]),
                })
            except Exception:  # noqa: BLE001 - skip a single malformed message
                continue

    random.Random(seed).shuffle(candidates)
    return candidates[:limit]


def load_spamassassin(
    dirs: dict[str, Path],
    limits: dict[str, int] | None = None,
    seed: int = SEED,
) -> list[dict]:
    """Load real legitimate/hard-negative emails from the SpamAssassin corpus."""
    limits = limits or SA_LIMITS
    rng = random.Random(seed)
    records: list[dict] = []

    for group, directory in dirs.items():
        if not directory.exists():
            raise FileNotFoundError(f"missing SpamAssassin group: {directory}")
        candidates: list[dict] = []
        seen: set[str] = set()
        for path in sorted(directory.iterdir()):
            if not path.is_file() or not path.name[:1].isdigit():
                continue
            try:
                with path.open("rb") as handle:
                    msg = email.message_from_binary_file(handle)
                cleaned = clean_message(msg.get("Subject"), _message_body(msg))
                text = _with_links(cleaned)
                if len(text) < 40 or _ascii_ratio(text) < 0.8:
                    continue
                key = _dedupe_key(text)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append({
                    "id": _stable_id("sa", group, path.name, text),
                    "text": text,
                    "subject": cleaned["subject"],
                    "sender": mask_sender(msg.get("From")),
                    "label": 0,
                    "category": "legit",
                    "source": "spamassassin",
                    "campaign": f"sa:{group}",
                    "cluster_id": "",
                    "language": "en",
                    "is_synthetic": False,
                    "license": "public-research",
                    "split": "",
                    "notes": group,
                })
            except Exception:  # noqa: BLE001
                continue

        rng.shuffle(candidates)
        chosen = candidates[: limits.get(group, 0)]
        print(f"[load] spamassassin/{group}: {len(chosen)} of {len(candidates)} candidates")
        records.extend(chosen)

    return records


def load_constructed(path: Path) -> list[dict]:
    """Load the hand-authored VIT corpus. Variants share a template cluster."""
    df = pd.read_csv(path)
    records: list[dict] = []
    for row in df.to_dict("records"):
        cleaned = clean_message(row.get("subject"), row.get("text"))
        sender = row.get("sender")
        notes = row.get("notes")
        records.append({
            "id": str(row["id"]),
            "text": cleaned["text"],
            "subject": cleaned["subject"],
            "sender": str(sender) if pd.notna(sender) else None,
            "label": int(row["label"]),
            "category": str(row["category"]),
            "source": "constructed_vit",
            "campaign": f"vit:{row['template_id']}",
            "cluster_id": f"vit:{row['template_id']}",
            "language": str(row["language"]),
            "is_synthetic": True,
            "license": "project-owned",
            "split": "",
            "notes": str(notes) if pd.notna(notes) else "",
        })
    return records


def cluster_records(records: list[dict], threshold: float = SIMILARITY_THRESHOLD) -> list[dict]:
    """Assign a cluster_id to public rows using per-label char n-gram similarity."""
    df = pd.DataFrame(records)
    public = df[df["cluster_id"].fillna("") == ""]

    for label, group in public.groupby("label"):
        texts = compose_text(group)
        vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1)
        matrix = vectorizer.fit_transform(texts)
        similarity = cosine_similarity(matrix)
        adjacency = similarity > threshold
        np.fill_diagonal(adjacency, False)
        _, components = connected_components(csr_matrix(adjacency), directed=False)

        for component in range(int(components.max()) + 1):
            idxs = group.index[components == component]
            first_id = sorted(df.loc[idxs, "id"])[0]
            df.loc[idxs, "cluster_id"] = f"{label}:{first_id}"

    df["cluster_id"] = df["cluster_id"].fillna("")
    missing = df[df["cluster_id"] == ""]
    for index, row in missing.iterrows():
        df.loc[index, "cluster_id"] = f"{row['label']}:{row['id']}"

    return df.to_dict("records")


def split_records(records: list[dict], n_splits: int = N_SPLITS, seed: int = SEED) -> pd.DataFrame:
    """Split each source independently so every source appears in test."""
    df = pd.DataFrame(records)
    frames: list[pd.DataFrame] = []

    for source, group in df.groupby("source", sort=True):
        group = group.reset_index(drop=True)
        n_groups = int(group["cluster_id"].nunique())
        folds = min(n_splits, n_groups)
        if folds < 3:
            raise ValueError(f"source {source!r} has too few clusters ({n_groups}) to split")

        if group["label"].nunique() == 1:
            splitter = GroupKFold(n_splits=folds, shuffle=True, random_state=seed)
        else:
            splitter = StratifiedGroupKFold(n_splits=folds, shuffle=True, random_state=seed)

        fold_of: dict[int, int] = {}
        for fold, (_, held_out) in enumerate(
            splitter.split(group, group["label"], group["cluster_id"])
        ):
            for index in held_out:
                fold_of[int(index)] = fold

        if len(fold_of) != len(group):
            raise ValueError(f"split coverage mismatch for source {source!r}")

        group["split"] = [
            "val" if fold_of[index] == 0 else "test" if fold_of[index] == 1 else "train"
            for index in range(len(group))
        ]
        if set(group["split"]) != {"train", "val", "test"}:
            raise ValueError(f"source {source!r} did not produce all three splits")
        frames.append(group)

    combined = pd.concat(frames, ignore_index=True)
    return combined.sample(frac=1.0, random_state=seed).reset_index(drop=True)


def _max_cross_split_similarity(df: pd.DataFrame) -> float:
    train = df[df["split"] == "train"]
    test = df[df["split"] == "test"]
    if train.empty or test.empty:
        return 0.0
    vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1)
    train_matrix = vectorizer.fit_transform(compose_text(train))
    test_matrix = vectorizer.transform(compose_text(test))
    return float(cosine_similarity(train_matrix, test_matrix).max())


def repair_leakage(
    df: pd.DataFrame,
    threshold: float = 0.85,
    seed: int = SEED,
    max_iterations: int = 6,
) -> pd.DataFrame:
    """
    Merge any same-source, same-label clusters that still cross a split, then
    re-split. This targets only leaking pairs instead of over-merging the corpus.
    """
    for _ in range(max_iterations):
        train = df[df["split"] == "train"]
        test = df[df["split"] == "test"]
        if train.empty or test.empty:
            return df

        vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1)
        train_matrix = vectorizer.fit_transform(compose_text(train))
        test_matrix = vectorizer.transform(compose_text(test))
        similarity = cosine_similarity(train_matrix, test_matrix)
        row_indices, column_indices = np.where(similarity > threshold)

        merges: dict[str, str] = {}
        for row, column in zip(row_indices, column_indices):
            train_row = train.iloc[row]
            test_row = test.iloc[column]
            if train_row["cluster_id"] == test_row["cluster_id"]:
                continue
            if (
                train_row["source"] != test_row["source"]
                or train_row["label"] != test_row["label"]
            ):
                continue
            old, new = sorted([train_row["cluster_id"], test_row["cluster_id"]])
            merges[old] = new

        if not merges:
            break

        changed = True
        while changed:
            changed = False
            for old, new in list(merges.items()):
                mask = df["cluster_id"] == old
                if mask.any():
                    df.loc[mask, "cluster_id"] = new
                    changed = True

        df = split_records(df.to_dict("records"), seed=seed)

    return df


def _stats(df: pd.DataFrame) -> dict[str, Any]:
    has_url = df["text"].str.contains(URL_RE)
    legit = df[df["label"] == 0]
    hard = legit["text"].str.contains(r"https?://", case=False) & legit["text"].str.contains(
        HARD_NEG_RE
    )

    per_source: dict[str, dict[str, int]] = {}
    for source, group in df.groupby("source"):
        counts = group["split"].value_counts().to_dict()
        per_source[str(source)] = {
            "train": int(counts.get("train", 0)),
            "val": int(counts.get("val", 0)),
            "test": int(counts.get("test", 0)),
            "total": int(len(group)),
        }

    test = df[df["split"] == "test"]
    return {
        "total_rows": int(len(df)),
        "class_balance": {
            "legit": int((df["label"] == 0).sum()),
            "phishing": int((df["label"] == 1).sum()),
        },
        "test_class_balance": {
            "legit": int((test["label"] == 0).sum()),
            "phishing": int((test["label"] == 1).sum()),
        },
        "per_source": per_source,
        "licenses": df.groupby("source")["license"].first().to_dict(),
        "url_shortcut_accuracy": float((has_url == df["label"].astype(bool)).mean()),
        "hard_negative_rate": float(hard.mean()) if len(legit) else 0.0,
        "max_cross_split_similarity": _max_cross_split_similarity(df),
        "n_clusters": int(df["cluster_id"].nunique()),
        "synthetic_rows": int(df["is_synthetic"].sum()),
    }


def write_card(manifest: dict[str, Any], path: Path) -> None:
    per_source_rows = "\n".join(
        f"| `{source}` | {values['total']} | {values['train']} | {values['val']} | "
        f"{values['test']} | `{manifest['licenses'].get(source, 'unknown')}` |"
        for source, values in sorted(manifest["per_source"].items())
    )
    split_rows = "\n".join(
        f"| {split} | {sum(values[split] for values in manifest['per_source'].values())} |"
        for split in ("train", "val", "test")
    )

    card = f"""# Dataset Card — PhishGuard Pilot Dataset

## 1. Summary

A multilingual-ready (English-only in this pilot) binary dataset for detecting
phishing messages aimed at university students, with the Q5 VIT account-suspension
scenario as the anchor case. It combines real public phishing email, real public
legitimate email including hard negatives, and a hand-authored VIT corpus.

- **Rows:** {manifest['total_rows']}
- **Classes:** {manifest['class_balance']['legit']} legitimate / {manifest['class_balance']['phishing']} phishing
- **Clusters:** {manifest['n_clusters']} near-duplicate groups
- **Synthetic rows:** {manifest['synthetic_rows']} (hand-authored VIT corpus)
- **Seed:** {manifest['seed']}
- **Frozen test SHA-256:** `{manifest['test_sha256']}`

## 2. Sources and licences

| Source | Rows | Train | Val | Test | Licence |
|---|---:|---:|---:|---:|---|
{per_source_rows}

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
{', '.join(REQUIRED_COLUMNS)}
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
{split_rows}

## 6. Quality gates measured at build time

| Gate | Value | Target |
|---|---:|---|
| URL-only shortcut accuracy | {manifest['url_shortcut_accuracy']:.4f} | < 0.70 |
| Hard-negative share of legit class | {manifest['hard_negative_rate']:.4f} | >= 0.25 |
| Max test-to-train char similarity | {manifest['max_cross_split_similarity']:.4f} | <= 0.85 |

The URL shortcut gate is the important one: in the previous 126-row dataset,
"contains a URL" predicted the label with 100% accuracy. This dataset deliberately
includes legitimate messages with links and security vocabulary.

## 7. Known biases and limitations

- **Temporal gap.** SpamAssassin ham is from 2002–2003; Nazario phishing is from
  2022–2024. The model may learn era-specific style. Report per-source results.
- **Label distribution.** The pilot is roughly balanced overall
  ({manifest['class_balance']['legit']} legitimate / {manifest['class_balance']['phishing']} phishing),
  but the test set is {manifest['test_class_balance']['legit']} legitimate /
  {manifest['test_class_balance']['phishing']} phishing because the public sources are
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
"""
    path.write_text(card, encoding="utf-8")


def build(
    raw_dir: Path = Path("datasets/raw/external"),
    out_dir: Path = Path("datasets/processed"),
    seed: int = SEED,
    nazario_limit: int = NAZARIO_LIMIT,
    sa_limits: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Build the dataset and write splits, manifest, and card."""
    raw_dir = Path(raw_dir)
    out_dir = Path(out_dir)

    nazario_paths = sorted((raw_dir / "nazario").glob("phishing-*"))
    if not nazario_paths:
        raise FileNotFoundError(f"no Nazario mbox files under {raw_dir / 'nazario'}")

    sa_dirs = {
        group: raw_dir / "spamassassin" / group
        for group in ("easy_ham", "easy_ham_2", "hard_ham")
    }

    print("[build] loading sources")
    records = load_nazario(nazario_paths, limit=nazario_limit, seed=seed)
    print(f"[load] nazario: {len(records)}")
    records.extend(load_spamassassin(sa_dirs, limits=sa_limits, seed=seed))
    records.extend(load_constructed(Path("datasets/constructed/vit_messages.csv")))
    print(f"[build] {len(records)} rows before clustering")

    records = cluster_records(records)
    df = split_records(records, seed=seed)
    df = repair_leakage(df, threshold=0.85, seed=seed)

    max_similarity = _max_cross_split_similarity(df)
    if max_similarity > 0.85:
        raise RuntimeError(
            "leakage repair failed: max cross-split similarity "
            f"{max_similarity:.4f} > 0.85"
        )

    out_dir.mkdir(parents=True, exist_ok=True)
    for split in ("train", "val", "test"):
        part = df[df["split"] == split][REQUIRED_COLUMNS]
        part.to_csv(out_dir / f"{split}.csv", index=False)
        print(f"[write] {split}.csv: {len(part)} rows")

    stats = _stats(df)
    stats["seed"] = seed
    stats["test_sha256"] = hashlib.sha256((out_dir / "test.csv").read_bytes()).hexdigest()
    stats["generated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")

    manifest_path = out_dir.parent / "manifest.json"
    manifest_path.write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")
    write_card(stats, out_dir.parent / "DATASET_CARD.md")
    print(f"[write] {manifest_path}")
    print(f"[write] {out_dir.parent / 'DATASET_CARD.md'}")
    print(
        f"[stats] url_shortcut={stats['url_shortcut_accuracy']:.3f} "
        f"hard_neg={stats['hard_negative_rate']:.3f} "
        f"max_sim={stats['max_cross_split_similarity']:.3f}"
    )
    return stats


def check(out_dir: Path = Path("datasets/processed")) -> int:
    """Verify the frozen test set has not changed since the manifest was written."""
    out_dir = Path(out_dir)
    manifest_path = out_dir.parent / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    actual = hashlib.sha256((out_dir / "test.csv").read_bytes()).hexdigest()
    expected = manifest.get("test_sha256")
    if actual != expected:
        print(f"[FAIL] test hash mismatch: expected {expected}, got {actual}")
        return 1
    print(f"[ok] frozen test hash matches ({actual[:12]}...)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", default="datasets/raw/external", type=Path)
    parser.add_argument("--out", default="datasets/processed", type=Path)
    parser.add_argument("--seed", default=SEED, type=int)
    parser.add_argument("--nazario-limit", default=NAZARIO_LIMIT, type=int)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    if args.check:
        return check(args.out)

    build(raw_dir=args.raw, out_dir=args.out, seed=args.seed, nazario_limit=args.nazario_limit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
