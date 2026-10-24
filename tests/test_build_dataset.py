"""
test_build_dataset.py
Quality gates for the built pilot dataset. These tests run against the committed
processed split files, so they also work offline in CI.
"""

import hashlib
import json
from pathlib import Path

import pandas as pd
import pytest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from training.build_dataset import load_constructed, mask_sender
from training.schema import REQUIRED_COLUMNS, compose_text

PROCESSED = Path("datasets/processed")
MANIFEST = Path("datasets/manifest.json")


@pytest.fixture(scope="module")
def built() -> pd.DataFrame:
    frames = [pd.read_csv(PROCESSED / f"{split}.csv") for split in ("train", "val", "test")]
    return pd.concat(frames, ignore_index=True)


@pytest.fixture(scope="module")
def manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def test_compose_text_joins_subject_and_body():
    df = pd.DataFrame({"subject": ["Hi", None, "  "], "text": ["Body", "Only", "Text"]})
    assert compose_text(df) == ["Hi\nBody", "Only", "Text"]


def test_load_constructed_maps_schema():
    rows = load_constructed(Path("datasets/constructed/vit_messages.csv"))
    assert len(rows) == 240
    assert {row["source"] for row in rows} == {"constructed_vit"}
    assert {row["license"] for row in rows} == {"project-owned"}
    assert all(row["is_synthetic"] for row in rows)


def test_mask_sender_keeps_only_domain():
    assert mask_sender('"VIT Helpdesk" <HelpDesk@VIT.ac.in>') == "***@vit.ac.in"
    assert mask_sender("") is None
    assert mask_sender(None) is None


def test_every_row_has_schema_and_text(built):
    assert list(built.columns) == REQUIRED_COLUMNS
    assert built.text.fillna("").str.len().min() > 0
    assert set(built.label) == {0, 1}
    assert set(built.language) == {"en"}


def test_splits_are_disjoint_and_complete(built):
    assert set(built.split) == {"train", "val", "test"}
    assert built.id.is_unique
    assert built.groupby("id").split.nunique().max() == 1


def test_no_cluster_crosses_splits(built):
    assert (built.groupby("cluster_id").split.nunique() == 1).all()
    assert (built.groupby("cluster_id").label.nunique() == 1).all()


def test_near_duplicates_do_not_cross_splits(built):
    train = built[built.split == "train"]
    test = built[built.split == "test"]
    vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1)
    train_matrix = vectorizer.fit_transform(compose_text(train))
    test_matrix = vectorizer.transform(compose_text(test))
    assert cosine_similarity(train_matrix, test_matrix).max() <= 0.85


def test_test_set_is_large_balanced_and_covers_every_source(built):
    test = built[built.split == "test"]
    assert len(test) >= 150
    assert test.label.value_counts().min() >= 60
    assert set(test.source) == {"nazario", "spamassassin", "constructed_vit"}


def test_url_is_not_a_shortcut(built):
    has_url = built.text.str.contains(r"http|www\.", case=False)
    assert (has_url == built.label.astype(bool)).mean() < 0.70


def test_hard_negatives_exist(built):
    legit = built[built.label == 0]
    hard = legit.text.str.contains(r"https?://", case=False) & legit.text.str.contains(
        r"suspend|verify|password|otp|login|account|immediately|expir|"
        r"last date|deadline|click|renew|registration|security",
        case=False,
    )
    assert hard.mean() >= 0.25


def test_public_senders_are_masked(built):
    public = built[built.source.isin(["nazario", "spamassassin"])]
    present = public.sender.dropna().astype(str)
    assert present.str.match(r"^\*\*\*@").all()


def test_manifest_records_frozen_test_hash(manifest):
    digest = hashlib.sha256((PROCESSED / "test.csv").read_bytes()).hexdigest()
    assert manifest["test_sha256"] == digest
    assert manifest["seed"] == 42
    assert set(manifest["per_source"]) == {"nazario", "spamassassin", "constructed_vit"}
