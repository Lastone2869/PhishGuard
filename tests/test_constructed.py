"""
test_constructed.py
Quality gates for the hand-authored VIT scenario corpus.
"""

import re
from pathlib import Path

import pandas as pd

PATH = Path("datasets/constructed/vit_messages.csv")
COLUMNS = [
    "id", "template_id", "subject", "text", "sender",
    "label", "category", "language", "notes",
]


def load() -> pd.DataFrame:
    return pd.read_csv(PATH)


def test_constructed_schema_and_counts():
    df = load()
    assert list(df.columns) == COLUMNS
    assert len(df) >= 240
    assert set(df.label) == {0, 1}
    assert df.template_id.nunique() >= 120
    assert (df.groupby("template_id").size() >= 2).all()


def test_constructed_rows_are_complete_and_unique():
    df = load()
    assert df.id.is_unique
    assert df.text.str.len().min() >= 60
    assert df.subject.str.len().min() > 0
    assert df.text.str.strip().nunique() == len(df)
    assert set(df.language) == {"en"}


def test_constructed_categories_match_labels():
    df = load()
    assert set(df[df.label == 0].category) == {"legit"}
    assert set(df[df.label == 1].category) == {"phishing"}


def test_constructed_has_hard_negatives():
    legit = load()
    legit = legit[legit.label == 0]
    hard = legit.text.str.contains(r"https?://", case=False) & legit.text.str.contains(
        r"suspend|verify|password|expir|last date|deadline|registration|renew",
        case=False,
    )
    assert hard.sum() >= 30


def test_constructed_phish_senders_are_not_official():
    phish = load()
    phish = phish[phish.label == 1]
    assert not phish.sender.str.contains(r"@vit\.ac\.in\b", case=False, regex=True).any()


def test_constructed_legit_has_official_senders():
    legit = load()
    legit = legit[legit.label == 0]
    assert legit.sender.str.contains(r"@vit\.ac\.in\b", case=False, regex=True).sum() >= 30


def test_constructed_link_coverage_is_realistic():
    df = load()
    has_url = df.text.str.contains(r"https?://", case=False)
    assert has_url[df.label == 1].mean() >= 0.80
    assert has_url[df.label == 0].mean() >= 0.60


def test_constructed_templates_have_varied_variants():
    df = load()
    for template_id, group in df.groupby("template_id"):
        assert group.text.nunique() == len(group), f"duplicate variant in {template_id}"
        assert group.sender.nunique() >= 1
