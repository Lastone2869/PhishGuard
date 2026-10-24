"""
test_fixtures.py
The legacy demo rows must stay out of the training/evaluation splits.
"""

import pandas as pd

FIXTURES = "datasets/fixtures/demo_messages.csv"
PROCESSED = "datasets/processed"


def test_demo_fixtures_exist_and_cover_both_classes():
    df = pd.read_csv(FIXTURES)
    assert len(df) >= 100
    assert set(df.label) == {0, 1}
    assert {"text", "label", "sender"} <= set(df.columns)


def test_fixtures_do_not_leak_into_splits():
    fixtures = set(pd.read_csv(FIXTURES).text.astype(str))
    built = pd.concat(
        [pd.read_csv(f"{PROCESSED}/{split}.csv") for split in ("train", "val", "test")],
        ignore_index=True,
    )
    assert not (set(built.text.astype(str)) & fixtures)
