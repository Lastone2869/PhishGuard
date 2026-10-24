"""
schema.py
The single definition of the dataset schema shared by the builder, the training
scripts, and the quality tests.
"""

from __future__ import annotations

import pandas as pd

REQUIRED_COLUMNS = [
    "id",
    "text",
    "subject",
    "sender",
    "label",
    "category",
    "source",
    "campaign",
    "cluster_id",
    "language",
    "is_synthetic",
    "license",
    "split",
    "notes",
]

LABEL_NAMES = {0: "legitimate", 1: "phishing"}


def compose_text(df: pd.DataFrame) -> list[str]:
    """Return the model input: subject line plus body, with blanks collapsed."""
    subject = df["subject"].fillna("").astype(str).str.strip()
    body = df["text"].fillna("").astype(str).str.strip()
    return (subject + "\n" + body).str.strip().tolist()
