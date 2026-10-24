"""
test_model_metadata.py
Guards against the stale-pickle failure: the artifacts must be trained by the
installed scikit-learn and must record the exact dataset they were trained on.
"""

import hashlib
import json
from pathlib import Path

import joblib
import pandas as pd
import pytest
import sklearn

from training.normalise import normalise_text
from training.schema import compose_text

MODELS = Path("models")
PROCESSED = Path("datasets/processed")


@pytest.fixture(scope="module")
def metadata() -> dict:
    return json.loads((MODELS / "metadata.json").read_text(encoding="utf-8"))


def test_metadata_matches_installed_sklearn(metadata):
    assert metadata["sklearn_version"] == sklearn.__version__


def test_metadata_records_frozen_dataset_hash(metadata):
    digest = hashlib.sha256((PROCESSED / "test.csv").read_bytes()).hexdigest()
    assert metadata["dataset_sha256"] == digest


def test_metadata_records_counts_and_sources(metadata):
    assert metadata["train_rows"] == len(pd.read_csv(PROCESSED / "train.csv"))
    assert metadata["val_rows"] == len(pd.read_csv(PROCESSED / "val.csv"))
    assert set(metadata["sources"]) == {"nazario", "spamassassin", "constructed_vit"}
    assert metadata["decision_threshold"] > 0


def test_model_artifacts_load_and_predict(metadata):
    model = joblib.load(MODELS / "core_model.pkl")
    vectorizer = joblib.load(MODELS / "tfidf_vectorizer.pkl")

    phishing = pd.DataFrame([{
        "subject": "URGENT: VIT account suspended",
        "text": "Your VTOP account will be suspended in 24 hours. Confirm your password at http://vit-fake.info/login",
    }])
    legit = pd.DataFrame([{
        "subject": "Winter timetable published",
        "text": "Dear Student, the timetable for Winter Semester 2026-27 is on VTOP. Review your slots.",
    }])

    phish_prob = model.predict_proba(
        vectorizer.transform([normalise_text(text) for text in compose_text(phishing)])
    )[0, 1]
    legit_prob = model.predict_proba(
        vectorizer.transform([normalise_text(text) for text in compose_text(legit)])
    )[0, 1]

    assert phish_prob > 0.50
    assert legit_prob < 0.50
    assert metadata["model_type"] == "LogisticRegression"
