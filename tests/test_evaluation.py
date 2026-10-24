"""
test_evaluation.py
The evaluation artefact must be machine-readable, per-source, and honest about
the pilot's limitations. It must not repeat the previous perfect-score claim.
"""

import hashlib
import json
from pathlib import Path

METRICS = Path("reports/metrics.json")
REPORT = Path("reports/evaluation_report.md")


def test_metrics_include_per_source_breakdown():
    metrics = json.loads(METRICS.read_text(encoding="utf-8"))
    assert set(metrics["per_source"]) == {"nazario", "spamassassin", "constructed_vit"}
    assert sum(row["n"] for row in metrics["per_source"].values()) == metrics["test_sample_count"]
    for row in metrics["per_source"].values():
        assert {"precision", "recall", "f1", "false_positive_rate", "n"} <= set(row)


def test_metrics_record_frozen_dataset_hash():
    metrics = json.loads(METRICS.read_text(encoding="utf-8"))
    digest = hashlib.sha256(Path("datasets/processed/test.csv").read_bytes()).hexdigest()
    assert metrics["dataset_sha256"] == digest


def test_overall_metrics_are_sane():
    metrics = json.loads(METRICS.read_text(encoding="utf-8"))
    for name in ("baseline", "core_model"):
        assert 0.0 <= metrics[name]["f1"] <= 1.0
    assert metrics["core_model"]["f1"] >= metrics["baseline"]["f1"] - 0.05
    assert metrics["core_model"]["f1"] >= 0.80
    assert metrics["baseline"]["f1"] >= 0.80
    assert metrics["url_shortcut_accuracy"] < 0.70


def test_verdict_evaluation_has_no_vit_high_risk_false_positives():
    metrics = json.loads(METRICS.read_text(encoding="utf-8"))
    assert "verdict_evaluation" in metrics
    vit = metrics["verdict_evaluation"]["per_source"]["constructed_vit"]
    assert vit["high_risk_fp"] == 0
    assert vit["flagged_fp_rate"] <= 0.15


def test_report_states_limitations_and_synthetic_data():
    text = REPORT.read_text(encoding="utf-8").lower()
    assert "limitation" in text
    assert "synthetic" in text
    assert "per-source" in text or "per source" in text
    assert "100%" not in text
