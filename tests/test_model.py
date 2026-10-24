"""
test_model.py
Tests ML model artifact integrity and inference on phishing vs legitimate samples.
"""

import os
import joblib
from training.normalise import normalise_text

def test_model_artifacts_exist():
    assert os.path.exists("models/core_model.pkl")
    assert os.path.exists("models/tfidf_vectorizer.pkl")
    assert os.path.exists("models/metadata.json")

def test_core_model_phishing_detection():
    model = joblib.load("models/core_model.pkl")
    vec = joblib.load("models/tfidf_vectorizer.pkl")

    phish_msg = "URGENT: Your student account will be suspended within 24 hours. Verify password at http://vit-fake.com"
    norm = normalise_text(phish_msg)
    X = vec.transform([norm])
    prob = model.predict_proba(X)[0, 1]

    assert prob > 0.60, f"Expected high phishing probability, got {prob}"

def test_core_model_legitimate_vit_notice():
    model = joblib.load("models/core_model.pkl")
    vec = joblib.load("models/tfidf_vectorizer.pkl")

    legit_msg = "Dear Student, the timetable for Winter Semester 2026-27 is published on VTOP. Please review allotments."
    norm = normalise_text(legit_msg)
    X = vec.transform([norm])
    prob = model.predict_proba(X)[0, 1]

    assert prob < 0.35, f"Expected low phishing probability for legitimate notice, got {prob}"
