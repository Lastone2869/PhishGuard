"""
train.py
Trains the Core PhishGuard model:
Word & Character n-gram TF-IDF + Logistic Regression with calibrated thresholding.
Preserves model coefficients for term-level evidence explainability.
Saves artifacts to:
  - models/core_model.pkl
  - models/tfidf_vectorizer.pkl
  - models/metadata.json
"""

import os
import sys

# Ensure project root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import json
import joblib
import numpy as np
import pandas as pd
from sklearn.pipeline import FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support
from training.normalise import normalise_text

def train_core():
    train_path = os.path.join("datasets", "processed", "train.csv")
    val_path = os.path.join("datasets", "processed", "val.csv")
    models_dir = "models"
    os.makedirs(models_dir, exist_ok=True)

    print("Loading datasets for Core Model (TF-IDF + Logistic Regression)...")
    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)

    X_train = [normalise_text(t) for t in train_df["text"]]
    y_train = train_df["label"].values

    X_val = [normalise_text(t) for t in val_df["text"]]
    y_val = val_df["label"].values

    # Word & Char n-gram union for robust adversarial resistance & subword cues
    word_vec = TfidfVectorizer(
        analyzer="word",
        ngram_range=(1, 2),
        sublinear_tf=True,
        max_features=2500
    )
    char_vec = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        sublinear_tf=True,
        max_features=2500
    )
    union_vectorizer = FeatureUnion([
        ("word", word_vec),
        ("char", char_vec)
    ])

    print("Fitting TF-IDF FeatureUnion...")
    X_train_vec = union_vectorizer.fit_transform(X_train)
    X_val_vec = union_vectorizer.transform(X_val)

    # Core classifier: Logistic Regression with balanced class weights
    clf = LogisticRegression(
        C=2.0,
        max_iter=1000,
        class_weight="balanced",
        random_state=42
    )
    clf.fit(X_train_vec, y_train)

    # Evaluate validation probabilities & optimize decision threshold
    val_probs = clf.predict_proba(X_val_vec)[:, 1]

    best_thresh = 0.50
    best_f1 = 0.0
    for thresh in np.arange(0.35, 0.70, 0.05):
        preds = (val_probs >= thresh).astype(int)
        _, _, f1, _ = precision_recall_fscore_support(y_val, preds, average="binary", zero_division=0)
        if f1 > best_f1:
            best_f1 = f1
            best_thresh = float(thresh)

    final_val_preds = (val_probs >= best_thresh).astype(int)
    acc = accuracy_score(y_val, final_val_preds)
    print(f"Optimal Validation Decision Threshold: {best_thresh:.2f}")
    print(f"Core Model Validation Accuracy: {acc:.4f}, F1: {best_f1:.4f}")
    print("\nClassification Report (Validation):")
    print(classification_report(y_val, final_val_preds, zero_division=0))

    # Save artifacts
    model_path = os.path.join(models_dir, "core_model.pkl")
    vec_path = os.path.join(models_dir, "tfidf_vectorizer.pkl")
    meta_path = os.path.join(models_dir, "metadata.json")

    joblib.dump(clf, model_path)
    joblib.dump(union_vectorizer, vec_path)

    metadata = {
        "model_type": "LogisticRegression",
        "vectorizer": "FeatureUnion(word_ngram=(1,2), char_ngram=(3,5))",
        "decision_threshold": best_thresh,
        "classes": [0, 1],
        "validation_accuracy": float(acc),
        "validation_f1": float(best_f1)
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"Saved Core Model artifacts to {models_dir}/")

if __name__ == "__main__":
    train_core()
