"""
train_baseline.py
Trains the baseline Multinomial Naive Bayes model on TF-IDF word features.
Saves model artifacts to models/baseline_model.pkl and models/baseline_vectorizer.pkl.
"""

import os
import sys

# Ensure project root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import classification_report, accuracy_score, f1_score
from training.normalise import normalise_text
from training.schema import compose_text

def train_baseline():
    train_path = os.path.join("datasets", "processed", "train.csv")
    val_path = os.path.join("datasets", "processed", "val.csv")
    models_dir = "models"
    os.makedirs(models_dir, exist_ok=True)

    print("Loading datasets for Baseline (MultinomialNB)...")
    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)

    X_train = [normalise_text(t) for t in compose_text(train_df)]
    y_train = train_df["label"].values

    X_val = [normalise_text(t) for t in compose_text(val_df)]
    y_val = val_df["label"].values

    # Word TF-IDF
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=3000)
    X_train_vec = vectorizer.fit_transform(X_train)
    X_val_vec = vectorizer.transform(X_val)

    # MultinomialNB
    clf = MultinomialNB(alpha=0.5)
    clf.fit(X_train_vec, y_train)

    val_preds = clf.predict(X_val_vec)
    acc = accuracy_score(y_val, val_preds)
    f1 = f1_score(y_val, val_preds, zero_division=0)
    print(f"Baseline Validation Accuracy: {acc:.4f}, F1: {f1:.4f}")
    print("\nClassification Report (Validation):")
    print(classification_report(y_val, val_preds, zero_division=0))

    # Save artifacts
    model_path = os.path.join(models_dir, "baseline_model.pkl")
    vec_path = os.path.join(models_dir, "baseline_vectorizer.pkl")
    joblib.dump(clf, model_path)
    joblib.dump(vectorizer, vec_path)
    print(f"Saved baseline artifacts to {model_path} and {vec_path}")

if __name__ == "__main__":
    train_baseline()
