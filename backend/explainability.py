"""
explainability.py
Combines ML model probabilities with rule signals into a calibrated composite risk score.
Maps score to a 4-level verdict: Low, Suspicious, High, Uncertain / Review Manually.
Extracts top positive feature weights from the Logistic Regression model for plain-language evidence.
"""

import os
import joblib
import numpy as np
from training.normalise import normalise_text

# Load core model and vectorizer
_MODEL = None
_VEC = None

def get_model_and_vec():
    global _MODEL, _VEC
    if _MODEL is None or _VEC is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        model_path = os.path.join(base_dir, "models", "core_model.pkl")
        vec_path = os.path.join(base_dir, "models", "tfidf_vectorizer.pkl")
        if not (os.path.exists(model_path) and os.path.exists(vec_path)):
            model_path = os.path.join("models", "core_model.pkl")
            vec_path = os.path.join("models", "tfidf_vectorizer.pkl")
        if os.path.exists(model_path) and os.path.exists(vec_path):
            _MODEL = joblib.load(model_path)
            _VEC = joblib.load(vec_path)
    return _MODEL, _VEC

def extract_top_terms(text: str, top_k: int = 5) -> list[dict]:
    """
    Extracts the highest-weighted terms present in the message using the
    trained Logistic Regression coefficients.
    """
    model, vec = get_model_and_vec()
    if model is None or vec is None or not text:
        return []

    norm_text = normalise_text(text)
    feature_names = vec.get_feature_names_out()
    coefs = model.coef_[0]

    # Transform text to sparse vector
    X_vec = vec.transform([norm_text])
    non_zero_indices = X_vec.nonzero()[1]

    term_contributions = []
    for idx in non_zero_indices:
        tfidf_val = X_vec[0, idx]
        weight = coefs[idx]
        contribution = tfidf_val * weight
        if contribution > 0:  # Positively contributing toward phishing
            clean_name = feature_names[idx]
            # Strip feature union prefix if present (e.g. 'word__', 'char__')
            clean_name = clean_name.replace("word__", "").replace("char__", "")
            term_contributions.append({
                "term": clean_name,
                "weight": float(contribution),
                "tfidf": float(tfidf_val)
            })

    # Sort descending by contribution
    term_contributions.sort(key=lambda x: x["weight"], reverse=True)
    return term_contributions[:top_k]

def compute_risk_verdict(model_prob: float, signals: dict, top_terms: list[dict]) -> dict:
    """
    Combines model probability with rule signals into a final score and risk label:
    - Low Risk
    - Suspicious
    - High Risk
    - Uncertain / Review Manually
    """
    # Signal weight adjustments
    rule_score_boost = 0.0
    if signals.get("sender_mismatch", {}).get("status") == "lookalike_impersonation":
        rule_score_boost += 0.25
    if signals.get("credential_request", {}).get("present"):
        rule_score_boost += 0.20
    if signals.get("urgency", {}).get("present"):
        rule_score_boost += 0.15
    if signals.get("suspicious_links", {}).get("present"):
        rule_score_boost += 0.20

    # Composite score clamped to [0.0, 1.0]
    composite_score = min(1.0, max(0.0, (model_prob * 0.65) + (rule_score_boost * 0.35)))

    # Determine Label
    corroborated_signals_count = sum([
        1 if signals.get("urgency", {}).get("present") else 0,
        1 if signals.get("credential_request", {}).get("present") else 0,
        1 if signals.get("suspicious_links", {}).get("present") else 0,
        1 if signals.get("sender_mismatch", {}).get("present") else 0,
    ])

    if composite_score >= 0.70 or corroborated_signals_count >= 2:
        label = "High Risk"
        badge_color = "red"
        recommendation = "Do not click links, do not reply, and do not provide credentials. Report immediately."
    elif 0.45 <= composite_score <= 0.55 and corroborated_signals_count == 0:
        label = "Uncertain / Review Manually"
        badge_color = "amber"
        recommendation = "Low model confidence with no corroborated attack rules. Verify with your institution's IT helpdesk before acting."
    elif composite_score >= 0.35 or corroborated_signals_count == 1:
        label = "Suspicious"
        badge_color = "amber"
        recommendation = "Meaningful warning indicators present. Review sender and URL structure carefully."
    else:
        label = "Low Risk"
        badge_color = "emerald"
        recommendation = "No overt threats detected. Always exercise standard cyber hygiene."

    # Build ranked explanations
    ranked_explanations = []
    
    # 1. Impersonation explanation
    if signals.get("sender_mismatch", {}).get("present"):
        ranked_explanations.append({
            "type": "sender_mismatch",
            "title": "Impersonation Alert",
            "description": signals["sender_mismatch"]["explanation"],
            "severity": "high"
        })
    # 2. Credential solicitation
    if signals.get("credential_request", {}).get("present"):
        ranked_explanations.append({
            "type": "credential_request",
            "title": "Credential Request Detected",
            "description": signals["credential_request"]["explanation"],
            "severity": "high"
        })
    # 3. Urgency pressure
    if signals.get("urgency", {}).get("present"):
        ranked_explanations.append({
            "type": "urgency",
            "title": "Urgency & Coercion Tactic",
            "description": signals["urgency"]["explanation"],
            "severity": "medium"
        })
    # 4. Suspicious links
    if signals.get("suspicious_links", {}).get("present"):
        ranked_explanations.append({
            "type": "suspicious_links",
            "title": "Suspicious Link Architecture",
            "description": signals["suspicious_links"]["explanation"],
            "severity": "high"
        })
    # 5. Top ML keywords
    if top_terms:
        term_names = [f"'{t['term']}'" for t in top_terms[:4]]
        ranked_explanations.append({
            "type": "ml_keywords",
            "title": "Statistical Text Signals",
            "description": f"The ML classifier flagged significant phishing term weights for: {', '.join(term_names)}.",
            "severity": "info"
        })

    return {
        "label": label,
        "badge_color": badge_color,
        "composite_score": round(float(composite_score), 4),
        "model_probability": round(float(model_prob), 4),
        "corroborated_signals_count": corroborated_signals_count,
        "recommendation": recommendation,
        "top_features": top_terms,
        "ranked_explanations": ranked_explanations
    }
