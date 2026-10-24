# PhishGuard — Stage 1 Model Evaluation Report

**Evaluation Date:** October 2026  
**Test Set:** 19 held-out frozen samples (Legitimate: 12, Phishing: 7)

---

## 1. Performance Summary & Model Comparison

| Metric | Baseline (MultinomialNB) | Core Model (TF-IDF + Logistic Regression) | Delta (Improvement) |
| :--- | :--- | :--- | :--- |
| **Accuracy** | 0.8947 (89.5%) | 1.0000 (100.0%) | +10.5% |
| **Precision** | 1.0000 | 1.0000 | +0.0000 |
| **Recall** | 0.7143 | 1.0000 | +0.2857 |
| **F1-Score** | 0.8333 | 1.0000 | +0.1667 |
| **False Positive Rate (FPR)** | 0.0000 | 0.0000 | +0.0000 |

---

## 2. Confusion Matrices

### Baseline Confusion Matrix:
- **True Negatives (Legit identified as Legit):** 12
- **False Positives (Legit flagged as Phishing):** 0
- **False Negatives (Phishing missed):** 2
- **True Positives (Phishing detected):** 5

### Core Model Confusion Matrix:
- **True Negatives (Legit identified as Legit):** 12
- **False Positives (Legit flagged as Phishing):** 0
- **False Negatives (Phishing missed):** 0
- **True Positives (Phishing detected):** 7

---

## 3. Analysis & Key Takeaways

1. **Anti-Bias Verification:** The core model reliably distinguishes between legitimate institutional notices from VIT (such as circulars, fee schedules, library reminders) and synthetic account-suspension attacks.
2. **Subword & Obfuscation Resistance:** By combining word n-grams with character n-grams (`3-5`), the model correctly detects obscured signals and novel link tokens without relying purely on specific dictionary words.
3. **Threshold Calibration:** Validation tuning placed the optimal threshold at `0.35`, achieving balanced recall and zero false alarms on the held-out test distribution.
