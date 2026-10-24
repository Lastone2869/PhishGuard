# Dataset Card — PhishGuard Benchmark

## 1. Dataset Summary
The PhishGuard dataset is designed to train and benchmark models for detecting phishing campaigns targeted at students, with a primary focus on higher-education environments (VIT and comparable institutions), alongside general email and SMS phishing scenarios.

## 2. Dataset Structure
- `datasets/raw/raw_messages.csv`: Deduplicated full master dataset.
- `datasets/processed/train.csv`: 70% stratified training split.
- `datasets/processed/val.csv`: 15% stratified validation split for hyperparameter tuning.
- `datasets/processed/test.csv`: 15% stratified held-out frozen test split for final evaluation.

### Schema:
- `text` (string): The raw or message body content.
- `label` (int): `1` for Phishing, `0` for Legitimate.
- `source` (string): Origin category (`synthetic_vit_phish`, `synthetic_vit_legit`, `general_phish_corpus`, `general_legit_corpus`).
- `language` (string): Language ISO code (`en` for core; `hi` and `ta` supported in Stage 2).
- `sender` (string, nullable): Stated or header sender email address/identifier.
- `is_synthetic` (boolean): `True` for constructed/template-generated scenario messages; `False` for real-world messages.

## 3. Targeted Scenario & Anti-Bias Construction
To ensure the detector does **not** rely on spurious correlation (e.g. learning that "mention of VIT" implies phishing), the dataset contains a balanced set of:
1. **VIT Phishing attacks:** Account suspension warnings, fake VTOP re-verification portals, fake KYC alerts, fake grade revision inquiries.
2. **VIT Legitimate notices:** Official circulars from academics, finance, library, COE, student welfare, proctor office, placement cell (`@vit.ac.in`).
3. **General Phishing:** Banking alerts, delivery updates, gift cards, tech support, cloud storage warnings.
4. **General Legitimate:** Peer chats, university announcements, order receipts, appointment confirmations.

## 4. Split Methodology
- Split with fixed `random_state=42` and stratification across target labels.
- Held-out test set remains strictly frozen for final performance verification.
