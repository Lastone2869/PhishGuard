# PhishGuard — AI-Based Phishing Awareness Tool for Students

PhishGuard is an AI-powered phishing-awareness tool specifically tailored for student communities. It analyzes message text (emails, SMS, chat messages), raw email headers, and message structure to flag suspicious messages, classify risk levels, and provide transparent, evidence-based explanations without ever visiting suspicious URLs.

## Project Structure (Specs §9)

```text
phishguard/
├── datasets/
│   ├── raw/
│   ├── processed/
│   ├── multilingual/            # constructed/translated hi + ta data (labelled synthetic)
│   └── DATASET_CARD.md          # sources, licences, labelling, split description
├── training/
│   ├── prepare_data.py
│   ├── normalise.py             # unicode, homoglyph, zero-width, de-obfuscation
│   ├── train_baseline.py        # Naive Bayes baseline
│   ├── train.py                 # TF-IDF + LR/SVM
│   ├── train_bayes_net.py
│   ├── train_hmm.py
│   ├── fusion.py                # stacking + calibration
│   ├── evaluate.py              # metrics, per-language, cross-source
│   ├── robustness.py            # adversarial/obfuscation tests
│   ├── ablation.py
│   └── requirements.txt
├── models/
│   └── README.md
├── backend/
│   ├── main.py
│   ├── detector.py              # orchestrates models + rules
│   ├── explainability.py        # term weights, rule hits, highlight spans
│   ├── url_analyser.py          # safe URL structure checks (never visits links)
│   ├── header_analyser.py       # Reply-To/From, SPF/DKIM/DMARC, display-name spoofing
│   ├── impersonation.py         # trusted-domain list, lookalike detection
│   ├── language.py              # language detection
│   ├── ocr_qr.py                # screenshot OCR and QR decoding
│   ├── campaigns.py             # similarity clustering
│   ├── reporting.py             # defanged links, pre-filled report
│   ├── privacy.py               # redaction before logging
│   ├── data/
│   │   ├── trusted_domains.json
│   │   └── quiz_messages.json
│   └── requirements.txt
├── frontend/
│   ├── index.html               # analyser + evidence panel + what-to-do panel
│   ├── quiz.html
│   ├── dashboard.html
│   ├── app.js
│   └── styles.css
├── reports/
│   ├── evaluation_report.md
│   └── figures/
├── tests/
│   ├── test_model.py
│   ├── test_signals.py
│   ├── test_url_analyser.py
│   ├── test_headers.py
│   ├── test_robustness.py
│   └── test_api.py
├── specs.md
├── implementation.md
└── README.md
```

## Quick Start (Stage 1 Core)

### Run Backend API:
```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

### Run Tests:
```bash
pytest tests/ -v
```
