# PhishGuard — Project Specifications

## 1. Overview
PhishGuard is an AI-based phishing-awareness tool for students. It analyses message text (emails, SMS and chat messages), raw email headers, and screenshots, flags potentially suspicious messages for user review, and explains exactly which evidence drove the verdict.

**Scenario (Question 5):** On 16 October 2026, students report emails and messages claiming that their VIT accounts will be suspended unless they click a link immediately. PhishGuard is built to detect this kind of campaign and to teach users how to recognise and report it.

PhishGuard is a web application with a FastAPI backend. It never visits links and never executes message content. All analysis is done on text and structure only.

## 2. Objectives
- Train a reliable, reproducible phishing detector on public and carefully constructed labelled datasets.
- Combine several AI techniques, each with a distinct role: TF-IDF + a linear classifier, a Bayesian network, and a Hidden Markov Model.
- Detect urgency, suspicious link text, credential requests and sender mismatches wherever the information is available.
- Support English, Hindi and Tamil, and expose performance gaps between languages.
- Show a risk label with evidence-based, plain-language explanations.
- Educate users through an interactive quiz and clear safe-handling and reporting advice.
- Provide honest, measurable evidence of performance (baseline comparison, per-language results, robustness tests).

## 3. Mandatory Features (from the Q5 brief)

| # | Feature | Requirement |
|---|---|---|
| M1 | Labelled message dataset | Public or carefully constructed dataset of legitimate and phishing messages, with documented preprocessing and a documented train/validation/test split. |
| M2 | Phishing signal detection | Detect urgency, suspicious link text, credential requests and sender mismatch wherever the information is available. |
| M3 | Risk label and explanation | Display the risk label and explain the strongest signals that influenced it. |
| M4 | Safe message analysis | Never open suspicious links automatically. Analyse link text and structure without visiting them. |
| M5 | Evaluation and reporting advice | Test on held-out data and report precision, recall and a confusion matrix. Give safe advice for avoiding and reporting suspicious messages. |

## 4. Additional Features

### 4.1 Features from the project plan
| # | Feature | Description |
|---|---|---|
| A6 | Multilingual detection | Analyse English, Hindi and Tamil messages. Detect and show the language. Test each language separately. Use character n-grams, since word tokenisation behaves differently in Tamil. Label any synthetic or translated data as such. |
| A7 | Organisation impersonation detection | Compare supplied sender details with a trusted reference list (VIT and other known organisations). Flag lookalike domains and show the evidence. Distinguish three outcomes: **verified mismatch**, **lookalike domain**, and **sender unknown/unverified**. Message text alone never proves the true sender. |
| A8 | Evidence-based explanation panel | Highlight the exact phrases and URL patterns that triggered warnings, explain each signal in plain language, and show which evidence came from the message. Highlights are driven by real model outputs (TF-IDF term weights and rule hits), not hardcoded. |
| A9 | Interactive cyber-safety quiz | 10–15 sample messages to classify, with explanations and a score tracker. Supports SDG 4. |
| A10 | Model performance and fairness dashboard | Precision, recall, F1-score, false-positive rate, confusion matrix, performance by language, and trained model vs baseline. |

### 4.2 New features
| # | Feature | Criterion | Description |
|---|---|---|---|
| N1 | Campaign detector | Innovation | Cluster similar messages using TF-IDF cosine similarity and flag "this looks like the same wave as the VIT suspension scam". |
| N2 | Screenshot and QR analysis | Innovation | OCR (Tesseract, including Hindi and Tamil) on uploaded images. Decode QR codes and show the embedded URL as text only; never open it. |
| N3 | Adversarial robustness test | Innovation / Technical | Test obfuscation such as `l0gin`, zero-width characters and mixed-script lookalikes (e.g. Cyrillic "а" for Latin "a"). Report the performance drop and how the normaliser recovers it. |
| N4 | Raw email header analysis | Functionality | Paste a full email to check Reply-To vs From mismatch, SPF/DKIM/DMARC results and display-name spoofing. |
| N5 | Safe URL structure analyser | Functionality | Without visiting the link, check punycode, IP-address hosts, shorteners, subdomain depth, unusual TLDs, Levenshtein distance to trusted domains, and anchor text vs actual href mismatch. |
| N6 | Three-level label with "uncertain" | Functionality / UX | Low / Suspicious / High risk. Low-confidence cases are routed to "review manually" rather than forcing a verdict. |
| N7 | Reporting workflow | Functionality | Generate a pre-filled report containing sender, evidence and a defanged link (`hxxp://`). Point users to the National Cyber Crime Reporting Portal (cybercrime.gov.in), the 1930 helpline, and the institution's IT helpdesk (real address to be added by the team). |
| N8 | "What to do now" panel | UX | Plain-language steps (don't click, don't reply, change your password if you already did, report it), plus a language toggle and a simple-mode view. |
| N9 | Privacy-first design | UX / Presentation | Process everything locally, redact phone numbers and emails before any logging, and state this on screen. |
| N10 | Cross-source generalisation test | Technical | Train on SMS data and test on email (and vice versa) and report the gap. |

## 5. AI / ML Architecture
Each technique has a specific job; none is decorative.

| Component | Role | Details |
|---|---|---|
| **TF-IDF + classifier (core)** | Main text classifier | Word and character n-gram TF-IDF with Logistic Regression or Linear SVM. Coefficients supply the evidence for the explanation panel. |
| **Baseline** | Comparison | TF-IDF (or bag-of-words) + Multinomial Naive Bayes. |
| **Bayesian network** | Reasoning over signals | Nodes: urgency, credential request, suspicious URL, sender mismatch, language, and phishing label. Handles missing evidence properly: if no sender is supplied, that node is left out of inference instead of guessed. Structure set by hand, probabilities learned from data (e.g. with `pgmpy`). |
| **HMM** | Message structure | Tag each sentence with a state (greeting, claim, threat/urgency, action request, sign-off). Train one HMM on phishing sequences and one on legitimate sequences; compare log-likelihoods. Optional second use: character-level HMM on domain names. Treated as a supporting signal; its ablation result is reported honestly. |
| **Fusion** | Final score | Stacked or weighted ensemble of the above plus rule-based signals, with probability calibration. Ablation: each model alone vs combined. |
| **Optional comparison** | Not the main model | A fine-tuned transformer (e.g. DistilBERT) may be compared against the main pipeline if time allows. |

### Preprocessing and normalisation
Unicode normalisation, zero-width character removal, homoglyph mapping, de-obfuscation (e.g. `0`→`o`), URL extraction and masking, language detection, and sentence segmentation (for the HMM).

## 6. Risk Labels
- **Low risk** — few or no signals; still advise caution.
- **Suspicious** — meaningful signals present; review before acting.
- **High risk** — strong, corroborated signals (e.g. urgency + credential request + sender or domain mismatch).
- **Uncertain / review manually** — model confidence is low or key information is missing.

Each label is accompanied by a ranked list of the strongest signals and the evidence from the message.

## 7. Technology Stack
- **Machine learning:** Python, pandas, scikit-learn, pgmpy (Bayesian network), hmmlearn (HMM), langdetect or fastText language ID, python-Levenshtein.
- **Image analysis:** Tesseract OCR (English, Hindi, Tamil), OpenCV or pyzbar for QR decoding.
- **Backend:** FastAPI.
- **Frontend:** Web UI (HTML, CSS, JavaScript) with analyser, evidence panel, quiz and dashboard pages.
- **Datasets:** Public phishing email and SMS datasets, legitimate email/SMS corpora, and carefully constructed or translated Hindi and Tamil messages (clearly labelled as synthetic).
- **Evaluation:** Precision, recall, F1-score, false-positive rate, confusion matrix, per-language metrics, cross-source tests, robustness tests and ablations.

## 8. System Architecture
1. Collect, clean, label and document public and constructed datasets.
2. Normalise text and extract features (TF-IDF, rule signals, URL features, sentence tags).
3. Train and evaluate the baseline, TF-IDF classifier, Bayesian network, HMM and fusion model.
4. Expose the pipeline through a FastAPI service accepting message text, optional sender details, optional raw headers, and optional images.
5. Run safe analysers (URL structure, headers, impersonation, OCR/QR, language detection) without visiting any link.
6. Return a risk label, calibrated score, ranked signals, and highlighted evidence.
7. Display results, safe advice and a pre-filled report in the web UI; feed the dashboard and quiz from stored evaluation results and quiz content.

## 9. Project Structure

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

## 10. Non-Functional Requirements
- Reliable detection on previously unseen messages and campaigns.
- Low inference latency.
- Clear, evidence-based, plain-language explanations; no unexplained percentages.
- Safe by design: no automatic link opening, no execution of message content, no automatic reporting.
- Privacy-first: local processing, redaction before any logging, no external transmission of message content.
- Graceful handling of missing metadata (no sender, no headers, no URLs).
- Accessible interface with language selection and a simple mode.
- Honest reporting of limitations (synthetic data, small multilingual sets, HMM contribution).

## 11. Success Criteria
- Reproducible evaluation on held-out data with a documented split.
- Documented precision, recall, F1-score, false-positive rate and confusion matrix.
- Trained model demonstrably compared against the Naive Bayes baseline, with ablations for each component.
- Per-language results for English, Hindi and Tamil, with gaps reported openly.
- Cross-source generalisation results (SMS ↔ email).
- Robustness results under obfuscation, with and without the normaliser.
- Working evidence panel driven by real model outputs.
- Verified safe URL handling: no outbound request is ever made to a submitted link.
- Working quiz with tracked scores and a performance dashboard.

## 12. Mapping to Evaluation Criteria

| Evaluation criterion | Supporting features |
|---|---|
| Innovation and creativity | Multilingual detection (A6), impersonation detection (A7), evidence-based explanations (A8), campaign detector (N1), screenshot/QR analysis (N2), adversarial robustness (N3) |
| Functionality and implementation | Working message analyser, header analysis (N4), safe URL analyser (N5), three-level label with uncertain (N6), reporting workflow (N7) |
| User experience and design | Highlighted evidence (A8), "what to do now" panel (N8), language toggle and simple mode, privacy-first design (N9) |
| Technical complexity | TF-IDF classifier, Bayesian network, HMM, fusion with calibration, sender/domain checks, held-out evaluation, baseline comparison, ablations, cross-source test (N10), dashboard (A10) |
| SDG alignment and presentation | Quiz (A9), educational explanations, student protection, measurable results (quiz scores, metrics) |

## 13. SDG Alignment
- **Primary: SDG 16 (Peace, Justice and Strong Institutions).** Supports awareness and prevention of cyber-enabled fraud by helping students identify and report suspicious messages. The contribution is indirect; the prototype does not eliminate cybercrime.
- **Secondary: SDG 9 (Industry, Innovation and Infrastructure).** Applies AI and language processing to improve users' ability to recognise threats in digital communications.
- **Additional: SDG 4 (Quality Education).** Strengthened by the interactive quiz and educational explanations. Measure it with quiz scores before and after reading explanations.

## 14. Scope

**In scope**
- Web application analysing pasted text, raw email headers and uploaded screenshots.
- English, Hindi and Tamil messages (subject to dataset support).
- Educational quiz, dashboard and reporting workflow.

**Out of scope**
- Visiting links or live URL reputation / threat-intelligence lookups.
- Voice or call phishing detection.
- Browser extensions (including Gmail integration) and chat-bot deployments (e.g. WhatsApp).
- Fine-tuned multilingual transformers as the main model (an optional comparison only).
- Automatic reporting, blocking or deletion based on a model prediction.
- Enterprise-wide deployment.
