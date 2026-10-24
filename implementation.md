# PhishGuard — Implementation Plan

The work is split into three stages.

- **Stage 1 — Core (mandatory Q5 requirements).** Everything the brief asks for. This is built and checked first, and it must work end to end before anything else starts.
- **Stage 2 — Additional features.** Built one at a time on top of the working core, in priority order.
- **Stage 3 — Final testing, documentation and presentation.**

Stage 1 is deliberately small. If time runs short, Stage 1 alone is a complete, submittable project.

---

# STAGE 1 — CORE (Mandatory Q5 Requirements)

**Brief:** On 16 October 2026, students report emails and messages claiming that their VIT accounts will be suspended unless they click a link immediately. Create an AI-based phishing-awareness tool that analyses message text and flags potentially suspicious messages for user review.

**Requirements and deliverables from the brief:**
1. Use a public or carefully constructed labelled dataset of legitimate and phishing messages.
2. Identify useful signals such as urgency, suspicious link text, requests for credentials, and sender mismatch where available.
3. Display a risk label and an explanation of the strongest signals; do not open suspicious links automatically.
4. Deliverables: a text-analysis prototype, a test set with precision/recall or a confusion matrix, and safe advice for reporting suspicious messages.

## 1.1 Labelled Dataset
*Requirement: public or carefully constructed labelled dataset.*
- Obtain public, appropriately licensed phishing and legitimate message datasets (email and SMS).
- Add carefully constructed messages modelled on the VIT account-suspension scenario, plus legitimate institutional notices (fee reminders, timetable changes, genuine password-expiry notices) so the model cannot learn "mentions VIT = phishing". Label constructed data as synthetic.
- Use a consistent schema from the start: `text`, `label`, `source`, `language`, `sender` (nullable), `is_synthetic`. Core uses English only; the `language` column keeps Stage 2 multilingual work easy.
- Remove duplicates and near-duplicates, inspect labels, and separate phishing from generic spam where possible.
- Create a leakage-resistant train / validation / test split (split by source or campaign, not just randomly) and document it.
- Write `DATASET_CARD.md` covering sources, licences, label definitions, class balance and known biases.

**Done when:** a cleaned, labelled dataset with a documented, frozen test set exists.

## 1.2 Preprocessing and Core Model
*Requirement: text-analysis prototype.*
- Preprocessing: lowercasing, Unicode normalisation, URL extraction and masking, whitespace and punctuation cleanup.
- **Baseline:** TF-IDF + Multinomial Naive Bayes.
- **Core model:** word and character n-gram TF-IDF + Logistic Regression (or Linear SVM). Keep the coefficients, since they feed the explanations.
- Tune hyperparameters and the decision threshold on the validation set only.
- Save the model and preprocessing pipeline.

**Done when:** a saved model scores new text and outputs a phishing probability.

## 1.3 Evaluation on Held-Out Data
*Requirement: test set with precision/recall or a confusion matrix.*
- Evaluate the baseline and core model on the untouched test set.
- Report precision, recall, F1-score, false-positive rate and the confusion matrix.
- Review false positives and false negatives by hand and note why they occur.
- Write results to `reports/evaluation_report.md` and a machine-readable metrics file (used later by the dashboard).

**Done when:** an evaluation report with a baseline-vs-model comparison exists.

## 1.4 Signal Detection
*Requirement: urgency, suspicious link text, credential requests, sender mismatch where available.*
- **Urgency:** phrases such as "immediately", "within 24 hours", "account will be suspended", "final warning".
- **Credential requests:** requests for password, OTP, PIN, login details, "verify your account", "confirm your identity".
- **Suspicious link text:** extract URLs and check them from text alone, without visiting them. Look for IP-address hosts, shorteners, misleading anchor text, many subdomains, `@` in the URL, and long or odd domains.
- **Sender mismatch (where available):** take an optional sender field. If supplied, compare the sender domain with a small trusted list (e.g. `vit.ac.in`) and flag a mismatch or an apparent lookalike. If not supplied, report "sender not provided" and do not guess.
- Each signal returns: present or absent, strength, and the exact text span that triggered it.

**Done when:** each of the four signal types works on test messages, and the sender check degrades gracefully when no sender is given.

## 1.5 Risk Label and Explanation
*Requirement: display a risk label and an explanation of the strongest signals.*
- Combine the model probability with the rule-based signals into a score.
- Map the score to a label: **Low**, **Suspicious**, **High**, with **Uncertain / review manually** when confidence is low.
- Rank the strongest signals (top TF-IDF terms by coefficient plus triggered rules).
- Explain each in plain language, e.g. "Urgent deadline: 'within 24 hours' is a pressure tactic used to stop you from checking."

**Done when:** every analysed message returns a label and a ranked, readable explanation.

## 1.6 Safe Link Handling
*Requirement: do not open suspicious links automatically.*
- Links are treated purely as text. No code path fetches, resolves, or previews a submitted URL.
- Display links in defanged form (`hxxp://`, `[.]`) and never as clickable anchors.
- Add a test that proves submitting a URL triggers no outbound network request to it.

**Done when:** the safety test passes and links are never clickable in the UI.

## 1.7 Minimal Prototype (API + Interface)
*Requirement: text-analysis prototype.*
- FastAPI endpoint accepting message text and an optional sender field, returning label, score, signals and explanations.
- Simple web page with: a message box, optional sender field, an Analyse button, and a results area showing the risk label, strongest signals and explanation.
- Keep it plain. Polish comes in Stage 2.

**Done when:** a user can paste a message and see a risk label with explanations in the browser.

## 1.8 Safe Advice and Reporting Guidance
*Requirement: safe advice for reporting suspicious messages.*
- Display a short "What to do" section with every result: don't click links, don't reply, don't share passwords or OTPs, verify through the official website or helpdesk, change your password if you already clicked.
- Reporting guidance: forward to the institution's IT helpdesk (the team adds the real address), report on the National Cyber Crime Reporting Portal (cybercrime.gov.in), and call the 1930 helpline for financial fraud.

**Done when:** advice and reporting steps appear alongside every result.

## 1.9 Stage 1 Checkpoint
Do not start Stage 2 until every row is true.

| Brief requirement | Satisfied by | Done |
|---|---|---|
| Labelled dataset of legitimate and phishing messages | 1.1 | ☐ |
| Urgency detection | 1.4 | ☐ |
| Credential-request detection | 1.4 | ☐ |
| Suspicious link text detection | 1.4 | ☐ |
| Sender mismatch where available | 1.4 | ☐ |
| Risk label displayed | 1.5, 1.7 | ☐ |
| Explanation of strongest signals | 1.5, 1.7 | ☐ |
| Links never opened automatically | 1.6 | ☐ |
| Text-analysis prototype working | 1.2, 1.7 | ☐ |
| Test set with precision/recall and confusion matrix | 1.3 | ☐ |
| Safe advice for reporting | 1.8 | ☐ |

---

# STAGE 2 — ADDITIONAL FEATURES

Built on top of the working core, in this order. Each item is independent, so it is safe to stop after any of them. Each one should add a short entry to the evaluation report where relevant.

## 2.1 Safe URL Structure Analyser
- Extend the Stage 1 link checks: punycode, shorteners, subdomain depth, unusual TLDs, Levenshtein distance to trusted domains, and anchor text vs actual href mismatch.
- Never visits the link.

## 2.2 Organisation Impersonation Detection
- Replace the small trusted list with a proper reference file (`trusted_domains.json`) covering VIT and other known organisations.
- Output one of three outcomes: **verified mismatch**, **lookalike domain**, or **sender unknown/unverified**, and show the evidence.
- Message text alone never proves the true sender.

## 2.3 Evidence-Based Explanation Panel
- Upgrade the Stage 1 explanation to highlight the exact phrases and URL patterns inside the message.
- Explain each signal in plain language and show which evidence came from the message.
- Drive all highlights from real model outputs (TF-IDF term weights and rule hits), not hardcoded spans.

## 2.4 Bayesian Network
- Nodes: urgency, credential request, suspicious URL, sender mismatch, language, phishing label.
- Set the structure by hand and learn the probabilities from data (e.g. `pgmpy`).
- Handles missing evidence properly: with no sender, that node is left out of inference rather than guessed.

## 2.5 Multilingual Detection (English, Hindi, Tamil)
- Build or translate Hindi and Tamil messages, clearly labelled as synthetic.
- Add language detection and show the detected language.
- Add character n-gram features and urgency/credential patterns for each language.
- **Test each language separately** and record the gaps.

## 2.6 Model Performance and Fairness Dashboard
- Show precision, recall, F1-score, false-positive rate, confusion matrix, per-language results, and trained model vs baseline.
- Read the real metrics files produced by the evaluation scripts.
- State dataset limitations (e.g. synthetic Hindi/Tamil) beside the numbers.

## 2.7 Three-Level Label Refinement and Calibration
- Calibrate probabilities and tune the "Uncertain / review manually" band using validation data.
- Report how often "Uncertain" is used and how accurate the remaining decisions are.

## 2.8 Raw Email Header Analysis
- Accept pasted full headers and check Reply-To vs From mismatch, SPF/DKIM/DMARC results, and display-name spoofing.
- Feeds a stronger sender-mismatch signal into the risk score.

## 2.9 Screenshot and QR Analysis
- OCR on uploaded images with Tesseract (English, Hindi, Tamil).
- Decode QR codes and show the embedded URL as text only. Never open it.
- Pass the extracted text through the normal pipeline.

## 2.10 Reporting Workflow and Privacy
- Generate a pre-filled report with sender, evidence and a defanged link, for the user to copy or send themselves.
- Process everything locally, redact phone numbers and emails before any logging, and state this on screen.
- Nothing is reported or blocked automatically.

## 2.11 Campaign Detector
- Cluster similar messages using TF-IDF cosine similarity.
- Flag "this looks like the same wave as the VIT suspension scam" when a message matches a known cluster.

## 2.12 Adversarial Robustness Test
- Add a normalisation step covering zero-width characters, homoglyphs (e.g. Cyrillic "а") and de-obfuscation (`l0gin` → `login`).
- Test obfuscated variants with and without the normaliser, and report the performance drop and recovery.

## 2.13 HMM Message-Structure Model and Fusion
- Tag sentences (greeting, claim, threat/urgency, action request, sign-off). Train one HMM on phishing sequences and one on legitimate sequences, and compare log-likelihoods.
- Optionally add a character-level HMM on domain names.
- Combine the TF-IDF model, Bayesian network, HMM and rule signals in a stacked or weighted ensemble.
- Run an **ablation** (each component alone vs combined) and report the HMM's contribution honestly, even if it is small.
- Optional comparison: a fine-tuned transformer such as DistilBERT, if time allows. It is not the main model.

## 2.14 Cross-Source Generalisation Test
- Train on SMS and test on email, and the reverse. Report the gap.

## 2.15 Interactive Cyber-Safety Quiz
- 10–15 sample messages (legitimate and phishing, across languages) with correct answers and explanations that use the same signals the tool detects.
- Score tracking, with an optional before/after comparison to support the SDG 4 argument.
- Keep it small.

## 2.16 Interface Polish and Accessibility
- "What to do now" panel in plain language, language toggle (English, Hindi, Tamil) and a simple-mode view.
- Readable contrast and accessible layout.

---

# STAGE 3 — FINAL TESTING, DOCUMENTATION AND PRESENTATION

- Test legitimate messages, obvious phishing, subtle phishing, unseen campaigns, each supported language, and missing-metadata cases (no sender, no headers, no links).
- Re-verify safe link handling, privacy behaviour, response time and error handling.
- Document setup instructions, the dataset card, evaluation results and limitations.
- Write the SDG justification: SDG 16 (primary), SDG 9 (secondary), SDG 4 (additional, strongest if the quiz is implemented well).
- Prepare the presentation around a demo of the VIT suspension scenario, the evidence panel, the dashboard results, and honest limitations.

---

# Development Order

**Stage 1:** Dataset → Preprocessing → Baseline and TF-IDF model → Held-out evaluation → Signal detection → Risk label and explanation → Safe link handling → Minimal API and UI → Safe advice and reporting guidance → *Stage 1 checkpoint*

**Stage 2:** URL analyser → Impersonation → Evidence panel → Bayesian network → Multilingual → Dashboard → Calibration and Uncertain label → Header analysis → OCR/QR → Reporting and privacy → Campaign detector → Robustness → HMM and fusion → Cross-source test → Quiz → Interface polish

**Stage 3:** Final testing → Documentation → Presentation

# Out of Scope
- Visiting links or live URL reputation / threat-intelligence lookups.
- Voice or call phishing detection.
- Browser extensions (including Gmail integration) and chat-bot deployments such as WhatsApp.
- Fine-tuned multilingual transformers as the main model (optional comparison only).
- Automatic reporting, blocking or deletion based on a model prediction.
