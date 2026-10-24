# PhishGuard — Presentation Playbook

A 10-minute product demo for the Q5 submission. The goal is to show the
scenario, the working tool, the evidence, and the honest limits — not a code
tour.

---

## 1. Deck outline (12 slides)

| # | Slide | Message | Visual |
|---|---|---|---|
| 1 | **PhishGuard** — *A second pair of eyes before the click* | Q5, 16 October 2026 VIT suspension scenario. | Screenshot of the High Risk result |
| 2 | **The 24-hour panic window** | The message uses urgency, a credential ask, and a lookalike link. | Sample message with three callouts |
| 3 | **Why students click** | Filters say “spam” without evidence; opening the link is the risk. | Three short pain points |
| 4 | **What PhishGuard does** | Paste text + optional sender → risk label + strongest signals + advice. Links are never opened. | Input → output diagram |
| 5 | **Live demo** | Four cases in three minutes. | The running UI |
| 6 | **How it works** | Normalise → word + character TF-IDF → Logistic Regression → four rule signals → verdict → explanations. | Pipeline diagram |
| 7 | **The dataset** | 1,290 rows: Nazario (CC-BY-4.0), SpamAssassin legit/hard-negative, 240 constructed VIT. Grouped splits, frozen test. URL-only shortcut: 1.00 → 0.543. | Dataset table + shortcut bar |
| 8 | **Evaluation** | 242-row frozen test: P 0.954, R 0.921, F1 0.937; confusion `[[149,4],[7,82]]`. VIT final labels: 0 High Risk FPs, 2 Suspicious + 1 Uncertain / 18 legit, 0 missed. | Confusion matrix + key numbers |
| 9 | **Safety by design** | Defanged links (`hxxp://`, `[.]`), non-clickable; socket-blocking test; local processing; no automatic reporting. | Defanged URL + test name |
| 10 | **Safe advice** | Don’t click, reply, or share OTPs. Verify via official VTOP/helpdesk. Report to cybercrime.gov.in or call 1930. | “What to do now” panel |
| 11 | **What this is not** | Pilot, English-only, no SMS, synthetic VIT rows, SpamAssassin is 2002–03 mail, sender is user-supplied evidence. | Honest limitations list |
| 12 | **Next** | SMS + cross-source, Hindi/Tamil, header analysis, Bayesian/HMM fusion, dashboard/quiz. Close: “A second pair of eyes before the click.” | Roadmap |

Use slides 1, 2, 5, 8, 10, 11 for a 5-minute version.

---

## 2. Live demo script (3 minutes)

Pre-run `python run.py` and open <http://127.0.0.1:8000>.

1. **The scenario (30s).** Click **VIT Account Suspension Scam → Analyse**.
   - Expected: **High Risk**, ~0.91, 4 signals.
   - Point at the defanged link: `hxxp://vit-account-verify[.]info/login`.
   - Point at the evidence panel: urgency, credential request, lookalike
     domain, risky TLD.

2. **The hard case (30s).** Click **Official VIT Timetable Circular** (or paste
   the genuine fee reminder) → Analyse.
   - Expected: **Low Risk**, verified official sender, 0 signals.
   - Say: “This is the part most demos skip — not crying wolf on real VIT mail.”

3. **A different attack (30s).** Click **GPay Account Limited → Analyse**.
   - Expected: **High Risk**. The same four signals generalise beyond VIT.

4. **Missing metadata (20s).** Clear the sender field and analyse a message.
   - Expected: sender status **Not provided**; the tool does not guess.

5. **The advice (30s).** Scroll to **What to do now** and
   **Reporting & Official Help**. Mention `cybercrime.gov.in` and 1930.

Keep a GIF or screenshots of these four cases as a fallback.

---

## 3. Timing

| Time | Section |
|---|---|
| 0:00–1:00 | Hook + the 16 October message |
| 1:00–2:00 | What the tool does |
| 2:00–5:00 | Live demo |
| 5:00–6:00 | How it works |
| 6:00–7:30 | Dataset + evaluation |
| 7:30–8:30 | Safety + advice |
| 8:30–9:30 | Limitations + next |
| 9:30–10:00 | Close |

---

## 4. One-page handout

- Q5 requirement → where it is satisfied.
- Dataset: 1,290 rows, sources and licences.
- Test: 242 rows, P/R/F1, confusion matrix.
- VIT final labels: 0 High Risk FPs, 2 Suspicious, 1 Uncertain, 0 missed.
- Safety: defanged links, socket-blocking test, no automatic reporting.
- Limitations: one line each.
- Run command and repo path.

---

## 5. Q&A preparation

| Question | Answer |
|---|---|
| Why TF-IDF, not a transformer? | Fast, offline, explainable coefficients; a transformer is an optional comparison. |
| Is 1,290 rows enough? | Pilot: grouped splits, near-duplicate repair, frozen test, per-source metrics. Next pass adds SMS and more VIT rows. |
| Why two false positives? | They are Suspicious/Uncertain, not High Risk; the tool routes them to review. |
| How do you prove links are not opened? | URL analysis is pure text; `tests/test_url_analyser.py` blocks `socket.connect`. |
| What about sender spoofing? | The sender field is evidence, not authentication. Header analysis (SPF/DKIM/DMARC) is next. |
| Is it private? | Local processing, no link fetching, PII redaction in the dataset, no automatic reporting. |
| Why is VIT F1 lower? | Synthetic domain shift; final labels: 0 High Risk FPs, 0 missed, 2 Suspicious + 1 Uncertain. |

---

## 6. Delivery tips

- Lead with the message, not the model.
- One idea per slide; three bullets maximum.
- Say “pilot” out loud. The limitations slide makes the rest credible.
- Never claim perfect accuracy. Say “F1 0.94 on a 242-row frozen test set”.
- Do not read code; show the pipeline and the evidence panel.
- Rehearse the four demo cases and know the expected labels.
- Have screenshots/GIF as a fallback if the server or projector fails.
