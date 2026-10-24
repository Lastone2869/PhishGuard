# VIT Generalisation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans or superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Cut the constructed-VIT false-positive rate (currently 0.50) and lift VIT F1 (currently 0.78) without weakening spoof detection.

**Architecture:** First expand the hand-authored VIT corpus from 120 to 240 rows (60 phishing + 60 legitimate templates). Rebuild, retrain, and re-evaluate per source. If the VIT FPR is still above 0.25, add a **guarded** verified-sender mitigation: only for `verified_official` senders, only when no corroborated content signal exists, and only below a model-probability ceiling. The mitigation is explained as user-supplied evidence, never as authentication.

**Tech Stack:** Python 3.12, pandas, scikit-learn 1.6.1, pytest.

**Spec:** `specs.md` §4.1/A7, §5, §6; `implementation.md` §2.2, §2.7; `datasets/DATASET_CARD.md`.

## Global Constraints

- Never lower risk when a credential request, urgency cue, or suspicious URL is present.
- A supplied sender is evidence, not proof. The UI must say it was supplied, not authenticated.
- Every split rebuild changes the frozen test hash; rerun evaluation and update the card/report.
- All changes follow TDD: failing test first, then implementation.
- Keep the existing 120 rows; append new templates, do not rewrite them.

## Tasks

### Task 1: Expand the constructed corpus to 240 rows

**Files:** `datasets/constructed/vit_messages.csv`, `tests/test_constructed.py`

- [ ] Write failing tests: `len(df) >= 240`, `template_id.nunique() >= 120`, hard negatives `>= 30`, official senders `>= 30`.
- [ ] Add 30 phishing templates (P31–P60) and 30 legitimate templates (L31–L60), two variants each.
- [ ] Cover subtle phishing (reply-to harvest, remote-support tool, fake refund, fake hall ticket) and genuine hard negatives (password reset, fee refund, registration deadline, OTP, bank alert, security alert).
- [ ] Run `pytest tests/test_constructed.py -q`; expect green.

### Task 2: Rebuild, retrain, re-evaluate

- [ ] `python -m training.build_dataset`
- [ ] `python -m training.train_baseline && python -m training.train`
- [ ] `python -m training.evaluate`
- [ ] Record VIT precision, recall, F1, FPR from `reports/metrics.json`.

### Task 3 (conditional): Guarded verified-sender mitigation

Trigger only if VIT FPR > 0.25 after Task 2.

**Files:** `backend/explainability.py`, `tests/test_verdict.py`

- [ ] Failing tests:
  - official sender + benign content + prob 0.60 → score reduced by 0.10, explanation mentions "supplied", not "authenticated".
  - official sender + credential request → no reduction.
  - official sender + suspicious link → no reduction.
  - lookalike sender + benign → no reduction.
  - prob 0.90 + official sender → no reduction (ceiling).
- [ ] Implement in `compute_risk_verdict`: `if status == "verified_official" and count == 0 and prob < 0.75: score = max(0, score - 0.10)` and append an info explanation.
- [ ] Run full suite.

### Task 4: Docs and verification

- [ ] Update `reports/evaluation_report.md` (auto-generated), `DATASET_CARD.md` (auto-generated), and `README.md` numbers.
- [ ] `pytest tests/ -q`, `python -m training.build_dataset --check`, smoke test phish + genuine fee reminder.
- [ ] Commit.

## Review Focus

1. A spoofed official sender must not suppress a real credential/urgency/link signal.
2. New hard negatives must not be near-duplicates of existing rows.
3. The expanded corpus must keep template-level grouping so variants never cross splits.
4. The test set must still contain VIT rows after the rebuild.
5. Doc numbers must be regenerated, not hand-edited.
