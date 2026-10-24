"""
test_signals.py
Tests signal detection for urgency, credential solicitation, and sender mismatch.
"""

from backend.detector import detect_signals

def test_urgency_detection():
    urgent_msg = "URGENT: Your account will be suspended within 24 hours. Final warning!"
    sigs = detect_signals(urgent_msg)
    assert sigs["urgency"]["present"] is True
    assert sigs["urgency"]["strength"] in ["medium", "high"]
    assert len(sigs["urgency"]["matches"]) >= 2

def test_credential_detection():
    cred_msg = "Please verify your account and confirm your password and OTP immediately."
    sigs = detect_signals(cred_msg)
    assert sigs["credential_request"]["present"] is True
    assert any("password" in m.lower() for m in sigs["credential_request"]["matches"])

def test_sender_mismatch_missing():
    msg = "General update message without sender header."
    sigs = detect_signals(msg, sender=None)
    assert sigs["sender_mismatch"]["present"] is False
    assert sigs["sender_mismatch"]["sender_provided"] is False
    assert sigs["sender_mismatch"]["status"] == "not_provided"

def test_sender_mismatch_official():
    msg = "Notice from Controller of Examinations regarding winter timetable."
    sigs = detect_signals(msg, sender="coe@vit.ac.in")
    assert sigs["sender_mismatch"]["present"] is False
    assert sigs["sender_mismatch"]["status"] == "verified_official"

def test_sender_mismatch_lookalike_spoofing():
    msg = "Action Required: VIT Semester fees discrepancy. Update your VTOP details."
    sigs = detect_signals(msg, sender="admin@vit-support-desk.com")
    assert sigs["sender_mismatch"]["present"] is True
    assert sigs["sender_mismatch"]["status"] == "lookalike_impersonation"
    assert "Impersonation alert" in sigs["sender_mismatch"]["explanation"]
