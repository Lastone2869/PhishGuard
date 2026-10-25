"""
test_integration.py
Comprehensive end-to-end integration tests for PhishGuard.
Tests FastAPI endpoints, static asset delivery, full request-response contract,
real-world phishing scenarios, degradation without sender, and security boundaries.
"""

import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

# =========================================================================
# 1. Server Routes & Static Asset Integration
# =========================================================================

def test_integration_health_and_static_assets():
    """Verifies that API healthcheck and frontend static assets are served correctly."""
    # Health endpoint
    h_resp = client.get("/api/health")
    assert h_resp.status_code == 200
    h_data = h_resp.json()
    assert h_data["status"] == "healthy"
    assert h_data["model_loaded"] is True

    # Frontend HTML index
    root_resp = client.get("/")
    assert root_resp.status_code == 200
    assert "text/html" in root_resp.headers["content-type"]
    assert "PhishGuard" in root_resp.text
    assert "results-card" in root_resp.text

    # Frontend stylesheet
    css_resp = client.get("/styles.css")
    assert css_resp.status_code == 200
    assert "text/css" in css_resp.headers["content-type"]
    assert "--border-focus" in css_resp.text

    # Frontend JavaScript controller
    js_resp = client.get("/app.js")
    assert js_resp.status_code == 200
    assert "handleAnalyse" in js_resp.text

def test_integration_html_shell_is_not_cached():
    """The HTML shell must revalidate so a code change is picked up on reload."""
    resp = client.get("/")
    assert "no-store" in resp.headers.get("cache-control", "")


def test_integration_self_hosted_font_mime_type():
    """The local IBM Plex files must be served as fonts, not text/plain."""
    resp = client.get("/fonts/ibm-plex-serif-400.woff2")
    assert resp.status_code == 200
    assert "font/woff2" in resp.headers["content-type"]


# =========================================================================
# 2. Response Contract & Schema Validation
# =========================================================================

def test_integration_full_response_contract():
    """Validates that POST /api/analyse returns all required fields in the schema."""
    payload = {
        "text": "Your VIT student account will be suspended within 24 hours. Enter your password at http://vit-fake.info/login",
        "sender": "admin@vit-support-desk.com"
    }
    resp = client.post("/api/analyse", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    required_keys = [
        "label", "badge_color", "composite_score", "model_probability",
        "recommendation", "corroborated_signals_count", "signals",
        "top_features", "ranked_explanations", "defanged_urls",
        "reporting_guidance", "what_to_do_now"
    ]
    for key in required_keys:
        assert key in data, f"Missing required response key: {key}"

    # Verify types
    assert isinstance(data["label"], str)
    assert isinstance(data["badge_color"], str)
    assert isinstance(data["composite_score"], float)
    assert isinstance(data["model_probability"], float)
    assert isinstance(data["recommendation"], str)
    assert isinstance(data["corroborated_signals_count"], int)
    assert isinstance(data["signals"], dict)
    assert isinstance(data["top_features"], list)
    assert isinstance(data["ranked_explanations"], list)
    assert isinstance(data["defanged_urls"], list)
    assert isinstance(data["reporting_guidance"], dict)
    assert isinstance(data["what_to_do_now"], list)

    # Verify reporting guidance contains institutional & national portal entries
    rg = data["reporting_guidance"]
    assert "institution_helpdesk" in rg
    assert "national_cyber_portal" in rg
    assert "helpline" in rg

# =========================================================================
# 3. Real-World Scenario Integration Tests
# =========================================================================

def test_integration_vit_suspension_phishing_scenario():
    """
    Scenario 1 (Question 5 Scenario):
    Student receives email claiming VIT account will be suspended within 24 hours
    unless they click a link immediately to verify their password.
    """
    payload = {
        "text": "URGENT: Your VIT Student Account will be suspended within 24 hours due to unverified KYC. Click here immediately to verify your password: http://vit-account-verify.info/login",
        "sender": "admin@vit-support-desk.com"
    }
    resp = client.post("/api/analyse", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["label"] == "High Risk"
    assert data["badge_color"] == "red"
    assert data["composite_score"] >= 0.70
    assert data["corroborated_signals_count"] >= 3

    # All signals must be triggered
    sigs = data["signals"]
    assert sigs["urgency"]["present"] is True
    assert sigs["credential_request"]["present"] is True
    assert sigs["suspicious_links"]["present"] is True
    assert sigs["sender_mismatch"]["status"] == "lookalike_impersonation"

    # Defanged link check (safe view)
    assert len(data["defanged_urls"]) == 1
    assert data["defanged_urls"][0].startswith("hxxp://")
    assert "vit-account-verify[.]info" in data["defanged_urls"][0]

    # Action list advice
    assert len(data["what_to_do_now"]) >= 3
    assert any("not click" in step.lower() for step in data["what_to_do_now"])

def test_integration_legitimate_vit_circular_scenario():
    """
    Official VIT circular from legitimate CoE address with no threats or credential requests.
    """
    payload = {
        "text": "Dear Student, The timetable for Winter Semester 2026-27 is now published on VTOP. Please review your slot allotments on the official portal.",
        "sender": "coe@vit.ac.in"
    }
    resp = client.post("/api/analyse", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["label"] == "Low Risk"
    assert data["badge_color"] == "emerald"
    assert data["composite_score"] < 0.35
    assert data["corroborated_signals_count"] == 0

    sigs = data["signals"]
    assert sigs["urgency"]["present"] is False
    assert sigs["credential_request"]["present"] is False
    assert sigs["sender_mismatch"]["status"] == "verified_official"

def test_integration_paypal_financial_phishing_scenario():
    """
    Financial phishing message: PayPal account limited, credential verification requested.
    """
    payload = {
        "text": "Your PayPal account has been limited due to suspicious transactions. Enter your credit card and login details at http://paypal-account-center.com/resolve to confirm your identity.",
        "sender": "service@paypal-security-update.com"
    }
    resp = client.post("/api/analyse", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["label"] in ["High Risk", "Suspicious"]
    assert data["signals"]["credential_request"]["present"] is True
    assert len(data["defanged_urls"]) > 0
    assert "paypal-account-center[.]com" in data["defanged_urls"][0]

def test_integration_gpay_financial_phishing_scenario():
    """
    Financial phishing message: GPay account limited, UPI PIN verification requested.
    """
    payload = {
        "text": "ALERT: Your Google Pay (GPay) account has been limited due to suspicious transactions. Click immediately to re-verify your UPI PIN: http://gpay-upi-verify.info/login",
        "sender": "security@gpay-support-desk.com"
    }
    resp = client.post("/api/analyse", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["label"] in ["High Risk", "Suspicious"]
    assert data["signals"]["credential_request"]["present"] is True
    assert len(data["defanged_urls"]) > 0
    assert "gpay-upi-verify[.]info" in data["defanged_urls"][0]

def test_integration_student_peer_chat_scenario():
    """
    Informal peer chat with no security risks.
    """
    payload = {
        "text": "Hey, let's meet at 5 PM in library discuss the operating systems project.",
        "sender": "rahul.student@gmail.com"
    }
    resp = client.post("/api/analyse", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["label"] == "Low Risk"
    assert data["composite_score"] < 0.35

def test_integration_missing_sender_graceful_degradation():
    """
    Verifies that when sender is omitted, the detector does not invent or assume sender,
    and returns status 'not_provided'.
    """
    payload = {
        "text": "Notice: Please attend the seminar tomorrow at 10 AM.",
        "sender": None
    }
    resp = client.post("/api/analyse", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["signals"]["sender_mismatch"]["sender_provided"] is False
    assert data["signals"]["sender_mismatch"]["status"] == "not_provided"

# =========================================================================
# 4. Security Boundary & Bug Regression Integration Tests
# =========================================================================

def test_integration_domain_spoofing_bypass_fix():
    """
    Regression Test for Bug 1:
    Attacker registers 'evilvit.ac.in' or 'fakevit.ac.in'.
    Must NOT be verified as official 'vit.ac.in'.
    Must be flagged as 'lookalike_impersonation'.
    """
    payload = {
        "text": "VIT Notice: Complete your student registration now.",
        "sender": "admin@evilvit.ac.in"
    }
    resp = client.post("/api/analyse", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["signals"]["sender_mismatch"]["status"] == "lookalike_impersonation"
    assert data["signals"]["sender_mismatch"]["present"] is True

def test_integration_ipv4_host_no_subdomain_false_positive():
    """
    Regression Test for Bug 5:
    IP host (192.168.1.1) must trigger IP address signal, but NOT
    'Unusually deep subdomain hierarchy'.
    """
    payload = {
        "text": "Log in at http://192.168.1.100/login",
        "sender": None
    }
    resp = client.post("/api/analyse", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    signals_list = data["signals"]["suspicious_links"]["signals"]
    assert any("Raw IP address" in s for s in signals_list)
    assert not any("subdomain hierarchy" in s.lower() for s in signals_list)

def test_integration_input_validation_and_errors():
    """Verifies that invalid payloads are caught with 400 or 422 status codes."""
    # Empty string
    r1 = client.post("/api/analyse", json={"text": ""})
    assert r1.status_code in [400, 422]

    # Whitespace only
    r2 = client.post("/api/analyse", json={"text": "     \n   "})
    assert r2.status_code in [400, 422]

    # Missing text field
    r3 = client.post("/api/analyse", json={"sender": "test@test.com"})
    assert r3.status_code == 422
