"""
test_api.py
Tests the FastAPI backend endpoints (/api/health, /api/analyse).
"""

from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_health_endpoint():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["stage"] == 1
    assert data["model_loaded"] is True

def test_analyse_phishing_request():
    payload = {
        "text": "URGENT: Your VIT Account will be suspended within 24 hours. Enter your password at http://vit-fake.info/login",
        "sender": "admin@vit-support-desk.com"
    }
    resp = client.post("/api/analyse", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["label"] == "High Risk"
    assert data["badge_color"] == "red"
    assert data["composite_score"] >= 0.70
    assert len(data["defanged_urls"]) > 0
    assert "vit-fake[.]info" in data["defanged_urls"][0]
    assert len(data["ranked_explanations"]) > 0
    assert len(data["what_to_do_now"]) > 0

def test_analyse_legitimate_request():
    payload = {
        "text": "Circular: VIT Riviera 2027 cultural fest registration opens next Monday. Contact the student welfare office for guidelines.",
        "sender": "studentwelfare@vit.ac.in"
    }
    resp = client.post("/api/analyse", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["label"] == "Low Risk"
    assert data["badge_color"] == "emerald"
    assert data["composite_score"] < 0.35

def test_empty_text_validation():
    payload = {"text": "   "}
    resp = client.post("/api/analyse", json=payload)
    assert resp.status_code in [400, 422]
