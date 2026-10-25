"""
main.py
FastAPI application backend for PhishGuard (Stage 1 Core).
Provides:
  - POST /api/analyse: Safe text and sender analysis endpoint
  - GET  /api/health: Healthcheck endpoint
  - Static file hosting for frontend UI
"""

import mimetypes
import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Windows' mimetypes registry does not know woff2; make the self-hosted fonts
# load reliably instead of being served as text/plain.
mimetypes.add_type("font/woff2", ".woff2")
mimetypes.add_type("font/woff", ".woff")

from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from training.normalise import normalise_text
from backend.detector import detect_signals
from backend.explainability import (
    get_model_and_vec,
    extract_top_terms,
    compute_risk_verdict
)

app = FastAPI(
    title="PhishGuard API",
    description="AI-based phishing awareness and text analysis backend for student protection.",
    version="1.0.0"
)

# Enable CORS for local testing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalyseRequest(BaseModel):
    text: str = Field(..., description="Message text body to analyse", min_length=1)
    sender: Optional[str] = Field(None, description="Optional sender email, name, or phone number")

class AnalyseResponse(BaseModel):
    label: str
    badge_color: str
    composite_score: float
    model_probability: float
    recommendation: str
    corroborated_signals_count: int
    signals: dict
    top_features: list[dict]
    ranked_explanations: list[dict]
    defanged_urls: list[str]
    reporting_guidance: dict
    what_to_do_now: list[str]

REPORTING_GUIDANCE = {
    "institution_helpdesk": "VIT IT Helpdesk (helpdesk@vit.ac.in / Student Welfare)",
    "national_cyber_portal": "https://cybercrime.gov.in (National Cyber Crime Reporting Portal)",
    "helpline": "Dial 1930 for immediate financial cyber fraud assistance in India",
    "status": "Safe Defanged Report Ready"
}

WHAT_TO_DO_STEPS = [
    "Do NOT click any links, open attachments, or scan QR codes contained in the message.",
    "Do NOT reply or attempt to contact the sender using the phone numbers or links provided in the message.",
    "Never share passwords, VTOP credentials, or OTP codes over email, SMS, or chat.",
    "If you already clicked or submitted credentials, immediately change your account password via the official portal.",
    "Forward suspicious emails claiming to be from VIT to the official IT Helpdesk and notify your proctor."
]

@app.get("/api/health")
def healthcheck():
    model, vec = get_model_and_vec()
    return {
        "status": "healthy",
        "stage": 1,
        "model_loaded": model is not None and vec is not None
    }

@app.post("/api/analyse", response_model=AnalyseResponse)
def analyse_message(request: AnalyseRequest):
    if not request.text.strip():
        raise HTTPException(status_code=400, detail="Message text cannot be empty.")

    model, vec = get_model_and_vec()
    if model is None or vec is None:
        raise HTTPException(status_code=503, detail="PhishGuard model artifacts are not loaded.")

    # 1. Normalise text safely
    norm_text = normalise_text(request.text)

    # 2. ML Model probability
    X_vec = vec.transform([norm_text])
    model_prob = float(model.predict_proba(X_vec)[0, 1])

    # 3. Rule signals (urgency, credentials, safe url check, sender mismatch)
    signals = detect_signals(request.text, request.sender)

    # 4. Explainable top positive feature terms from the trained model
    top_terms = extract_top_terms(request.text)

    # 5. Composite score and label verdict
    verdict = compute_risk_verdict(model_prob, signals, top_terms)

    # 6. Safe defanged links
    defanged_urls = signals["suspicious_links"].get("defanged_urls", [])

    return AnalyseResponse(
        label=verdict["label"],
        badge_color=verdict["badge_color"],
        composite_score=verdict["composite_score"],
        model_probability=verdict["model_probability"],
        recommendation=verdict["recommendation"],
        corroborated_signals_count=verdict["corroborated_signals_count"],
        signals=signals,
        top_features=verdict["top_features"],
        ranked_explanations=verdict["ranked_explanations"],
        defanged_urls=defanged_urls,
        reporting_guidance=REPORTING_GUIDANCE,
        what_to_do_now=WHAT_TO_DO_STEPS
    )

@app.middleware("http")
async def disable_html_cache(request, call_next):
    """Keep the shell HTML fresh; versioned CSS/JS handles the rest."""
    response = await call_next(request)
    if request.url.path in ("/", "/index.html"):
        response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


# Mount frontend directory for static assets and HTML UI
frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
if os.path.exists(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
