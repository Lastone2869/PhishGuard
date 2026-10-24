"""
detector.py
Orchestrates rule-based phishing signal detection for PhishGuard Stage 1:
1. Urgency detection
2. Credential request detection
3. Suspicious link structure analysis (never visits links)
4. Sender mismatch and impersonation checking (gracefully handles missing senders)
"""

import os
import re
import json
from training.normalise import extract_urls
from backend.url_analyser import analyse_url_structure

# Load trusted domains
TRUSTED_DOMAINS_PATH = os.path.join(os.path.dirname(__file__), "data", "trusted_domains.json")
try:
    with open(TRUSTED_DOMAINS_PATH, "r", encoding="utf-8") as f:
        _td_data = json.load(f)
        TRUSTED_DOMAINS = set(_td_data.get("trusted_domains", []))
        INSTITUTIONAL_KEYWORDS = _td_data.get("institutional_keywords", ["vit", "vtop"])
except Exception:
    TRUSTED_DOMAINS = {"vit.ac.in", "vtop.vit.ac.in", "google.com", "microsoft.com"}
    INSTITUTIONAL_KEYWORDS = ["vit", "vtop"]

URGENCY_PATTERNS = [
    r"\b(?:immediately|without delay|right now|at once)\b",
    r"\bwithin \d{1,2} (?:hours?|hrs?|minutes?|days?)\b",
    r"\b(?:account will be suspended|pending suspension|scheduled for termination)\b",
    r"\b(?:final warning|action required|last notice|critical alert)\b",
    r"\b(?:debarred|de-registration|cancelled|terminated)\b",
    r"\b(?:expires? today|immediate action|urgent notice)\b"
]

CREDENTIAL_VERBS = (
    r"(?:enter|provide|send|share|submit|confirm|verify|re-?enter|type|give|"
    r"reply\s+with|respond\s+with|upload)"
)
CREDENTIAL_NOUNS = (
    r"(?:passwords?|passcode|pin|otp|one[- ]time password|verification code|"
    r"login details|login credentials|student credentials|credentials|"
    r"bank account(?: number)?|ifsc|aadhaar|pan|upi id|credit card|cvv|ssn)"
)

# Detect disclosure requests, not mere mentions. "password expires" and
# "never share your password" must not count as credential solicitation.
CREDENTIAL_PATTERNS = [
    rf"\b{CREDENTIAL_VERBS}\b[^.\n]{{0,60}}?\b{CREDENTIAL_NOUNS}\b",
    r"\b(?:verify (?:your )?account|confirm (?:your )?identity|re-verify)\b",
    r"\bupdate (?:your )?(?:login details|login credentials|credentials)\b",
]

NEGATION_RE = re.compile(
    r"\b(?:never|do not|don't|does not|will not|won't|cannot|can't|"
    r"no need to|not required to)\b[^.\n]{0,40}$",
    re.IGNORECASE,
)

def detect_signals(text: str, sender: str = None) -> dict:
    """
    Detects evidence signals across 4 categories:
    - urgency
    - credential_request
    - suspicious_links
    - sender_mismatch
    """
    signals = {
        "urgency": {
            "present": False,
            "strength": "none",
            "matches": [],
            "explanation": "No urgent deadlines or pressure tactics detected."
        },
        "credential_request": {
            "present": False,
            "strength": "none",
            "matches": [],
            "explanation": "No requests for passwords, OTPs, or authentication credentials found."
        },
        "suspicious_links": {
            "present": False,
            "strength": "none",
            "extracted_urls": [],
            "defanged_urls": [],
            "signals": [],
            "explanation": "No suspicious URLs or concealed destinations identified."
        },
        "sender_mismatch": {
            "present": False,
            "strength": "none",
            "sender_provided": bool(sender and sender.strip()),
            "status": "not_provided" if not (sender and sender.strip()) else "verified",
            "sender": sender.strip() if sender else None,
            "explanation": "Sender information was not provided (authenticity cannot be corroborated from text alone)."
        }
    }

    if not text:
        return signals

    # 1. Urgency Detection
    urgency_matches = []
    for pat in URGENCY_PATTERNS:
        for m in re.finditer(pat, text, flags=re.IGNORECASE):
            urgency_matches.append(m.group(0))
    if urgency_matches:
        signals["urgency"]["present"] = True
        signals["urgency"]["strength"] = "high" if len(urgency_matches) > 1 else "medium"
        signals["urgency"]["matches"] = list(set(urgency_matches))
        spans_str = ", ".join(f"'{s}'" for s in signals["urgency"]["matches"][:3])
        signals["urgency"]["explanation"] = f"Urgency pressure tactic detected ({spans_str}) urging hasty action."

    # 2. Credential Request Detection
    cred_matches = []
    for pat in CREDENTIAL_PATTERNS:
        for m in re.finditer(pat, text, flags=re.IGNORECASE):
            prefix = text[max(0, m.start() - 50) : m.start()]
            if NEGATION_RE.search(prefix):
                continue
            cred_matches.append(m.group(0).strip()[:80])
    if cred_matches:
        signals["credential_request"]["present"] = True
        signals["credential_request"]["strength"] = "high" if len(cred_matches) > 1 else "medium"
        signals["credential_request"]["matches"] = list(set(cred_matches))
        spans_str = ", ".join(f"'{s}'" for s in signals["credential_request"]["matches"][:3])
        signals["credential_request"]["explanation"] = f"Credential solicitation detected ({spans_str}). Legitimate institutions never ask for passwords/OTPs over message."

    # 3. Suspicious Links Analysis (safe - no web access)
    urls = extract_urls(text)
    if urls:
        url_analyses = [
            analyse_url_structure(u, trusted_domains=TRUSTED_DOMAINS) for u in urls
        ]
        signals["suspicious_links"]["extracted_urls"] = urls
        signals["suspicious_links"]["defanged_urls"] = [ua["defanged"] for ua in url_analyses]
        
        flagged_signals = []
        is_any_suspicious = False
        for ua in url_analyses:
            if ua["is_suspicious"]:
                is_any_suspicious = True
                flagged_signals.extend(ua["signals"])
                
        if is_any_suspicious:
            signals["suspicious_links"]["present"] = True
            signals["suspicious_links"]["strength"] = "high"
            signals["suspicious_links"]["signals"] = list(set(flagged_signals))
            signals["suspicious_links"]["explanation"] = f"Suspicious URL structure detected: {'; '.join(signals['suspicious_links']['signals'][:2])}"
        else:
            signals["suspicious_links"]["explanation"] = "Message contains links, but no blatant spoofing/shortener indicators were found."

    # 4. Sender Mismatch & Lookalike Detection
    if sender and sender.strip():
        sender_clean = sender.strip().lower()
        sender_domain = sender_clean.split("@")[-1] if "@" in sender_clean else sender_clean
        
        # Check if text mentions institutional cues
        text_lower = text.lower()
        claims_institution = any(k in text_lower for k in INSTITUTIONAL_KEYWORDS)
        
        if claims_institution:
            if sender_domain == "vit.ac.in" or sender_domain.endswith(".vit.ac.in"):
                signals["sender_mismatch"]["present"] = False
                signals["sender_mismatch"]["status"] = "verified_official"
                signals["sender_mismatch"]["strength"] = "none"
                signals["sender_mismatch"]["explanation"] = f"Sender domain (@{sender_domain}) matches verified institutional domain list."
            else:
                signals["sender_mismatch"]["present"] = True
                signals["sender_mismatch"]["status"] = "lookalike_impersonation"
                signals["sender_mismatch"]["strength"] = "high"
                signals["sender_mismatch"]["explanation"] = f"Impersonation alert: Message claims to represent VIT, but sender domain is '@{sender_domain}' (not official vit.ac.in)."
        else:
            if sender_domain in TRUSTED_DOMAINS or any(sender_domain.endswith("." + td) for td in TRUSTED_DOMAINS):
                signals["sender_mismatch"]["status"] = "verified_external"
                signals["sender_mismatch"]["explanation"] = f"Sender domain (@{sender_domain}) matches recognized domain."
            else:
                signals["sender_mismatch"]["status"] = "unverified_external"
                signals["sender_mismatch"]["explanation"] = f"Sender (@{sender_domain}) is an unverified external address."

    return signals
