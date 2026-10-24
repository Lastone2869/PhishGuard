"""
url_analyser.py
Safe URL analysis and defanging module.
Inspects link text and syntactic structure only.
CRITICAL SAFETY RULE: NEVER MAKES OUTBOUND NETWORK REQUESTS TO ANY LINK.
"""

import re
from urllib.parse import urlparse

# Shortener domain patterns
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc"
}

# Suspicious/high-abuse TLDs often seen in student phishing
SUSPICIOUS_TLDS = {
    "xyz", "top", "cc", "info", "me", "biz", "online", "club",
    "live", "work", "loan", "click", "rest", "surf"
}

IPV4_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$")

def defang_url(url: str) -> str:
    """
    Converts a clickable or active URL into a defanged representation.
    E.g.: 'http://example.com/test' -> 'hxxp://example[.]com/test'
    """
    if not url:
        return ""
    # Replace http/https scheme with hxxp/hxxps
    defanged = re.sub(r"^https://", "hxxps://", url, flags=re.IGNORECASE)
    defanged = re.sub(r"^http://", "hxxp://", defanged, flags=re.IGNORECASE)
    # Defang dots in the domain portion
    parsed = urlparse(url if "://" in url else "http://" + url)
    netloc_defanged = parsed.netloc.replace(".", "[.]")
    if parsed.netloc:
        defanged = defanged.replace(parsed.netloc, netloc_defanged, 1)
    return defanged

def analyse_url_structure(url: str, trusted_domains: set[str] | None = None) -> dict:
    """
    Analyses the lexical and structural properties of a URL safely from text.
    Returns detected risk signals and whether the URL is suspicious.

    Domains in trusted_domains (and their subdomains) skip the heuristics that
    are normal for institutions, such as vtop.vit.ac.in having four labels.
    """
    signals = []
    suspicious = False
    trusted_set = {domain.lower().strip(".") for domain in (trusted_domains or set())}

    # Normalize url with a scheme for urlparse if missing
    parsed_url = url if "://" in url else "http://" + url
    try:
        parsed = urlparse(parsed_url)
    except Exception:
        return {
            "url": url,
            "defanged": defang_url(url),
            "is_suspicious": True,
            "trusted": False,
            "signals": ["Malformed or unparseable URL string"]
        }

    # Extract hostname safely (handles ports, userinfo, and IPv6 properly)
    host = (parsed.hostname or "").lower()
    is_ip = bool(IPV4_REGEX.match(host))
    trusted = bool(host) and any(
        host == domain or host.endswith("." + domain) for domain in trusted_set
    )

    # 1. IP Address Host Check
    if is_ip:
        signals.append(f"Raw IP address used as host ({host}) rather than a registered domain name")
        suspicious = True

    # 2. Known URL Shortener Check
    for shortener in SHORTENER_DOMAINS:
        if host == shortener or host.endswith("." + shortener):
            signals.append(f"Known URL shortener ({shortener}) conceals real destination")
            suspicious = True
            break

    # 3. '@' Symbol in URL
    if parsed.netloc and "@" in parsed.netloc:
        signals.append("URL authority contains '@' character which can conceal the true destination host")
        suspicious = True
    elif "@" in url:
        signals.append("URL contains '@' character which can conceal the true destination host")
        suspicious = True

    # 4. Excessive Subdomains Check (exclude IP addresses and trusted domains)
    if not is_ip and not trusted:
        subdomain_parts = host.split(".")
        if len(subdomain_parts) >= 4:
            signals.append(f"Unusually deep subdomain hierarchy ({len(subdomain_parts)} levels) in host: '{host}'")
            suspicious = True

        # 5. Suspicious TLD Check
        tld = subdomain_parts[-1] if subdomain_parts else ""
        if tld in SUSPICIOUS_TLDS:
            signals.append(f"High-risk top-level domain (.{tld}) commonly associated with phishing campaigns")
            suspicious = True

    # 6. Lookalike keywords in non-official domains (e.g., 'vit-login', 'vtop-auth')
    phish_cues = ["vit-", "-vit", "vtop", "portal-login", "account-verify", "kyc", "suspended"]
    if not trusted:
        for cue in phish_cues:
            if cue in host:
                signals.append(f"Host '{host}' mimics institutional credentials with '{cue}' token")
                suspicious = True
                break

    return {
        "url": url,
        "defanged": defang_url(url),
        "is_suspicious": suspicious,
        "trusted": trusted,
        "signals": signals
    }
