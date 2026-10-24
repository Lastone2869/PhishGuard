"""
normalise.py
Text normalisation and cleaning module for PhishGuard.
Handles Unicode normalisation, zero-width characters, homoglyphs,
URL extraction and masking, and whitespace cleanup.
"""

import re
import unicodedata

# Common zero-width characters used for evasion
ZERO_WIDTH_CHARS = [
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\ufeff",  # zero-width no-break space
    "\u200e",  # left-to-right mark
    "\u200f",  # right-to-left mark
]

# Common Cyrillic and Greek homoglyphs used in phishing
HOMOGLYPH_MAP = {
    # Cyrillic lookalikes
    "а": "a", "А": "A",
    "в": "b", "В": "B",
    "с": "c", "С": "C",
    "е": "e", "Е": "E",
    "о": "o", "О": "O",
    "р": "p", "Р": "P",
    "х": "x", "Х": "X",
    "у": "y", "У": "Y",
    "і": "i", "І": "I",
    "ј": "j", "Ј": "J",
    "ѕ": "s", "Ѕ": "S",
    "ԁ": "d", "Ԃ": "D",
    "ԛ": "q", "Ԛ": "Q",
    "ԝ": "w", "Ԝ": "W",
    "М": "M", "м": "m",
    "Н": "H", "н": "h",
    "Т": "T", "т": "t",
    "К": "K", "к": "k",
    # Greek lookalikes
    "α": "a", "Α": "A",
    "ο": "o", "Ο": "O",
    "ν": "v", "Ν": "N",
}

# Regex to safely detect URLs (does NOT resolve or visit them)
URL_REGEX = re.compile(
    r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
)

def remove_zero_width(text: str) -> str:
    """Removes all zero-width characters from text."""
    for ch in ZERO_WIDTH_CHARS:
        text = text.replace(ch, "")
    return text

def map_homoglyphs(text: str) -> str:
    """Replaces common non-Latin lookalike characters with their ASCII counterparts."""
    res = []
    for ch in text:
        res.append(HOMOGLYPH_MAP.get(ch, ch))
    return "".join(res)

def deobfuscate_leetspeak(text: str) -> str:
    """
    Standard de-obfuscation for common phishing keywords.
    E.g., 'l0gin' -> 'login', 'p@ssword' -> 'password'.
    """
    replacements = [
        (r"\bl[0o]g[i1!]n\b", "login"),
        (r"\bp[@a]ssw[o0]rd\b", "password"),
        (r"\bv[i1!]t\b", "vit"),
        (r"\bv[t7][o0]p\b", "vtop"),
        (r"\bacc[o0]unt\b", "account"),
        (r"\bver[i1!]fy\b", "verify"),
        (r"\bsecu[r1]ty\b", "security"),
    ]
    for pattern, rep in replacements:
        text = re.sub(pattern, rep, text, flags=re.IGNORECASE)
    return text

def extract_urls(text: str) -> list[str]:
    """Safely extracts all URL strings from the input text without performing network access."""
    if not text:
        return []
    matches = URL_REGEX.findall(text)
    urls = []
    for match in matches:
        if isinstance(match, tuple):
            urls.append(match[0])
        else:
            urls.append(match)
    return urls

def mask_urls(text: str, mask: str = " [URL_TOKEN] ") -> str:
    """Replaces URLs with a generic mask token for text classification."""
    return URL_REGEX.sub(mask, text)

def clean_whitespace(text: str) -> str:
    """Collapses multiple spaces, tabs, and newlines into clean single spaces."""
    return re.sub(r"\s+", " ", text).strip()

def normalise_text(text: str, mask_url: bool = True) -> str:
    """
    Comprehensive normalisation pipeline:
    1. Unicode NFKD normalisation
    2. Zero-width character removal
    3. Homoglyph substitution
    4. Leetspeak deobfuscation
    5. URL extraction/masking (optional)
    6. Whitespace cleanup and lowercasing
    """
    if not text or not isinstance(text, str):
        return ""

    # 1. Unicode decomposition & normalisation
    t = unicodedata.normalize("NFKD", text)

    # 2. Strip zero-width evasion bytes
    t = remove_zero_width(t)

    # 3. Replace lookalikes
    t = map_homoglyphs(t)

    # 4. De-obfuscate common evasion tokens
    t = deobfuscate_leetspeak(t)

    # 5. Mask URLs if requested
    if mask_url:
        t = mask_urls(t)

    # 6. Lowercase & clean spacing
    t = clean_whitespace(t.lower())

    return t

if __name__ == "__main__":
    test_sample = "URGENT:\u200b V1T Student Аccount (l0gin) at http://vit-fake.com!"
    print("Original (escaped): ", test_sample.encode("ascii", "backslashreplace").decode("ascii"))
    print("Extracted URLs:     ", extract_urls(test_sample))
    print("Normalised:         ", normalise_text(test_sample))
