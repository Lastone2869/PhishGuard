"""
email_clean.py
Safe, deterministic cleaning for raw email sources.

Every function is pure and network-free. HTML is parsed with the stdlib
HTMLParser, payloads are decoded with the declared charset, and PII is redacted
before anything is written to a dataset file.
"""

from __future__ import annotations

import email
import re
from email.message import Message
from html.parser import HTMLParser

_BLOCK_TAGS = {
    "p", "div", "br", "tr", "li", "ul", "ol", "table", "thead", "tbody",
    "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "section", "article",
    "header", "footer", "hr",
}
_HTML_HINT = re.compile(
    r"<\s*/?\s*(?:html|body|head|meta|p|div|a|br|table|span|td|tr|"
    r"font|img|center|b|i|u|strong|em|style|script)\b",
    re.I,
)
_URL_RE = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.I)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"(?<![\dA-Za-z])(?:\+91[\s\-]?)?[6-9]\d{4}[\s\-]?\d{5}(?![\dA-Za-z])")

_QUOTE_MARKERS = [
    re.compile(r"^\s*On .+ wrote:\s*$", re.I | re.M),
    re.compile(r"^\s*-{2,}\s*Original Message\s*-{2,}\s*$", re.I | re.M),
    re.compile(r"^\s*From:\s.*\n\s*Sent:\s", re.I | re.M),
]


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.links: list[dict] = []
        self._href: str | None = None
        self._anchor: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style"}:
            self._skip += 1
            return
        if self._skip:
            return
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._anchor = []
        elif tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"}:
            self._skip = max(0, self._skip - 1)
            return
        if self._skip:
            return
        if tag == "a":
            anchor = _collapse_inline("".join(self._anchor))
            if self._href:
                self.links.append({"anchor": anchor or self._href, "href": self._href})
            self._href = None
            self._anchor = []
        elif tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        self.parts.append(data)
        if self._href is not None:
            self._anchor.append(data)


def _collapse_inline(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("\xa0", " ")).strip()


def _normalise_lines(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\xa0", " ")
    lines = [_collapse_inline(line) for line in text.split("\n")]
    lines = [line for line in lines if line]
    return "\n".join(lines)


def html_to_text(html: str) -> tuple[str, list[dict]]:
    """Convert an HTML body to readable text plus (anchor, href) pairs."""
    if not html:
        return "", []
    if not _HTML_HINT.search(html):
        return html.strip(), []

    parser = _TextExtractor()
    parser.feed(html)
    parser.close()
    return _normalise_lines("".join(parser.parts)), parser.links


def decode_payload(part: Message) -> str:
    """Decode a MIME part using its declared charset, never raising on bad bytes."""
    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_payload()
        return raw if isinstance(raw, str) else ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def trim_quoted(text: str) -> str:
    """Remove quoted replies and forwarded header blocks."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    for marker in _QUOTE_MARKERS:
        match = marker.search(text)
        if match:
            text = text[: match.start()]
    lines = [line for line in text.split("\n") if not line.lstrip().startswith(">")]
    return "\n".join(lines).strip()


def trim_signature(text: str) -> str:
    """Remove the standard '-- ' signature block."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    match = re.search(r"\n--\s*\n", text)
    if match:
        text = text[: match.start()]
    return text.strip()


def parse_sender(raw: str | None) -> tuple[str | None, str | None]:
    """Return (display_name, lowercased_address) for a From header."""
    if not raw or not raw.strip():
        return None, None
    name, address = email.utils.parseaddr(raw)
    name = name.strip() or None
    address = address.strip().lower() or None
    return name, address


def redact_pii(text: str) -> str:
    """Replace emails and Indian mobile numbers, leaving URLs untouched."""
    out: list[str] = []
    cursor = 0
    for match in _URL_RE.finditer(text):
        out.append(_redact_segment(text[cursor : match.start()]))
        out.append(match.group(0))
        cursor = match.end()
    out.append(_redact_segment(text[cursor:]))
    return "".join(out)


def _redact_segment(segment: str) -> str:
    segment = _EMAIL_RE.sub("<EMAIL>", segment)
    return _PHONE_RE.sub("<PHONE>", segment)


def clean_message(subject: str | None, body: str | None) -> dict:
    """Clean one message and return {text, subject, links, warnings}."""
    warnings: list[str] = []
    raw = body or ""
    links: list[dict] = []

    if _HTML_HINT.search(raw):
        raw, links = html_to_text(raw)
        warnings.append("html")

    text = trim_quoted(raw)
    text = trim_signature(text)
    text = _normalise_lines(redact_pii(text))

    clean_subject = subject.strip() if isinstance(subject, str) else ""
    clean_subject = redact_pii(clean_subject) if clean_subject else None

    if not text:
        warnings.append("empty_body")
    if clean_subject is None:
        warnings.append("no_subject")

    return {"text": text, "subject": clean_subject, "links": links, "warnings": warnings}
