"""
test_email_clean.py
Unit tests for HTML extraction, payload decoding, quote/signature trimming,
sender parsing, PII redaction, and the clean_message composition.
"""

import email
from email.mime.text import MIMEText

from training.email_clean import (
    clean_message,
    decode_payload,
    html_to_text,
    parse_sender,
    redact_pii,
    trim_quoted,
    trim_signature,
)


def test_html_to_text_keeps_anchor_words_and_drops_tags():
    text, links = html_to_text(
        '<p>Verify <a href="http://vit-fake.info/x">your account</a> now</p>'
    )
    assert "Verify your account now" in text
    assert "<p>" not in text
    assert links == [{"anchor": "your account", "href": "http://vit-fake.info/x"}]


def test_html_to_text_handles_entities_breaks_and_scripts():
    text, _ = html_to_text(
        "<div>Fee&nbsp;due &amp; payable<br>Pay now<script>alert(1)</script></div>"
    )
    assert "alert" not in text
    assert "Fee due & payable" in text
    assert "Pay now" in text.splitlines()


def test_html_to_text_passes_through_plain_text():
    text, links = html_to_text("Just a plain message.")
    assert text == "Just a plain message."
    assert links == []


def test_decode_payload_handles_base64_and_charset():
    msg = email.message_from_string(
        "Content-Type: text/plain; charset=utf-8\n"
        "Content-Transfer-Encoding: base64\n\n"
        "aGVsbG8="
    )
    assert decode_payload(msg) == "hello"

    latin = MIMEText("café", "plain", "latin-1")
    assert "café" in decode_payload(latin)


def test_trim_quoted_removes_reply_chain():
    raw = "Please pay now.\n\nOn Mon, 5 Oct 2026, VIT wrote:\n> old message\n> more"
    assert trim_quoted(raw) == "Please pay now."


def test_trim_quoted_removes_outlook_header_block():
    raw = "Action needed.\n\nFrom: VIT\nSent: Monday\nTo: student\nSubject: Fees"
    assert trim_quoted(raw) == "Action needed."


def test_trim_quoted_keeps_normal_prose_starting_with_on():
    raw = "On Monday we will meet in the library."
    assert trim_quoted(raw) == raw


def test_trim_quoted_drops_leading_quote_markers():
    assert trim_quoted("> quoted line\nActual line") == "Actual line"


def test_trim_signature_removes_signature_block():
    assert trim_signature("Body text.\n\n-- \nRegards, IT") == "Body text."


def test_parse_sender_display_name_and_address():
    assert parse_sender('"VIT Helpdesk" <HelpDesk@VIT.ac.in>') == (
        "VIT Helpdesk",
        "helpdesk@vit.ac.in",
    )
    assert parse_sender("helpdesk@vit.ac.in") == (None, "helpdesk@vit.ac.in")
    assert parse_sender("") == (None, None)


def test_redact_pii_replaces_email_and_phone_but_keeps_url():
    out = redact_pii("Mail me at a.b@x.com or +91 98765 43210, see http://vit.ac.in/help")
    assert "<EMAIL>" in out
    assert "<PHONE>" in out
    assert "a.b@x.com" not in out
    assert "98765" not in out
    assert "http://vit.ac.in/help" in out


def test_redact_pii_does_not_touch_years_or_short_numbers():
    out = redact_pii("Semester 2026, room 12345, roll 21BCE1234")
    assert out == "Semester 2026, room 12345, roll 21BCE1234"


def test_clean_message_handles_missing_fields():
    out = clean_message(None, "")
    assert out["text"] == ""
    assert out["subject"] is None
    assert out["links"] == []
    assert "empty_body" in out["warnings"]
    assert "no_subject" in out["warnings"]


def test_clean_message_strips_html_and_redacts():
    out = clean_message(
        "URGENT",
        '<p>Send your password to <a href="http://evil.example/x">this page</a>.</p>'
        "Call 9876543210.",
    )
    assert "this page" in out["text"]
    assert "<p>" not in out["text"]
    assert "<PHONE>" in out["text"]
    assert out["links"][0]["href"] == "http://evil.example/x"
    assert out["subject"] == "URGENT"
