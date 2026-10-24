"""
test_url_analyser.py
Tests URL structural analysis, defanging, and safe handling.
MANDATORY SAFETY CHECK (§1.6):
Verifies that analyzing arbitrary URLs never attempts to resolve or initiate outbound network sockets.
"""

import socket
import pytest
from backend.url_analyser import defang_url, analyse_url_structure

def test_defang_url():
    raw_url = "http://vit-fake-portal.xyz/login.php?user=student"
    defanged = defang_url(raw_url)
    assert defanged.startswith("hxxp://")
    assert "[.]" in defanged
    assert "vit-fake-portal[.]xyz" in defanged

    https_url = "https://vtop-auth.info/verify"
    defanged_https = defang_url(https_url)
    assert defanged_https.startswith("hxxps://")
    assert "vtop-auth[.]info" in defanged_https

def test_analyse_url_ip_host():
    res = analyse_url_structure("http://192.168.1.100/vit_auth")
    assert res["is_suspicious"] is True
    assert any("IP address" in s for s in res["signals"])

def test_analyse_url_shortener():
    res = analyse_url_structure("http://bit.ly/vit-portal-renew")
    assert res["is_suspicious"] is True
    assert any("shortener" in s for s in res["signals"])

def test_analyse_url_suspicious_tld():
    res = analyse_url_structure("http://vit-portal.xyz/login")
    assert res["is_suspicious"] is True
    assert any("top-level domain" in s for s in res["signals"])

def test_zero_network_activity_guarantee(monkeypatch):
    """
    Simulates a strictly disconnected environment by blocking socket creation.
    Proves that analysing a suspicious URL does not trigger any outbound network connection.
    """
    def blocked_connect(*args, **kwargs):
        raise AssertionError("SECURITY VIOLATION: Outbound network connection attempted during URL analysis!")

    monkeypatch.setattr(socket.socket, "connect", blocked_connect)

    # Analyse a simulated phishing link - MUST NOT touch the socket
    res = analyse_url_structure("http://malicious-external-vit-hack.xyz/steal?creds=1")
    assert res["is_suspicious"] is True
    assert "malicious-external-vit-hack[.]xyz" in res["defanged"]
