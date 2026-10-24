"""
test_fetch_sources.py
Tests the source manifest contract and checksum helpers.
No network access: fetching is exercised manually via the CLI.
"""

import hashlib
import json
from pathlib import Path

import pytest

from training.fetch_sources import (
    ALLOWED_LICENSES,
    load_manifest,
    sha256_file,
    validate_manifest,
)


def _manifest():
    return json.loads(Path("datasets/sources.json").read_text(encoding="utf-8"))


def test_manifest_has_required_fields_for_every_source():
    manifest = _manifest()
    assert manifest["sources"], "manifest must list at least one source"
    for source in manifest["sources"]:
        assert {"name", "url", "license", "sha256", "dest", "kind"} <= set(source)
        assert source["license"] in ALLOWED_LICENSES
        assert source["url"].startswith("https://")
        assert source["kind"] in {"mbox", "tar.bz2"}
        assert source["sha256"] is None or (
            len(source["sha256"]) == 64
            and all(c in "0123456789abcdef" for c in source["sha256"])
        )


def test_manifest_source_names_are_unique():
    names = [s["name"] for s in _manifest()["sources"]]
    assert len(names) == len(set(names))


def test_validate_manifest_rejects_missing_license():
    with pytest.raises(ValueError, match="license"):
        validate_manifest(
            {"sources": [{"name": "x", "url": "https://x", "sha256": None, "dest": "d", "kind": "mbox"}]}
        )


def test_validate_manifest_rejects_unknown_license():
    with pytest.raises(ValueError, match="license"):
        validate_manifest(
            {"sources": [{"name": "x", "url": "https://x", "license": "WTFPL", "sha256": None, "dest": "d", "kind": "mbox"}]}
        )


def test_validate_manifest_rejects_non_https_url():
    with pytest.raises(ValueError, match="https"):
        validate_manifest(
            {"sources": [{"name": "x", "url": "http://x", "license": "CC-BY-4.0", "sha256": None, "dest": "d", "kind": "mbox"}]}
        )


def test_load_manifest_validates(tmp_path):
    path = tmp_path / "sources.json"
    path.write_text(json.dumps({"sources": [
        {"name": "x", "url": "https://x", "license": "project-owned", "sha256": None, "dest": "d", "kind": "mbox"}
    ]}), encoding="utf-8")
    assert load_manifest(path)["sources"][0]["name"] == "x"


def test_sha256_file_matches_known_content(tmp_path):
    path = tmp_path / "a.txt"
    path.write_text("phishguard", encoding="utf-8")
    assert sha256_file(path) == hashlib.sha256(b"phishguard").hexdigest()
