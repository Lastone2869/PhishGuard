"""
fetch_sources.py
Downloads and verifies the external datasets listed in datasets/sources.json.

This is the only module allowed to make outbound requests. It is never imported
by the API, the models, or the test suite's default path; it runs only when the
dataset is being (re)built.

Usage:
    python -m training.fetch_sources --dest datasets/raw/external
    python -m training.fetch_sources --dest datasets/raw/external --extract
    python -m training.fetch_sources --dest datasets/raw/external --only nazario-2023
"""

from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_MANIFEST = Path("datasets/sources.json")
ALLOWED_LICENSES = {"CC-BY-4.0", "public-research", "project-owned"}
ALLOWED_KINDS = {"mbox", "tar.bz2"}
USER_AGENT = "phishguard-dataset/1.0 (educational project)"


def sha256_file(path: Path) -> str:
    """Return the lowercase hex SHA-256 of a file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_manifest(manifest: dict[str, Any]) -> None:
    """Raise ValueError if the manifest is missing required fields or bad values."""
    sources = manifest.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("manifest must contain a non-empty 'sources' list")

    for source in sources:
        name = source.get("name", "<unnamed>")
        for field in ("url", "license", "dest", "kind"):
            if not source.get(field):
                raise ValueError(f"source {name!r} is missing required field {field!r}")

        if source["license"] not in ALLOWED_LICENSES:
            raise ValueError(
                f"source {name!r} has unsupported license {source['license']!r}; "
                f"allowed: {sorted(ALLOWED_LICENSES)}"
            )
        if not str(source["url"]).startswith("https://"):
            raise ValueError(f"source {name!r} URL must use https://")
        if source["kind"] not in ALLOWED_KINDS:
            raise ValueError(f"source {name!r} has unsupported kind {source['kind']!r}")

        checksum = source.get("sha256")
        if checksum is not None and not (
            isinstance(checksum, str)
            and len(checksum) == 64
            and all(c in "0123456789abcdef" for c in checksum)
        ):
            raise ValueError(f"source {name!r} has an invalid sha256 value")


def load_manifest(path: Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    """Load and validate the manifest."""
    manifest = json.loads(Path(path).read_text(encoding="utf-8"))
    validate_manifest(manifest)
    return manifest


def _download(url: str, target: Path) -> None:
    """Download url to target atomically via a .part file."""
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_suffix(target.suffix + ".part")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=120) as response, partial.open("wb") as out:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            out.write(chunk)
    partial.replace(target)


def fetch_sources(
    dest: Path,
    only: list[str] | None = None,
    manifest_path: Path = DEFAULT_MANIFEST,
) -> list[Path]:
    """
    Download every manifest source (or only the named ones) into dest.

    Existing files are reused after checksum verification. Newly computed
    checksums are written back to the manifest so later runs can verify them.
    Returns the list of downloaded/local paths.
    """
    manifest = load_manifest(manifest_path)
    selected = [
        source for source in manifest["sources"]
        if only is None or source["name"] in only
    ]
    if only and len(selected) != len(only):
        missing = sorted(set(only) - {source["name"] for source in selected})
        raise ValueError(f"unknown source name(s): {missing}")

    dest = Path(dest)
    paths: list[Path] = []
    changed = False
    for source in selected:
        target = dest / source["dest"]
        if not target.exists():
            print(f"[fetch] {source['name']}: {source['url']}")
            _download(source["url"], target)
            source["sha256"] = sha256_file(target)
            changed = True
        else:
            print(f"[skip]  {source['name']}: already present")

        actual = sha256_file(target)
        expected = source.get("sha256")
        if expected and actual != expected:
            raise ValueError(
                f"checksum mismatch for {source['name']}: expected {expected}, got {actual}"
            )
        if not expected:
            source["sha256"] = actual
            changed = True
        paths.append(target)

    if changed:
        manifest_path.write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        print(f"[write] updated checksums in {manifest_path}")

    return paths


def extract_sources(
    dest: Path,
    only: list[str] | None = None,
    manifest_path: Path = DEFAULT_MANIFEST,
) -> list[Path]:
    """Extract tar.bz2 sources next to their archives; leave mbox files alone."""
    manifest = load_manifest(manifest_path)
    extracted: list[Path] = []
    for source in manifest["sources"]:
        if only is not None and source["name"] not in only:
            continue
        if source["kind"] != "tar.bz2":
            continue
        archive = Path(dest) / source["dest"]
        if not archive.exists():
            raise FileNotFoundError(f"archive not downloaded: {archive}")
        out_dir = archive.parent
        with tarfile.open(archive, "r:bz2") as tar:
            tar.extractall(path=out_dir, filter="data")
        print(f"[unpack] {archive.name} -> {out_dir}")
        extracted.append(out_dir)
    return extracted


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dest", default="datasets/raw/external", type=Path)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST, type=Path)
    parser.add_argument("--only", action="append", default=None)
    parser.add_argument("--extract", action="store_true")
    args = parser.parse_args(argv)

    fetch_sources(args.dest, only=args.only, manifest_path=args.manifest)
    if args.extract:
        extract_sources(args.dest, only=args.only, manifest_path=args.manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
