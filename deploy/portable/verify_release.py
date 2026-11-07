#!/usr/bin/env python3
"""Validate integrity and schema of an operator-produced portable release bundle.

This does not authenticate a registry digest or approve a deployment.
"""
import hashlib
import json
import pathlib
import re
import sys

FILES = {
    "release.json",
    "deploy.sh",
    "aws-s3-backup.sh",
    "betasoft-openproject-backup.service",
    "betasoft-openproject-backup.timer",
}
CHANNELS = {"pilot", "staging", "production"}
IMAGE_PATTERN = re.compile(r"ghcr\.io/aristha/openproject@sha256:[0-9a-f]{64}\Z")
SHA_PATTERN = re.compile(r"[0-9a-f]{40}\Z")


def verify(directory: pathlib.Path) -> None:
    if not directory.is_dir():
        raise ValueError("Release directory does not exist")
    present = {path.name for path in directory.iterdir()}
    if present != FILES | {"SHA256SUMS"}:
        raise ValueError(f"Unexpected release bundle files: {sorted(present ^ (FILES | {'SHA256SUMS'}))}")

    manifest = {}
    for line in (directory / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([a-zA-Z0-9_.-]+)", line)
        if not match or match.group(2) in manifest:
            raise ValueError("Malformed or duplicate SHA256SUMS entry")
        manifest[match.group(2)] = match.group(1)
    if set(manifest) != FILES:
        raise ValueError("Checksums do not match expected release filenames")
    for name, digest in manifest.items():
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Non-file or symlink in release bundle: {name}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError(f"Checksum mismatch: {name}")

    data = json.loads((directory / "release.json").read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) != {
        "schema_version", "environment", "image", "source_sha",
        "deployment_mode", "migrations"
    }:
        raise ValueError("Unexpected release schema")
    if data["schema_version"] != 1 or data["environment"] not in CHANNELS:
        raise ValueError("Invalid release channel or schema version")
    if not isinstance(data["image"], str) or not IMAGE_PATTERN.fullmatch(data["image"]):
        raise ValueError("Only immutable expected GHCR images are allowed")
    if not isinstance(data["source_sha"], str) or not SHA_PATTERN.fullmatch(data["source_sha"]):
        raise ValueError("Source SHA must be a full immutable commit hash")
    if data["deployment_mode"] != "manual-on-host" or data["migrations"] != "not-performed":
        raise ValueError("Release must not claim automatic deploy or migrations")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("Usage: verify_release.py <release-dir>")
        verify(pathlib.Path(sys.argv[1]))
        print("RELEASE_BUNDLE_VERIFIED: local checksums, files and metadata; NOT authenticated provenance")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Release bundle rejected: {exc}", file=sys.stderr)
        sys.exit(1)
