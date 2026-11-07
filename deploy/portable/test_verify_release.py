#!/usr/bin/env python3
"""Offline tests: no cloud or registry access."""
import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest

MODULE_PATH = pathlib.Path(__file__).with_name("verify_release.py")
spec = importlib.util.spec_from_file_location("verify_release", MODULE_PATH)
verify_release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify_release)


class ReleaseBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        for filename in verify_release.FILES - {"release.json"}:
            (self.root / filename).write_text("placeholder", encoding="utf-8")
        self.data = {
            "schema_version": 1,
            "environment": "pilot",
            "image": "ghcr.io/aristha/openproject@sha256:" + "a" * 64,
            "source_sha": "b" * 40,
            "deployment_mode": "manual-on-host",
            "migrations": "not-performed",
        }
        self.write_manifest()

    def write_manifest(self):
        (self.root / "release.json").write_text(json.dumps(self.data), encoding="utf-8")
        (self.root / "SHA256SUMS").write_text(
            "".join(
                hashlib.sha256((self.root / name).read_bytes()).hexdigest()
                + "  " + name + "\n"
                for name in sorted(verify_release.FILES)
            ),
            encoding="utf-8",
        )

    def test_valid(self):
        verify_release.verify(self.root)

    def test_tampered_file(self):
        (self.root / "deploy.sh").write_text("tampered", encoding="utf-8")
        with self.assertRaises(ValueError):
            verify_release.verify(self.root)

    def test_mutable_image(self):
        self.data["image"] = "ghcr.io/aristha/openproject:latest"
        self.write_manifest()
        with self.assertRaises(ValueError):
            verify_release.verify(self.root)

    def test_unknown_file(self):
        (self.root / "credential.txt").write_text("unexpected", encoding="utf-8")
        with self.assertRaises(ValueError):
            verify_release.verify(self.root)

    def test_schema_claims_migration(self):
        self.data["migrations"] = "applied"
        self.write_manifest()
        with self.assertRaises(ValueError):
            verify_release.verify(self.root)

    def test_path_traversal_manifest(self):
        with (self.root / "SHA256SUMS").open("a", encoding="utf-8") as stream:
            stream.write("0" * 64 + "  ../secrets\n")
        with self.assertRaises(ValueError):
            verify_release.verify(self.root)


if __name__ == "__main__":
    unittest.main()
