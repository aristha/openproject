"""Offline regression tests for manual, signed GHCR candidate build contract."""
import base64
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "agent"))

from write_slsa_build_predicate import predicate, SOURCE, WORKFLOW
from check_verified_build_attestation import check


class SignedBuildContractTests(unittest.TestCase):
    def setUp(self):
        self.source = "a" * 40
        self.digest = "sha256:" + "b" * 64
        self.pred = predicate(self.source, self.digest, 123, 1)

    def verified_json(self):
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{"name": "ghcr.io/aristha/openproject",
                         "digest": {"sha256": self.digest.removeprefix("sha256:")}}],
            "predicate": self.pred,
        }
        return json.dumps([{"payload": base64.b64encode(
            json.dumps(statement).encode()).decode()}]).encode()

    def test_producer_matches_consumer(self):
        self.assertTrue(check(self.verified_json(), self.source, self.digest))

    def test_predicate_build_dependency(self):
        dep = self.pred["buildDefinition"]["resolvedDependencies"][0]
        self.assertEqual(dep, {"uri": SOURCE, "digest": {"gitCommit": self.source}})
        self.assertEqual(self.pred["runDetails"]["builder"]["id"], WORKFLOW + "@refs/heads/dev")

    def test_reject_bad_source_sha(self):
        with self.assertRaises(ValueError):
            predicate("bad", self.digest, 123, 1)

    def test_reject_mutable_tag(self):
        with self.assertRaises(ValueError):
            predicate(self.source, "latest", 123, 1)

    def test_reject_invalid_run_id(self):
        with self.assertRaises(ValueError):
            predicate(self.source, self.digest, 0, 1)
        with self.assertRaises(ValueError):
            predicate(self.source, self.digest, True, 1)

    def test_reject_wrong_build_sha(self):
        with self.assertRaises(ValueError):
            check(self.verified_json(), "c" * 40, self.digest)

    def test_reject_wrong_image_digest(self):
        with self.assertRaises(ValueError):
            check(self.verified_json(), self.source, "sha256:" + "c" * 64)

    def test_reject_unsigned_plain_statement(self):
        with self.assertRaises(ValueError):
            check(json.dumps([{"predicate": self.pred}]).encode(), self.source, self.digest)

    def test_workflow_is_manual_only(self):
        workflow = (pathlib.Path(__file__).resolve().parents[2] /
                    ".github/workflows/fork-build-attested-image.yml").read_text()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("\n  push:", workflow)
        self.assertNotIn("\n  pull_request:", workflow)
        self.assertIn("github.ref == 'refs/heads/dev'", workflow)
        self.assertIn("environment: pilot", workflow)
        self.assertIn("cosign attest --yes --type slsaprovenance1", workflow)
        self.assertIn("cosign verify-attestation --type slsaprovenance1", workflow)
        self.assertIn("SOURCE_SHA", __import__("write_slsa_build_predicate").__dict__)
        self.assertIn("provenance: mode=min", workflow)
        self.assertIn("persist-credentials: false", workflow)

    def test_no_host_deploy_or_unpinned_actions(self):
        workflow = (pathlib.Path(__file__).resolve().parents[2] /
                    ".github/workflows/fork-build-attested-image.yml").read_text()
        for forbidden in ("ssh ", "kubectl ", "systemctl ", "docker compose", "ec2 start-instances",
                          "--execute", "openproject:latest", "deploy.sh"):
            self.assertNotIn(forbidden, workflow)
        import re
        for ref in re.findall(r"^\s+uses:\s+[^@\s]+@([^\s]+)", workflow, re.M):
            self.assertRegex(ref, r"^[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
