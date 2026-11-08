"""Offline tests for Phase 5 online acceptance controls; no network used."""
import base64
import json
import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "agent"))

from accept_signed_ghcr_candidate import (IDENTITY, IMAGE_NAME, policy_for,
                                          run_acceptance)
from image_provenance import ProvenanceError


class RegistryAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.digest = "sha256:" + "b" * 64
        self.source = "a" * 40
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "ghcr.io/aristha/openproject",
                         "digest": {"sha256": "b" * 64}}],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {"buildDefinition": {"resolvedDependencies": [{
                "uri": "git+https://github.com/aristha/openproject",
                "digest": {"gitCommit": self.source},
            }]}},
        }
        self.stdout = json.dumps([{"payload": base64.b64encode(
            json.dumps(statement).encode()).decode()}]).encode()
        self.calls = []

    def runner(self, command, **kwargs):
        self.calls.append(command)
        identity = command[command.index("--certificate-identity") + 1]
        return mock.Mock(returncode=0 if identity == IDENTITY and
                         command[-1] == IMAGE_NAME + self.digest else 1,
                         stdout=self.stdout)

    def test_positive_and_three_negative_gates(self):
        self.assertTrue(run_acceptance(self.digest, self.source, runner=self.runner))
        self.assertEqual(len(self.calls), 4)
        self.assertTrue(all("--certificate-identity" in c for c in self.calls))
        self.assertTrue(all("--certificate-oidc-issuer" in c for c in self.calls))
        self.assertTrue(all("--insecure-ignore-tlog" not in c for c in self.calls))

    def test_forged_source_sha_fails(self):
        with self.assertRaises(ProvenanceError):
            run_acceptance(self.digest, "c" * 40, runner=self.runner)

    def test_unsigned_registry_response_fails(self):
        def fail(*args, **kwargs):
            return mock.Mock(returncode=1, stdout=self.stdout)
        with self.assertRaises(ProvenanceError):
            run_acceptance(self.digest, self.source, runner=fail)

    def test_wrong_signer_accepted_is_failure(self):
        def all_good(*args, **kwargs):
            return mock.Mock(returncode=0, stdout=self.stdout)
        with self.assertRaisesRegex(ProvenanceError, "signer identity"):
            run_acceptance(self.digest, self.source, runner=all_good)

    def test_wrong_digest_accepted_is_failure(self):
        def digest_bug(command, **kwargs):
            identity = command[command.index("--certificate-identity") + 1]
            return mock.Mock(returncode=0 if identity == IDENTITY else 1,
                             stdout=self.stdout)
        with self.assertRaisesRegex(ProvenanceError, "image digest"):
            run_acceptance(self.digest, self.source, runner=digest_bug)

    def test_reject_mutable_tag(self):
        with self.assertRaises(ProvenanceError):
            policy_for("latest", self.source)

    def test_reject_short_source(self):
        with self.assertRaises(ProvenanceError):
            policy_for(self.digest, "a" * 8)

    def test_policy_workflow_pinned(self):
        p = policy_for(self.digest, self.source)
        self.assertEqual(p["certificate_identity"], IDENTITY)
        self.assertEqual(p["build_sha"], self.source)
        self.assertEqual(p["image"], IMAGE_NAME + self.digest)

    def test_no_api_or_deploy_side_effect(self):
        content = (pathlib.Path(__file__).resolve().parent /
                   "accept_signed_ghcr_candidate.py").read_text()
        for forbidden in ("docker push", "cosign attest", "docker compose",
                          "systemctl", "ec2 start-instances", "curl -X POST"):
            self.assertNotIn(forbidden, content)


if __name__ == "__main__":
    unittest.main()
