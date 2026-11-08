"""Offline security regression coverage for signed provenance validation."""
import base64
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock

import image_provenance as provenance


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.digest = "a" * 64
        self.build_sha = "b" * 40
        self.image = "ghcr.io/aristha/openproject@sha256:" + self.digest
        self.policy = {
            "schema_version": 1,
            "image": self.image,
            "build_sha": self.build_sha,
            "certificate_identity": "https://github.com/aristha/openproject/.github/workflows/build-image.yml@refs/heads/dev",
            "certificate_oidc_issuer": provenance.ISSUER,
            "source_repository": "aristha/openproject",
        }
        self.statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "ghcr.io/aristha/openproject",
                         "digest": {"sha256": self.digest}}],
            "predicateType": provenance.PREDICATE,
            "predicate": {"buildDefinition": {
                "resolvedDependencies": [{"uri": "git+https://github.com/aristha/openproject",
                                           "digest": {"gitCommit": self.build_sha}}]
            }},
        }

    def encoded(self):
        return json.dumps([{"payload": base64.b64encode(
            json.dumps(self.statement).encode()).decode()}]).encode()

    def test_valid_statement(self):
        self.assertTrue(provenance.parse_verified_cosign(self.encoded(), self.policy))

    def test_wrong_subject_digest(self):
        self.statement["subject"][0]["digest"]["sha256"] = "c" * 64
        with self.assertRaises(provenance.ProvenanceError):
            provenance.parse_verified_cosign(self.encoded(), self.policy)

    def test_wrong_source_commit(self):
        self.statement["predicate"]["buildDefinition"]["resolvedDependencies"][0]["digest"]["gitCommit"] = "d" * 40
        with self.assertRaises(provenance.ProvenanceError):
            provenance.parse_verified_cosign(self.encoded(), self.policy)

    def test_wrong_source_repository(self):
        self.statement["predicate"]["buildDefinition"]["resolvedDependencies"][0]["uri"] = "git+https://github.com/attacker/openproject"
        with self.assertRaises(provenance.ProvenanceError):
            provenance.parse_verified_cosign(self.encoded(), self.policy)

    def test_wrong_predicate(self):
        self.statement["predicateType"] = "https://example.com/unsigned"
        with self.assertRaises(provenance.ProvenanceError):
            provenance.parse_verified_cosign(self.encoded(), self.policy)

    def test_unsigned_cosign_output_rejected(self):
        with self.assertRaises(provenance.ProvenanceError):
            provenance.parse_verified_cosign(json.dumps([self.statement]).encode(), self.policy)

    def test_keyless_verifier_failure_is_fail_closed(self):
        def fake_run(command, **kwargs):
            self.assertIn("--certificate-identity", command)
            self.assertIn("--certificate-oidc-issuer", command)
            self.assertNotIn("--insecure-ignore-tlog", command)
            self.assertNotIn("--insecure-ignore-sct", command)
            return mock.Mock(returncode=1, stdout=self.encoded())
        with self.assertRaises(provenance.ProvenanceError):
            provenance.verify_image(self.image, self.policy, runner=fake_run)

    def test_successful_cosign_verification(self):
        def fake_run(command, **kwargs):
            self.assertEqual(command[-1], self.image)
            self.assertEqual(command[0], "/usr/local/bin/cosign")
            return mock.Mock(returncode=0, stdout=self.encoded())
        self.assertTrue(provenance.verify_image(self.image, self.policy, runner=fake_run))

    def test_wrong_image_rejected_before_cosign(self):
        with self.assertRaises(provenance.ProvenanceError):
            provenance.verify_image("ghcr.io/attacker/image@sha256:" + self.digest,
                                    self.policy, runner=mock.Mock())

    def test_untrusted_signer_policy(self):
        bad = dict(self.policy, certificate_identity=
                   "https://github.com/attacker/openproject/.github/workflows/build.yml@refs/heads/dev")
        with mock.patch.object(provenance, "control_file", return_value=json.dumps(bad)):
            with self.assertRaises(provenance.ProvenanceError):
                provenance.load_policy(Path("/etc/betasoft/policy.json"))

    def test_untrusted_signer_ref(self):
        bad = dict(self.policy, certificate_identity=
                   "https://github.com/aristha/openproject/.github/workflows/build.yml@refs/pull/4/merge")
        with mock.patch.object(provenance, "control_file", return_value=json.dumps(bad)):
            with self.assertRaises(provenance.ProvenanceError):
                provenance.load_policy(Path("/etc/betasoft/policy.json"))

    def test_cosign_timeout(self):
        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd="cosign", timeout=90)
        with self.assertRaises(provenance.ProvenanceError):
            provenance.verify_image(self.image, self.policy, runner=timeout)


if __name__ == "__main__":
    unittest.main()
