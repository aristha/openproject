"""Offline tests for Phase 5 online acceptance controls; no network used."""
import base64
import json
import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "agent"))

from accept_signed_ghcr_candidate import (IDENTITY, IMAGE_NAME, AcceptanceStageError,
                                          policy_for, run_acceptance, safe_diagnostic)
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
        self.assertEqual(command[0], "/home/runner/.cosign/cosign")
        self.assertEqual(kwargs["env"].get("HOME"), "/home/runner")
        identity = command[command.index("--certificate-identity") + 1]
        return mock.Mock(returncode=0 if identity == IDENTITY and
                         command[-1] == IMAGE_NAME + self.digest else 1,
                         stdout=self.stdout)

    @mock.patch("accept_signed_ghcr_candidate.shutil.which", return_value="/home/runner/.cosign/cosign")
    @mock.patch.dict("accept_signed_ghcr_candidate.os.environ", {"HOME": "/home/runner", "DOCKER_CONFIG": "/home/runner/.docker"})
    def test_positive_and_three_negative_gates(self, _binary):
        self.assertTrue(run_acceptance(self.digest, self.source, runner=self.runner))
        self.assertEqual(len(self.calls), 4)
        self.assertTrue(all("--certificate-identity" in c for c in self.calls))
        self.assertTrue(all("--certificate-oidc-issuer" in c for c in self.calls))
        self.assertTrue(all("--insecure-ignore-tlog" not in c for c in self.calls))

    @mock.patch("accept_signed_ghcr_candidate.shutil.which", return_value="/home/runner/.cosign/cosign")
    @mock.patch.dict("accept_signed_ghcr_candidate.os.environ", {"HOME": "/home/runner", "DOCKER_CONFIG": "/home/runner/.docker"})
    def test_forged_source_sha_fails(self, _binary):
        with self.assertRaises(ProvenanceError):
            run_acceptance(self.digest, "c" * 40, runner=self.runner)

    @mock.patch("accept_signed_ghcr_candidate.shutil.which", return_value="/home/runner/.cosign/cosign")
    @mock.patch.dict("accept_signed_ghcr_candidate.os.environ", {"HOME": "/home/runner", "DOCKER_CONFIG": "/home/runner/.docker"})
    def test_unsigned_registry_response_fails(self, _binary):
        def fail(*args, **kwargs):
            return mock.Mock(returncode=1, stdout=self.stdout)
        with self.assertRaises(ProvenanceError):
            run_acceptance(self.digest, self.source, runner=fail)

    @mock.patch("accept_signed_ghcr_candidate.shutil.which", return_value="/home/runner/.cosign/cosign")
    @mock.patch.dict("accept_signed_ghcr_candidate.os.environ", {"HOME": "/home/runner", "DOCKER_CONFIG": "/home/runner/.docker"})
    def test_wrong_signer_accepted_is_failure(self, _binary):
        def all_good(*args, **kwargs):
            return mock.Mock(returncode=0, stdout=self.stdout)
        with self.assertRaisesRegex(ProvenanceError, "signer identity"):
            run_acceptance(self.digest, self.source, runner=all_good)

    @mock.patch("accept_signed_ghcr_candidate.shutil.which", return_value="/home/runner/.cosign/cosign")
    @mock.patch.dict("accept_signed_ghcr_candidate.os.environ", {"HOME": "/home/runner", "DOCKER_CONFIG": "/home/runner/.docker"})
    def test_wrong_digest_accepted_is_failure(self, _binary):
        def digest_bug(command, **kwargs):
            identity = command[command.index("--certificate-identity") + 1]
            return mock.Mock(returncode=0 if identity == IDENTITY else 1,
                             stdout=self.stdout)
        with self.assertRaisesRegex(ProvenanceError, "image digest"):
            run_acceptance(self.digest, self.source, runner=digest_bug)

    @mock.patch("accept_signed_ghcr_candidate.shutil.which", return_value=None)
    def test_missing_runner_binary_fails_closed(self, _binary):
        with self.assertRaisesRegex(ProvenanceError, "executable unavailable"):
            run_acceptance(self.digest, self.source, runner=self.runner)

    @mock.patch("accept_signed_ghcr_candidate.shutil.which", return_value="/home/runner/.cosign/cosign")
    @mock.patch.dict("accept_signed_ghcr_candidate.os.environ", {"HOME": "/home/runner"})
    def test_positive_cosign_crypto_failure_classified(self, _binary):
        def reject(*args, **kwargs):
            return mock.Mock(returncode=1, stdout=b"SECRET_STDOUT", stderr=b"SECRET_STDERR")
        with self.assertRaises(AcceptanceStageError) as caught:
            run_acceptance(self.digest, self.source, runner=reject)
        self.assertEqual(caught.exception.code, "COSIGN_CRYPTO_REJECTED")
        msg = safe_diagnostic(caught.exception)
        self.assertIn("stage=positive code=COSIGN_CRYPTO_REJECTED", msg)
        self.assertNotIn("SECRET", msg)

    @mock.patch("accept_signed_ghcr_candidate.shutil.which", return_value="/home/runner/.cosign/cosign")
    @mock.patch.dict("accept_signed_ghcr_candidate.os.environ", {"HOME": "/home/runner"})
    def test_verified_json_policy_rejection_reports_only_safe_schema(self, _binary):
        def bad_shape(*args, **kwargs):
            data = json.dumps([{"payload": "not-base64", "credential": "DO_NOT_LEAK"}]).encode()
            return mock.Mock(returncode=0, stdout=data)
        with self.assertRaises(AcceptanceStageError) as caught:
            run_acceptance(self.digest, self.source, runner=bad_shape)
        self.assertEqual(caught.exception.code, "VERIFIED_STATEMENT_POLICY_REJECTED")
        msg = safe_diagnostic(caught.exception)
        self.assertIn("stage=positive", msg)
        self.assertIn("schema=PAYLOAD_DECODE", msg)
        self.assertNotIn("DO_NOT_LEAK", msg)

    @mock.patch("accept_signed_ghcr_candidate.shutil.which", return_value="/home/runner/.cosign/cosign")
    @mock.patch.dict("accept_signed_ghcr_candidate.os.environ", {"HOME": "/home/runner"})
    def test_crypto_runner_timeout_is_static_error(self, _binary):
        def timeout(*args, **kwargs):
            raise __import__("subprocess").TimeoutExpired(cmd="SECRET_COMMAND", timeout=90)
        with self.assertRaises(AcceptanceStageError) as caught:
            run_acceptance(self.digest, self.source, runner=timeout)
        self.assertEqual(caught.exception.code, "COSIGN_EXECUTION_ERROR")
        self.assertNotIn("SECRET_COMMAND", safe_diagnostic(caught.exception))

    @mock.patch("accept_signed_ghcr_candidate.shutil.which", return_value="/home/runner/.cosign/cosign")
    @mock.patch.dict("accept_signed_ghcr_candidate.os.environ", {"HOME": "/home/runner"})
    def test_statement_policy_rejection_identifies_source_dependency(self, _binary):
        fake_statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{"name": "ghcr.io/aristha/openproject",
                         "digest": {"sha256": "b" * 64}}],
            "predicate": {"buildDefinition": {"resolvedDependencies": [
                {"uri": "git+https://github.com/aristha/openproject",
                 "digest": {"gitCommit": "c" * 40}}]}}
        }
        verified = json.dumps([{"payloadType": "application/vnd.in-toto+json",
            "payload": base64.b64encode(json.dumps(fake_statement).encode()).decode()
        }]).encode()
        def runner(*args, **kwargs):
            return mock.Mock(returncode=0, stdout=verified)
        with self.assertRaises(AcceptanceStageError) as caught:
            run_acceptance(self.digest, self.source, runner=runner)
        self.assertEqual(caught.exception.schema, "SOURCE_DEPENDENCY")
        self.assertNotIn("gitCommit", safe_diagnostic(caught.exception))
        self.assertNotIn("c" * 40, safe_diagnostic(caught.exception))

    def test_public_diagnostic_never_uses_arbitrary_exception_text(self):
        self.assertEqual(safe_diagnostic(ProvenanceError("SECRET_PRIVATE")),
                         "GHCR_SIGNED_PROVENANCE_ACCEPTANCE_FAILED stage=preflight code=INPUT_OR_RUNTIME_REJECTED")
        self.assertNotIn("SECRET_PRIVATE", safe_diagnostic(ProvenanceError("SECRET_PRIVATE")))

    @mock.patch("accept_signed_ghcr_candidate.shutil.which", return_value="/home/runner/.cosign/cosign")
    @mock.patch.dict("accept_signed_ghcr_candidate.os.environ", {"HOME": "/home/runner"})
    def test_negative_signer_failure_is_specific(self, _binary):
        def all_good(*args, **kwargs):
            return mock.Mock(returncode=0, stdout=self.stdout)
        with self.assertRaises(AcceptanceStageError) as caught:
            run_acceptance(self.digest, self.source, runner=all_good)
        self.assertEqual(caught.exception.code, "WRONG_SIGNER_ACCEPTED")
        self.assertIn("stage=negative_signer", safe_diagnostic(caught.exception))

    def test_reject_mutable_tag(self):
        with self.assertRaises(ProvenanceError):
            policy_for("latest", self.source)

    def test_reject_short_source(self):
        with self.assertRaises(ProvenanceError):
            policy_for(self.digest, "a" * 8)

    def test_host_default_binary_unmodified(self):
        from image_provenance import verify_image
        policy = policy_for(self.digest, self.source)
        seen = []
        def runner(cmd, **kwargs):
            seen.append((cmd, kwargs))
            return mock.Mock(returncode=0, stdout=self.stdout)
        self.assertTrue(verify_image(policy["image"], policy, runner=runner))
        self.assertEqual(seen[0][0][0], "/usr/local/bin/cosign")
        self.assertEqual(seen[0][1]["env"]["HOME"], "/root")

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
