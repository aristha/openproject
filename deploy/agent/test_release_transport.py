"""Offline fail-closed regression suite for GitHub release transport."""
import datetime as dt
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

import release_transport as transport


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.source = "a" * 40
        self.image = "ghcr.io/aristha/openproject@sha256:" + "b" * 64
        self.request = {
            "schema_version": 1, "run_id": 123, "artifact_id": 456,
            "artifact_sha256": "c" * 64, "environment": "pilot",
            "source_sha": self.source, "image": self.image,
            "expires_at": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat(),
        }
        self.run = {
            "id": 123, "repository": {"full_name": "aristha/openproject"},
            "path": transport.WORKFLOW + "@refs/heads/dev", "run_number": 7,
            "event": "workflow_dispatch", "head_branch": "dev", "head_sha": self.source,
            "status": "completed", "conclusion": "success",
        }
        self.artifact = {
            "id": 456, "workflow_run": {"id": 123}, "name": "openproject-pilot-7",
            "expired": False, "size_in_bytes": 5000, "digest": "sha256:" + "c" * 64,
        }

    def test_valid_metadata(self):
        transport.validate_request(self.request)
        transport.validate_metadata(self.run, self.artifact, self.request)

    def test_reject_forged_repo(self):
        self.run["repository"]["full_name"] = "attacker/openproject"
        with self.assertRaises(transport.TransportError):
            transport.validate_metadata(self.run, self.artifact, self.request)

    def test_reject_other_workflow(self):
        self.run["path"] = "other.yml@refs/heads/dev"
        with self.assertRaises(transport.TransportError):
            transport.validate_metadata(self.run, self.artifact, self.request)

    def test_reject_failed_run(self):
        self.run["conclusion"] = "failure"
        with self.assertRaises(transport.TransportError):
            transport.validate_metadata(self.run, self.artifact, self.request)

    def test_reject_other_run_artifact(self):
        self.artifact["workflow_run"]["id"] = 10
        with self.assertRaises(transport.TransportError):
            transport.validate_metadata(self.run, self.artifact, self.request)

    def test_reject_digest_mismatch(self):
        self.artifact["digest"] = "sha256:" + "d" * 64
        with self.assertRaises(transport.TransportError):
            transport.validate_metadata(self.run, self.artifact, self.request)

    def test_reject_expiry(self):
        self.request["expires_at"] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)).isoformat()
        with self.assertRaises(transport.TransportError):
            transport.validate_request(self.request)

    def test_reject_prod_channel(self):
        self.request["environment"] = "production"
        with self.assertRaises(transport.TransportError):
            transport.validate_request(self.request)

    def test_redirect_allowlist(self):
        for url in ("http://foo.actions.githubusercontent.com/path",
                    "https://evil.example/path",
                    "https://user@foo.actions.githubusercontent.com/file",
                    "https://foo.actions.githubusercontent.com:444/file"):
            self.assertFalse(transport.safe_redirect(url), url)
        self.assertTrue(transport.safe_redirect("https://foo.actions.githubusercontent.com/path"))

    def test_verification_only_and_tampered_archive(self):
        with io.BytesIO() as fp:
            with zipfile.ZipFile(fp, "w") as z:
                z.writestr("release.json", "{}")
            data = fp.getvalue()
        self.request["artifact_sha256"] = hashlib.sha256(data).hexdigest()
        self.artifact["digest"] = "sha256:" + self.request["artifact_sha256"]
        self.artifact["size_in_bytes"] = len(data)
        with tempfile.TemporaryDirectory() as d:
            args = mock.Mock(request=d + "/request", approval=d + "/approval",
                             token_file=d + "/token", output=d + "/release.zip", stage=False)
            approval = {k: self.request[k] for k in ("artifact_sha256", "source_sha", "image", "environment")}
            payload = [data]
            def get(url, token, archive=False):
                if archive:
                    return payload[0]
                if "/runs/" in url:
                    return json.dumps(self.run).encode()
                return json.dumps(self.artifact).encode()
            with mock.patch.object(transport.os, "geteuid", return_value=0), \
                 mock.patch.object(transport, "control_file", side_effect=[
                     json.dumps(self.request), "token", json.dumps(self.request), "token"]), \
                 mock.patch.object(transport, "read_approval", return_value=approval), \
                 mock.patch.object(transport, "verify_zip", return_value={
                     "environment": "pilot", "source_sha": self.source, "image": self.image}):
                result, context = transport.run(args, getter=get)
                self.assertEqual(result, "VERIFIED_ONLY")
                self.assertEqual(context["run_id"], 123)
                self.assertFalse(Path(args.output).exists())
                payload[0] = data + b"modified"
                with self.assertRaises(transport.TransportError):
                    transport.run(args, getter=get)

    def test_atomic_stage(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "release.zip"
            with mock.patch.object(transport, "require_root_owned_dir"):
                transport.atomic_stage(target, b"approved")
            self.assertEqual(target.read_bytes(), b"approved")

    def test_alert_spool(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(transport, "require_root_owned_dir"):
                transport.alert_spool(Path(d))
            alerts = list(Path(d).glob("alert-*.json"))
            self.assertEqual(len(alerts), 1)
            self.assertEqual(json.loads(alerts[0].read_text())["severity"], "error")


if __name__ == "__main__":
    unittest.main()
