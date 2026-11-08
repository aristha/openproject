"""Security regression tests for the approved local release agent."""
import datetime as dt
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

spec = importlib.util.spec_from_file_location(
    "approved_release_agent", Path(__file__).with_name("approved_release_agent.py")
)
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inbox = self.root / "inbox"
        self.state = self.root / "state"
        self.inbox.mkdir()
        self.state.mkdir()
        self.digest = "a" * 64
        self.image = "ghcr.io/aristha/openproject@sha256:" + self.digest
        self.sha = "b" * 40
        self.approval = {
            "schema_version": 1,
            "environment": "pilot",
            "artifact_sha256": "0" * 64,
            "image": self.image,
            "source_sha": self.sha,
            "schema_approved": "NO_MIGRATIONS",
            "expires_at": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2)).isoformat(),
        }
        self.files = {
            name: b"test-placeholder" for name in agent.FILES if name != "release.json"
        }
        self.release = {
            "schema_version": 1,
            "environment": "pilot",
            "image": self.image,
            "source_sha": self.sha,
            "deployment_mode": "manual-on-host",
            "migrations": "not-performed",
        }
        self.write_zip()

    def write_zip(self, extra=None):
        self.files["release.json"] = json.dumps(self.release).encode()
        checksums = "".join(
            hashlib.sha256(content).hexdigest() + "  " + name + "\n"
            for name, content in sorted(self.files.items())
        ).encode()
        with zipfile.ZipFile(self.inbox / "release.zip", "w") as z:
            for name, content in self.files.items():
                z.writestr(name, content)
            z.writestr("SHA256SUMS", checksums)
            if extra:
                z.writestr(extra, b"unexpected")
        self.approval["artifact_sha256"] = hashlib.sha256((self.inbox / "release.zip").read_bytes()).hexdigest()
        (self.inbox / "approval.json").write_text(json.dumps(self.approval))

    def test_verify_bundle(self):
        with tempfile.TemporaryDirectory() as d:
            data = agent.verify_zip(self.inbox / "release.zip", self.approval["artifact_sha256"], Path(d))
            self.assertEqual(data["image"], self.image)

    def test_reject_modified_bundle(self):
        with (self.inbox / "release.zip").open("ab") as f:
            f.write(b"tamper")
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError, "differs"):
                agent.verify_zip(self.inbox / "release.zip", self.approval["artifact_sha256"], Path(d))

    def test_reject_path_traversal(self):
        self.write_zip("../injected")
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError, "Unexpected ZIP"):
                agent.verify_zip(self.inbox / "release.zip", self.approval["artifact_sha256"], Path(d))

    def test_reject_schema_migration(self):
        self.release["migrations"] = "performed"
        self.write_zip()
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                agent.verify_zip(self.inbox / "release.zip", self.approval["artifact_sha256"], Path(d))

    def test_approval_expiry_invalid(self):
        self.approval["expires_at"] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)).isoformat()
        (self.inbox / "approval.json").write_text(json.dumps(self.approval))
        # This fails on CI's unprivileged UID before expiry; patch just file stat UID for this test.
        fake = mock.Mock(st_uid=0, st_mode=0o100600)
        with mock.patch.object(Path, "lstat", return_value=fake):
            with self.assertRaisesRegex(ValueError, "expired"):
                agent.read_approval(self.inbox / "approval.json")

    def test_observe_only_never_executes(self):
        args = mock.Mock(inbox=str(self.inbox), state_dir=str(self.state),
                         deploy_root=str(self.root), backup_hook="/tmp/fake-backup", execute=False)
        with mock.patch.object(agent.os, "geteuid", return_value=0), \
             mock.patch.object(agent, "require_root_owned_dir"), \
             mock.patch.object(agent, "read_approval", return_value=self.approval), \
             mock.patch.object(agent, "require_root_lock"), \
             mock.patch.object(agent.subprocess, "run") as run:
            self.assertEqual(agent.run(args), 0)
            run.assert_not_called()

    def test_execution_requires_enable_flag(self):
        args = mock.Mock(inbox=str(self.inbox), state_dir=str(self.state),
                         deploy_root=str(self.root), backup_hook="/tmp/fake-backup", execute=True)
        with mock.patch.object(agent.os, "geteuid", return_value=0), \
             mock.patch.object(agent, "require_root_owned_dir"), \
             mock.patch.object(agent, "read_approval", return_value=self.approval), \
             mock.patch.object(agent, "require_root_lock"), \
             mock.patch.dict(agent.os.environ, {"OPENPROJECT_AGENT_EXECUTE_ENABLED": ""}):
            with self.assertRaisesRegex(ValueError, "Execution disabled"):
                agent.run(args)

    def test_window_rules(self):
        tz = ZoneInfo("Asia/Ho_Chi_Minh")
        self.assertTrue(agent.permitted_window(dt.datetime(2026, 11, 9, 10, 0, tzinfo=tz)))
        self.assertFalse(agent.permitted_window(dt.datetime(2026, 11, 8, 10, 0, tzinfo=tz)))
        self.assertFalse(agent.permitted_window(dt.datetime(2026, 11, 9, 17, 45, tzinfo=tz)))


    def test_reject_zip_expansion_over_limit(self):
        self.files["deploy.sh"] = b"x" * (4 * 1024 * 1024 + 1)
        self.write_zip()
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError, "uncompressed size"):
                agent.verify_zip(self.inbox / "release.zip", self.approval["artifact_sha256"], Path(d))

    def test_reject_symlink_state_file(self):
        target = self.root / "outside.json"
        target.write_text("{}")
        link = self.state / "last-deployed.json"
        link.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "root-only regular"):
            agent.read_state(link)

    def test_reject_writable_backup_hook(self):
        hook = self.root / "unsafe-backup.sh"
        hook.write_text("#!/bin/sh\\nexit 0\\n")
        hook.chmod(0o777)
        with self.assertRaises(ValueError):
            agent.require_root_executable(hook)

    def test_reject_symlink_backup_hook(self):
        script = self.root / "backup.sh"
        script.write_text("#!/bin/sh\\nexit 0\\n")
        script.chmod(0o700)
        link = self.root / "backup-link"
        link.symlink_to(script)
        with self.assertRaises(ValueError):
            agent.require_root_executable(link)

    def test_reject_relative_agent_directory(self):
        with self.assertRaisesRegex(ValueError, "absolute"):
            agent.require_root_owned_dir(Path("relative/inbox"))

    def test_reject_symlink_agent_directory(self):
        link = self.root / "symlink-inbox"
        link.symlink_to(self.inbox, target_is_directory=True)
        with self.assertRaises(ValueError):
            agent.require_root_owned_dir(link)



from zoneinfo import ZoneInfo

if __name__ == "__main__":
    unittest.main()
