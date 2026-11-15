"""Security regression tests for the approved local release agent."""
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_transport

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

    def execute_args(self):
        return mock.Mock(inbox=str(self.inbox), state_dir=str(self.state),
                         deploy_root=str(self.root), backup_hook="/tmp/fake-backup", execute=True,
                         provenance_policy="/fake/policy.json", alerts=str(self.root / "alerts"),
                         deploy_timeout=1500, term_grace=300)

    def run_execute(self, deploy_effect=None, provenance_effect=None, alert=True):
        """Run an --execute cycle with every host-specific gate patched; returns (rc_or_exc, run mock)."""
        fake_stat = mock.Mock(st_uid=0, st_mode=0o100600)
        with mock.patch.object(agent.os, "geteuid", return_value=0), \
             mock.patch.object(agent, "require_root_owned_dir"), \
             mock.patch.object(agent, "require_root_executable"), \
             mock.patch.object(agent, "read_approval", return_value=self.approval), \
             mock.patch.object(agent, "require_root_lock"), \
             mock.patch.object(agent, "permitted_window", return_value=True), \
             mock.patch.object(Path, "lstat", return_value=fake_stat), \
             mock.patch.dict(agent.os.environ, {"OPENPROJECT_AGENT_EXECUTE_ENABLED": "YES"}), \
             mock.patch.object(agent, "verify_provenance", side_effect=provenance_effect) as self.prov, \
             mock.patch.object(agent, "emit_failure_alert") as self.alert, \
             mock.patch.object(agent, "run_deploy", side_effect=deploy_effect) as run:
            try:
                return agent.run(self.execute_args()), run
            except Exception as exc:
                return exc, run

    def marker(self, digest=None):
        return self.state / ("deploy-failed-" + (digest or self.approval["artifact_sha256"]) + ".json")

    def test_failed_deploy_writes_marker(self):
        failure = agent.subprocess.CalledProcessError(3, ["deploy.sh"])
        result, run = self.run_execute(failure)
        self.assertIsInstance(result, agent.subprocess.CalledProcessError)
        run.assert_called_once()
        record = json.loads(self.marker().read_text())
        self.assertEqual(record["artifact_sha256"], self.approval["artifact_sha256"])
        self.assertEqual(record["image"], self.image)
        self.assertIn("status 3", record["reason"])
        self.assertIn("failed_at", record)
        self.assertEqual(self.marker().stat().st_mode & 0o777, 0o600)
        self.assertFalse((self.state / "last-deployed.json").exists())
        self.assertEqual([p.name for p in self.state.iterdir() if p.name.startswith(".")], [])

    def test_second_run_after_failure_is_refused_without_deploy(self):
        self.run_execute(agent.subprocess.CalledProcessError(1, ["deploy.sh"]))
        result, run = self.run_execute()
        self.assertIsInstance(result, ValueError)
        self.assertIn("remove", str(result))
        self.assertIn(str(self.marker()), str(result))
        run.assert_not_called()

    def test_different_artifact_is_not_blocked(self):
        self.run_execute(agent.subprocess.CalledProcessError(1, ["deploy.sh"]))
        failed_marker = self.marker()
        self.release["source_sha"] = "c" * 40
        self.approval["source_sha"] = "c" * 40
        self.write_zip()
        self.assertNotEqual(self.marker(), failed_marker)
        self.assertTrue(failed_marker.exists())
        result, run = self.run_execute(lambda *a, **k: None)
        self.assertEqual(result, 0)
        run.assert_called_once()

    def test_success_leaves_no_marker(self):
        result, run = self.run_execute(lambda *a, **k: None)
        self.assertEqual(result, 0)
        run.assert_called_once()
        self.assertFalse(self.marker().exists())
        self.assertTrue((self.state / "last-deployed.json").exists())

    def test_timeout_writes_marker(self):
        result, _ = self.run_execute(agent.subprocess.TimeoutExpired(["deploy.sh"], 1500))
        self.assertIsInstance(result, agent.subprocess.TimeoutExpired)
        self.assertIn("timed out", json.loads(self.marker().read_text())["reason"])

    def test_observe_only_writes_no_marker(self):
        args = self.execute_args()
        args.execute = False
        with mock.patch.object(agent.os, "geteuid", return_value=0), \
             mock.patch.object(agent, "require_root_owned_dir"), \
             mock.patch.object(agent, "read_approval", return_value=self.approval), \
             mock.patch.object(agent, "require_root_lock"), \
             mock.patch.object(agent.subprocess, "run") as run:
            self.assertEqual(agent.run(args), 0)
            run.assert_not_called()
        self.assertEqual(list(self.state.glob("deploy-failed-*")), [])

    def test_provenance_failure_blocks_deploy_with_marker_and_alert(self):
        failure = agent.ProvenanceGateError("Image provenance verification failed: ProvenanceError")
        result, run = self.run_execute(provenance_effect=failure)
        self.assertIs(result, failure)
        run.assert_not_called()
        self.assertIn("provenance", json.loads(self.marker().read_text())["reason"])
        self.alert.assert_called_once_with(str(self.root / "alerts"))
        self.assertFalse((self.state / "last-deployed.json").exists())

    def test_provenance_checked_before_deploy_with_approved_image(self):
        order = []
        self.run_execute(lambda *a, **k: order.append("deploy"), lambda *a, **k: order.append("prov"))
        self.assertEqual(order, ["prov", "deploy"])
        self.prov.assert_called_once_with(self.approval, "/fake/policy.json")

    def test_alert_on_deploy_failure_and_timeout_but_not_success(self):
        self.run_execute(agent.subprocess.CalledProcessError(2, ["deploy.sh"]))
        self.alert.assert_called_once()
        self.marker().unlink()
        self.run_execute(agent.DeployTimeout(["deploy.sh"], 1500, True))
        self.alert.assert_called_once()
        self.assertIn("SIGKILL", json.loads(self.marker().read_text())["reason"])
        self.marker().unlink()
        self.run_execute(lambda *a, **k: None)
        self.alert.assert_not_called()

    def test_alert_spool_failure_does_not_mask_original_error(self):
        failure = agent.subprocess.CalledProcessError(7, ["deploy.sh"])
        fake_stat = mock.Mock(st_uid=0, st_mode=0o100600)
        with mock.patch.object(agent.os, "geteuid", return_value=0), \
             mock.patch.object(agent, "require_root_owned_dir"), \
             mock.patch.object(agent, "require_root_executable"), \
             mock.patch.object(agent, "read_approval", return_value=self.approval), \
             mock.patch.object(agent, "require_root_lock"), \
             mock.patch.object(agent, "permitted_window", return_value=True), \
             mock.patch.object(Path, "lstat", return_value=fake_stat), \
             mock.patch.dict(agent.os.environ, {"OPENPROJECT_AGENT_EXECUTE_ENABLED": "YES"}), \
             mock.patch.object(agent, "verify_provenance"), \
             mock.patch.object(agent, "run_deploy", side_effect=failure), \
             mock.patch.object(release_transport, "alert_spool", side_effect=OSError("disk full")) as spool, \
             mock.patch.object(sys, "stderr", new_callable=io.StringIO) as err:
            with self.assertRaises(agent.subprocess.CalledProcessError) as caught:
                agent.run(self.execute_args())
        self.assertIs(caught.exception, failure)
        spool.assert_called_once()
        self.assertIn("OSError", err.getvalue())
        self.assertNotIn("disk full", err.getvalue())
        self.assertIn("status 7", json.loads(self.marker().read_text())["reason"])

    def test_alert_spool_uses_existing_alert_dispatch_schema(self):
        with mock.patch.object(release_transport, "require_root_owned_dir"):
            agent.emit_failure_alert(self.state)
        (alert,) = self.state.glob("alert-*.json")
        self.assertEqual(json.loads(alert.read_text())["component"], "release-transport")

    def test_verify_provenance_passes_image_and_loaded_policy(self):
        import image_provenance
        policy = {"image": self.image}
        with mock.patch.object(image_provenance, "load_policy", return_value=policy) as load, \
             mock.patch.object(image_provenance, "verify_image", return_value=True) as verify:
            agent.verify_provenance(self.approval, "/p.json")
        load.assert_called_once_with("/p.json")
        verify.assert_called_once_with(self.image, policy)

    def test_verify_provenance_fails_closed(self):
        import image_provenance
        with self.assertRaises(agent.ProvenanceGateError):
            agent.verify_provenance(self.approval, None)
        with mock.patch.object(image_provenance, "load_policy", return_value={}), \
             mock.patch.object(image_provenance, "verify_image",
                               side_effect=image_provenance.ProvenanceError("secret-detail")):
            with self.assertRaises(agent.ProvenanceGateError) as caught:
                agent.verify_provenance(self.approval, "/p.json")
        self.assertNotIn("secret-detail", str(caught.exception))

    def test_main_returns_distinct_code_on_timeout(self):
        with mock.patch.object(agent, "run", side_effect=agent.DeployTimeout(["x"], 5, False)), \
             mock.patch.object(sys, "argv", ["agent"]), \
             mock.patch.object(sys, "stderr", new_callable=io.StringIO):
            self.assertEqual(agent.main(), agent.EXIT_DEPLOY_TIMEOUT)


class RunDeployTests(unittest.TestCase):
    def fake_proc(self, waits):
        proc = mock.Mock(pid=4242)
        proc.wait.side_effect = waits
        return proc

    def run_with(self, waits):
        proc = self.fake_proc(waits)
        with mock.patch.object(agent.subprocess, "Popen", return_value=proc) as popen, \
             mock.patch.object(agent.os, "killpg") as killpg:
            try:
                agent.run_deploy(["deploy.sh"], {}, timeout=10, grace=7)
                exc = None
            except BaseException as caught:
                exc = caught
        return exc, popen, killpg, proc

    def test_timeout_sends_term_then_kill_after_grace(self):
        expired = agent.subprocess.TimeoutExpired
        exc, popen, killpg, proc = self.run_with([expired("c", 10), expired("c", 7), 0])
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertEqual(killpg.call_args_list,
                         [mock.call(4242, signal.SIGTERM), mock.call(4242, signal.SIGKILL)])
        self.assertEqual([c.kwargs.get("timeout") for c in proc.wait.call_args_list], [10, 7, None])
        self.assertIsInstance(exc, agent.DeployTimeout)
        self.assertTrue(exc.killed)
        self.assertEqual(exc.timeout, 10)

    def test_exit_within_grace_is_not_killed(self):
        exc, _, killpg, _ = self.run_with([agent.subprocess.TimeoutExpired("c", 10), 143])
        self.assertEqual(killpg.call_args_list, [mock.call(4242, signal.SIGTERM)])
        self.assertIsInstance(exc, agent.DeployTimeout)
        self.assertFalse(exc.killed)

    def test_nonzero_exit_raises_called_process_error_without_signals(self):
        exc, _, killpg, _ = self.run_with([3])
        self.assertIsInstance(exc, agent.subprocess.CalledProcessError)
        self.assertEqual(exc.returncode, 3)
        killpg.assert_not_called()

    def test_success_returns_none(self):
        exc, _, killpg, _ = self.run_with([0])
        self.assertIsNone(exc)
        killpg.assert_not_called()

    def test_interrupt_terminates_group_and_reraises(self):
        exc, _, killpg, _ = self.run_with([KeyboardInterrupt(), 0])
        self.assertIsInstance(exc, KeyboardInterrupt)
        self.assertEqual(killpg.call_args_list, [mock.call(4242, signal.SIGTERM)])


class RealProcessGroupTests(unittest.TestCase):
    """Real bash scripts prove the TERM trap runs and the group is killed only after the grace."""

    def script(self, body):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        path = Path(d.name) / "deploy.sh"
        path.write_text("#!/bin/bash\n" + body)
        return Path(d.name), path

    def test_term_trap_runs_before_deadline_kill(self):
        out, script = self.script('trap \'echo rolled-back > "$1/rollback"; exit 143\' TERM\n'
                                  'sleep 30 & wait\n')
        with self.assertRaises(agent.DeployTimeout) as caught:
            agent.run_deploy(["/bin/bash", str(script), str(out)], {"PATH": os.environ["PATH"]},
                             timeout=1, grace=10)
        self.assertFalse(caught.exception.killed)
        self.assertEqual((out / "rollback").read_text().strip(), "rolled-back")

    def test_ignoring_term_gets_group_killed_after_grace(self):
        out, script = self.script('trap \'\' TERM\n(trap \'\' TERM; echo $BASHPID > "$1/child"; sleep 60) &\n'
                                  'while :; do sleep 1; done\n')
        started = time.monotonic()
        with self.assertRaises(agent.DeployTimeout) as caught:
            agent.run_deploy(["/bin/bash", str(script), str(out)], {"PATH": os.environ["PATH"]},
                             timeout=1, grace=2)
        self.assertTrue(caught.exception.killed)
        self.assertGreaterEqual(time.monotonic() - started, 2.5)
        child = int((out / "child").read_text())
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                os.kill(child, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        else:
            self.fail("child of deploy group survived SIGKILL")


from zoneinfo import ZoneInfo

if __name__ == "__main__":
    unittest.main()
