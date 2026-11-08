"""Offline negative tests for HTTPS alert delivery, retries and idempotency."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import alert_dispatch as alerts


class AlertTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.spool = self.root / "spool"
        self.delivered = self.root / "delivered"
        self.spool.mkdir()
        self.delivered.mkdir()
        self.config = self.root / "config.json"
        self.token = self.root / "token"
        self.token.write_text("redacted-token")
        self.config.write_text(json.dumps({
            "schema_version": 1,
            "endpoint": "https://notify.example.com/v1/alert",
            "expected_host": "notify.example.com",
            "token_file": str(self.token),
        }))
        self.args = mock.Mock(spool=str(self.spool), delivered=str(self.delivered),
                              config=str(self.config))
        self.alert = self.spool / "alert-001.json"
        self.alert.write_text(json.dumps({
            "severity": "error", "component": "release-transport",
            "time": "2026-11-08T00:00:00+00:00",
            "message": "release transport verification failed",
        }))

    def guarded(self, sender, sleeper=lambda n: None):
        with mock.patch.object(alerts.os, "geteuid", return_value=0), \\
             mock.patch.object(alerts, "require_root_owned_dir"), \\
             mock.patch.object(alerts, "control_file", side_effect=[
                 self.config.read_text(), "redacted-token"]), \\
             mock.patch.object(alerts.os, "fstat", wraps=os.fstat):
            # CI runner owns temporary files; mock only the root-only file check.
            original = alerts.os.fstat
            def pretend_root(fd):
                st = original(fd)
                return mock.Mock(st_mode=st.st_mode, st_uid=0)
            with mock.patch.object(alerts.os, "fstat", side_effect=pretend_root):
                return alerts.run(self.args, sender=sender, sleeper=sleeper)

    def test_success_archives_once(self):
        calls = []
        def sender(url, token, event, key):
            calls.append(key)
            return "ok"
        self.assertEqual(self.guarded(sender), 0)
        self.assertEqual(len(calls), 1)
        self.assertFalse(self.alert.exists())
        self.assertTrue((self.delivered / self.alert.name).exists())
        self.assertEqual(self.guarded(sender), 0)
        self.assertEqual(len(calls), 1)

    def test_retry_then_success_same_key(self):
        keys = []
        def sender(url, token, event, key):
            keys.append(key)
            return "retry" if len(keys) < 3 else "ok"
        self.assertEqual(self.guarded(sender), 0)
        self.assertEqual(len(set(keys)), 1)
        self.assertFalse(self.alert.exists())

    def test_exhausted_retry_preserves_spool(self):
        with self.assertRaises(alerts.DeliveryError):
            self.guarded(lambda *args: "retry")
        self.assertTrue(self.alert.exists())

    def test_permanent_rejection_preserves_spool(self):
        with self.assertRaises(alerts.DeliveryError):
            self.guarded(lambda *args: "reject")
        self.assertTrue(self.alert.exists())

    def test_reject_symlink_alert(self):
        self.alert.unlink()
        outside = self.root / "outside"
        outside.write_text("{}")
        self.alert.symlink_to(outside)
        with self.assertRaises(alerts.DeliveryError):
            alerts.safe_alert(self.alert)

    def test_reject_modified_schema(self):
        self.alert.write_text('{"severity":"info"}')
        with self.assertRaises(alerts.DeliveryError):
            alerts.safe_alert(self.alert)

    def test_reject_large_payload(self):
        self.alert.write_bytes(b"x" * (alerts.MAX_ALERT + 1))
        with self.assertRaises(alerts.DeliveryError):
            alerts.safe_alert(self.alert)

    def test_reject_http_endpoint(self):
        c = json.loads(self.config.read_text())
        c["endpoint"] = "http://notify.example.com/alert"
        with mock.patch.object(alerts, "control_file", return_value=json.dumps(c)):
            with self.assertRaises(alerts.DeliveryError):
                alerts.config_from(self.config)

    def test_reject_wrong_hostname(self):
        c = json.loads(self.config.read_text())
        c["endpoint"] = "https://attacker.example.com/alert"
        with mock.patch.object(alerts, "control_file", return_value=json.dumps(c)):
            with self.assertRaises(alerts.DeliveryError):
                alerts.config_from(self.config)

    def test_reject_loopback_endpoint(self):
        c = json.loads(self.config.read_text())
        c["endpoint"] = "https://127.0.0.1/alert"
        c["expected_host"] = "127.0.0.1"
        with mock.patch.object(alerts, "control_file", return_value=json.dumps(c)):
            with self.assertRaises(alerts.DeliveryError):
                alerts.config_from(self.config)

    def test_retry_codes(self):
        self.assertIn(429, alerts.RETRY_CODES)
        self.assertNotIn(403, alerts.RETRY_CODES)


if __name__ == "__main__":
    unittest.main()
