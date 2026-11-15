"""Offline tests for portable release migration drift detection (temp git repos)."""
import pathlib
import subprocess
import tempfile
import unittest

from check_migration_drift import check, main


class MigrationDriftTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.tmp.name)
        self.git("init", "-q")
        (self.repo / "db/migrate").mkdir(parents=True)
        (self.repo / "db/migrate/001_a.rb").write_text("a\n")
        self.base = self.commit("base")

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args):
        return subprocess.run(
            ["git", "-c", "user.email=t@l", "-c", "user.name=t", "-C", str(self.repo), *args],
            check=True, capture_output=True, text=True).stdout.strip()

    def commit(self, msg):
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", msg)
        return self.git("rev-parse", "HEAD")

    def test_same_sha_is_not_performed(self):
        self.assertEqual(check(self.repo, self.base, self.base), "not-performed")

    def test_unrelated_change_is_not_performed(self):
        (self.repo / "app.rb").write_text("x\n")
        new = self.commit("app")
        self.assertEqual(check(self.repo, self.base, new), "not-performed")

    def test_added_migration_fails(self):
        (self.repo / "db/migrate/002_b.rb").write_text("b\n")
        new = self.commit("mig")
        with self.assertRaisesRegex(ValueError, "002_b.rb"):
            check(self.repo, self.base, new)

    def test_modified_and_removed_migration_fail(self):
        (self.repo / "db/migrate/001_a.rb").write_text("changed\n")
        mod = self.commit("mod")
        with self.assertRaises(ValueError):
            check(self.repo, self.base, mod)
        (self.repo / "db/migrate/001_a.rb").unlink()
        rem = self.commit("rm")
        with self.assertRaises(ValueError):
            check(self.repo, mod, rem)

    def test_rollback_direction_also_fails(self):
        (self.repo / "db/migrate/002_b.rb").write_text("b\n")
        new = self.commit("mig")
        with self.assertRaises(ValueError):
            check(self.repo, new, self.base)

    def test_rejects_bad_or_unknown_sha(self):
        with self.assertRaisesRegex(ValueError, "40-hex"):
            check(self.repo, "HEAD", self.base)
        with self.assertRaisesRegex(ValueError, "not available"):
            check(self.repo, "f" * 40, self.base)

    def test_main_exit_codes(self):
        self.assertEqual(main(["--repo", str(self.repo), "--current-sha", self.base, "--new-sha", self.base]), 0)
        (self.repo / "db/migrate/002_b.rb").write_text("b\n")
        new = self.commit("mig")
        self.assertEqual(main(["--repo", str(self.repo), "--current-sha", self.base, "--new-sha", new]), 1)


if __name__ == "__main__":
    unittest.main()
