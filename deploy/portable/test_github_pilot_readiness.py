"""No-network security tests for GitHub pilot approval and branch protection."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_github_pilot_readiness as preflight


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.env = {
            "name": "pilot",
            "prevent_self_review": True,
            "protection_rules": [{
                "type": "required_reviewers",
                "reviewers": [{"type": "User", "reviewer": {"login": "release-owner"}}],
            }],
            "deployment_branch_policy": {
                "protected_branches": True,
                "custom_branch_policies": False,
            },
        }
        self.branch = {"name": "dev", "protected": True}
        self.protection = {
            "required_pull_request_reviews": {
                "required_approving_review_count": 1,
                "dismiss_stale_reviews": True,
            },
            "required_status_checks": {
                "strict": True,
                "contexts": ["validate"],
                "checks": [],
            },
            "enforce_admins": {"enabled": True},
            "allow_force_pushes": {"enabled": False},
            "allow_deletions": {"enabled": False},
        }

    def test_protected_dev_with_reviewers(self):
        result = preflight.check_environment(self.env, self.branch, protection=self.protection)
        self.assertEqual(result["status"], "METADATA_PRECHECK_PASS")
        self.assertTrue(result["required_reviewers_present"])

    def test_reject_missing_required_reviewers(self):
        self.env["protection_rules"] = []
        with self.assertRaises(preflight.ReadinessError):
            preflight.check_environment(self.env, self.branch, protection=self.protection)

    def test_reject_no_self_review_protection(self):
        self.env["prevent_self_review"] = False
        with self.assertRaises(preflight.ReadinessError):
            preflight.check_environment(self.env, self.branch, protection=self.protection)

    def test_reject_unprotected_dev(self):
        self.branch["protected"] = False
        with self.assertRaises(preflight.ReadinessError):
            preflight.check_environment(self.env, self.branch, protection=self.protection)

    def test_reject_no_branch_restrictions(self):
        self.env["deployment_branch_policy"] = {
            "protected_branches": False, "custom_branch_policies": False}
        with self.assertRaises(preflight.ReadinessError):
            preflight.check_environment(self.env, self.branch, protection=self.protection)

    def test_reject_environment_name_mismatch(self):
        self.env["name"] = "production"
        with self.assertRaises(preflight.ReadinessError):
            preflight.check_environment(self.env, self.branch, protection=self.protection)

    def test_exact_dev_custom_branch_only(self):
        self.env["deployment_branch_policy"] = {
            "protected_branches": False, "custom_branch_policies": True}
        policies = {"total_count": 1, "branch_policies": [
            {"name": "dev", "type": "branch"}]}
        result = preflight.check_environment(self.env, self.branch, policies, self.protection)
        self.assertEqual(result["branch_policy"], "exact-dev")
        policies["branch_policies"][0]["name"] = "*"
        with self.assertRaises(preflight.ReadinessError):
            preflight.check_environment(self.env, self.branch, policies, self.protection)

    def test_reject_multiple_custom_branch_policies(self):
        self.env["deployment_branch_policy"] = {
            "protected_branches": False, "custom_branch_policies": True}
        policies = {"total_count": 2, "branch_policies": [
            {"name": "dev", "type": "branch"}, {"name": "*", "type": "branch"}]}
        with self.assertRaises(preflight.ReadinessError):
            preflight.check_environment(self.env, self.branch, policies, self.protection)

    def test_reject_missing_reviewer_identity(self):
        self.env["protection_rules"][0]["reviewers"] = [
            {"type": "User", "reviewer": {}}]
        with self.assertRaises(preflight.ReadinessError):
            preflight.check_environment(self.env, self.branch, protection=self.protection)

    def test_missing_protection_rejected(self):
        with self.assertRaises(preflight.ReadinessError):
            preflight.check_environment(self.env, self.branch, protection=None)

    def test_missing_required_pr_reviews(self):
        self.protection["required_pull_request_reviews"] = None
        with self.assertRaises(preflight.ReadinessError):
            preflight.check_environment(self.env, self.branch, protection=self.protection)

    def test_zero_approvals_rejected(self):
        self.protection["required_pull_request_reviews"]["required_approving_review_count"] = 0
        with self.assertRaises(preflight.ReadinessError):
            preflight.check_environment(self.env, self.branch, protection=self.protection)

    def test_stale_reviews_must_be_dismissed(self):
        self.protection["required_pull_request_reviews"]["dismiss_stale_reviews"] = False
        with self.assertRaises(preflight.ReadinessError):
            preflight.check_environment(self.env, self.branch, protection=self.protection)

    def test_required_portable_ci_must_be_present(self):
        self.protection["required_status_checks"]["contexts"] = ["unrelated"]
        with self.assertRaises(preflight.ReadinessError):
            preflight.check_environment(self.env, self.branch, protection=self.protection)

    def test_strict_checks_must_be_enabled(self):
        self.protection["required_status_checks"]["strict"] = False
        with self.assertRaises(preflight.ReadinessError):
            preflight.check_environment(self.env, self.branch, protection=self.protection)

    def test_admin_bypass_rejected(self):
        self.protection["enforce_admins"]["enabled"] = False
        with self.assertRaises(preflight.ReadinessError):
            preflight.check_environment(self.env, self.branch, protection=self.protection)

    def test_force_push_and_deletion_rejected(self):
        for key in ("allow_force_pushes", "allow_deletions"):
            with self.subTest(key=key):
                self.protection[key]["enabled"] = True
                with self.assertRaises(preflight.ReadinessError):
                    preflight.check_environment(self.env, self.branch, protection=self.protection)
                self.protection[key]["enabled"] = False

    def test_read_only_api_and_exact_endpoints(self):
        calls = []
        def getter(url, token):
            calls.append(url)
            assert token == "fake-token"
            if url.endswith("/environments/pilot"):
                return self.env
            if url.endswith("/branches/dev"):
                return self.branch
            if url.endswith("/branches/dev/protection"):
                return self.protection
            raise AssertionError("Unexpected API URL")
        self.assertEqual(preflight.run(getter, "fake-token")["status"],
                         "METADATA_PRECHECK_PASS")
        self.assertEqual(set(calls), {
            preflight.API + "/environments/pilot",
            preflight.API + "/branches/dev",
            preflight.API + "/branches/dev/protection",
        })

    def test_no_token_in_success_output(self):
        self.assertNotIn("GH_TOKEN", json.dumps(
            preflight.check_environment(self.env, self.branch, protection=self.protection)))


if __name__ == "__main__":
    unittest.main()
