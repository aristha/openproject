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

    def test_protected_dev_with_reviewers(self):
        result = preflight.check_environment(self.env, self.branch)
        self.assertEqual(result["status"], "METADATA_PRECHECK_PASS")
        self.assertTrue(result["required_reviewers_present"])

    def test_reject_missing_required_reviewers(self):
        self.env["protection_rules"] = []
        with self.assertRaises(preflight.ReadinessError):
            preflight.check_environment(self.env, self.branch)

    def test_reject_no_self_review_protection(self):
        self.env["prevent_self_review"] = False
        with self.assertRaises(preflight.ReadinessError):
            preflight.check_environment(self.env, self.branch)

    def test_reject_unprotected_dev(self):
        self.branch["protected"] = False
        with self.assertRaises(preflight.ReadinessError):
            preflight.check_environment(self.env, self.branch)

    def test_reject_no_branch_restrictions(self):
        self.env["deployment_branch_policy"] = {
            "protected_branches": False, "custom_branch_policies": False}
        with self.assertRaises(preflight.ReadinessError):
            preflight.check_environment(self.env, self.branch)

    def test_reject_environment_name_mismatch(self):
        self.env["name"] = "production"
        with self.assertRaises(preflight.ReadinessError):
            preflight.check_environment(self.env, self.branch)

    def test_exact_dev_custom_branch_only(self):
        self.env["deployment_branch_policy"] = {
            "protected_branches": False, "custom_branch_policies": True}
        policies = {"total_count": 1, "branch_policies": [
            {"name": "dev", "type": "branch"}]}
        result = preflight.check_environment(self.env, self.branch, policies)
        self.assertEqual(result["branch_policy"], "exact-dev")
        policies["branch_policies"][0]["name"] = "*"
        with self.assertRaises(preflight.ReadinessError):
            preflight.check_environment(self.env, self.branch, policies)

    def test_reject_multiple_custom_branch_policies(self):
        self.env["deployment_branch_policy"] = {
            "protected_branches": False, "custom_branch_policies": True}
        policies = {"total_count": 2, "branch_policies": [
            {"name": "dev", "type": "branch"}, {"name": "*", "type": "branch"}]}
        with self.assertRaises(preflight.ReadinessError):
            preflight.check_environment(self.env, self.branch, policies)

    def test_reject_missing_reviewer_identity(self):
        self.env["protection_rules"][0]["reviewers"] = [
            {"type": "User", "reviewer": {}}]
        with self.assertRaises(preflight.ReadinessError):
            preflight.check_environment(self.env, self.branch)

    def test_read_only_api_and_exact_endpoints(self):
        calls = []
        def getter(url, token):
            calls.append(url)
            assert token == "fake-token"
            if url.endswith("/environments/pilot"):
                return self.env
            if url.endswith("/branches/dev"):
                return self.branch
            raise AssertionError("Unexpected API URL")
        self.assertEqual(preflight.run(getter, "fake-token")["status"],
                         "METADATA_PRECHECK_PASS")
        self.assertEqual(set(calls), {
            preflight.API + "/environments/pilot",
            preflight.API + "/branches/dev",
        })

    def test_no_token_in_success_output(self):
        self.assertNotIn("GH_TOKEN", json.dumps(
            preflight.check_environment(self.env, self.branch)))


if __name__ == "__main__":
    unittest.main()
