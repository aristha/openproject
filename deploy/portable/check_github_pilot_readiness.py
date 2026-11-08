#!/usr/bin/env python3
"""Read-only GitHub pilot environment approval preflight; no release or deploy.

Fail closed when metadata cannot be read or environment reviewers / branch
constraints are absent. Running this audit does not approve a release.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com/repos/aristha/openproject"
ALLOWED = {
    API + "/environments/pilot",
    API + "/branches/dev",
    API + "/environments/pilot/deployment-branch-policies?per_page=100",
}
MAX_RESPONSE = 128 * 1024


class ReadinessError(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def github_get(url, token):
    # No arbitrary URL or user-controlled endpoint: token never sent elsewhere.
    if url not in ALLOWED or not token or "\n" in token:
        raise ReadinessError("GitHub environment preflight input rejected")
    opener = urllib.request.build_opener(NoRedirect())
    request = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "openproject-environment-preflight",
    })
    try:
        with opener.open(request, timeout=12) as response:
            if response.status != 200:
                raise ReadinessError("Environment metadata HTTP response rejected")
            payload = response.read(MAX_RESPONSE + 1)
    except (urllib.error.URLError, TimeoutError) as exc:
        raise ReadinessError("Unable to read GitHub environment metadata") from exc
    if len(payload) > MAX_RESPONSE:
        raise ReadinessError("Environment metadata response too large")
    try:
        return json.loads(payload)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ReadinessError("Malformed GitHub metadata") from exc


def check_environment(env, dev_branch, branch_policies=None):
    if not isinstance(env, dict) or env.get("name") != "pilot":
        raise ReadinessError("Expected existing pilot environment")
    rules = env.get("protection_rules")
    if not isinstance(rules, list):
        raise ReadinessError("Missing pilot environment protection rules")
    reviewer_rules = [rule for rule in rules if isinstance(rule, dict)
                      and rule.get("type") == "required_reviewers"]
    if len(reviewer_rules) != 1:
        raise ReadinessError("Exactly one required-reviewers rule is mandatory")
    reviewers = reviewer_rules[0].get("reviewers")
    if not isinstance(reviewers, list) or not reviewers:
        raise ReadinessError("Pilot required reviewers not configured")
    for reviewer in reviewers:
        if (not isinstance(reviewer, dict) or reviewer.get("type") not in ("User", "Team")
                or not isinstance(reviewer.get("reviewer"), dict)
                or not reviewer["reviewer"].get("login") and
                not reviewer["reviewer"].get("slug")):
            raise ReadinessError("Pilot reviewer entry incomplete")
    if env.get("prevent_self_review") is not True:
        raise ReadinessError("Pilot must prevent self-approval")
    policy = env.get("deployment_branch_policy")
    if not isinstance(policy, dict):
        raise ReadinessError("Pilot deployment branch policy missing")
    protected, custom = policy.get("protected_branches"), policy.get("custom_branch_policies")
    if type(protected) is not bool or type(custom) is not bool or protected == custom:
        raise ReadinessError("Ambiguous or permissive pilot branch policy")
    if not isinstance(dev_branch, dict) or dev_branch.get("name") != "dev":
        raise ReadinessError("Cannot validate dev branch")
    if protected:
        if dev_branch.get("protected") is not True:
            raise ReadinessError("Protected-branch policy requires protected dev")
    else:
        if not isinstance(branch_policies, dict):
            raise ReadinessError("Custom branch policy list not available")
        policies = branch_policies.get("branch_policies")
        if not isinstance(policies, list) or branch_policies.get("total_count") != 1:
            raise ReadinessError("Custom branch policy must allow exact dev only")
        if len(policies) != 1 or policies[0].get("name") != "dev" or policies[0].get("type") != "branch":
            raise ReadinessError("Custom pilot branch policy must be exact dev branch")
    return {
        "pilot_exists": True,
        "required_reviewers_present": True,
        "prevent_self_review": True,
        "dev_branch_protected": dev_branch.get("protected") is True,
        "branch_policy": "protected" if protected else "exact-dev",
        "status": "METADATA_PRECHECK_PASS",
    }


def run(getter, token):
    env = getter(API + "/environments/pilot", token)
    branch = getter(API + "/branches/dev", token)
    policy = env.get("deployment_branch_policy") if isinstance(env, dict) else None
    custom = (getter(API + "/environments/pilot/deployment-branch-policies?per_page=100", token)
              if isinstance(policy, dict) and policy.get("custom_branch_policies") is True
              else None)
    return check_environment(env, branch, custom)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--token-env", default="GH_TOKEN",
                        help="Name of env var holding GitHub metadata read token")
    args = parser.parse_args()
    token = os.environ.get(args.token_env, "")
    if not token:
        print("PILOT_PREFLIGHT_UNVERIFIED: GitHub metadata read token missing", file=sys.stderr)
        return 1
    try:
        result = run(github_get, token)
    except (ReadinessError, OSError, ValueError):
        print("PILOT_PREFLIGHT_UNVERIFIED: metadata rules rejected or inaccessible", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
