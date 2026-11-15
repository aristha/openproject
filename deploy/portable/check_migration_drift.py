#!/usr/bin/env python3
"""Fail closed when db/migrate differs between the running and the new commit.

Portable releases never run migrations, so any change under db/migrate between
the currently running source SHA and the new source SHA must block release
preparation. Prints "not-performed" (the value for release.json "migrations") on success.
"""
import argparse
import pathlib
import re
import subprocess
import sys

SHA_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
MIGRATE_PATH = "db/migrate"


def _git(repo: pathlib.Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)


def check(repo: pathlib.Path, current_sha: str, new_sha: str) -> str:
    for label, sha in (("current", current_sha), ("new", new_sha)):
        if not SHA_PATTERN.fullmatch(sha):
            raise ValueError(f"{label} SHA must be a full 40-hex lowercase commit hash")
        if _git(repo, "cat-file", "-e", f"{sha}^{{commit}}").returncode != 0:
            raise ValueError(f"{label} SHA {sha} is not available in the checkout (fetch more history)")
    result = _git(repo, "diff", "--name-status", "--no-renames", current_sha, new_sha, "--", MIGRATE_PATH)
    if result.returncode != 0:
        raise ValueError(f"git diff failed: {result.stderr.strip()}")
    changed = result.stdout.strip()
    if changed:
        raise ValueError(
            f"{MIGRATE_PATH} changed between running {current_sha} and new {new_sha}; "
            "portable releases do not support database migrations yet:\n" + changed)
    return "not-performed"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current-sha", required=True)
    parser.add_argument("--new-sha", required=True)
    parser.add_argument("--repo", default=".")
    args = parser.parse_args(argv)
    try:
        print(check(pathlib.Path(args.repo), args.current_sha, args.new_sha))
    except ValueError as exc:
        print(f"Migration check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
