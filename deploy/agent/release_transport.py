#!/usr/bin/env python3
"""Approval-gated GitHub artifact transport. Never creates approval or executes deploy."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from http.client import HTTPException

from approved_release_agent import read_approval, require_root_owned_dir, verify_zip

API = "https://api.github.com/repos/aristha/openproject"
WORKFLOW = ".github/workflows/fork-prepare-portable-release.yml"
REDIRECT_HOSTS = (".actions.githubusercontent.com", ".githubusercontent.com", ".blob.core.windows.net")
MAX_ZIP = 8 * 1024 * 1024


class TransportError(ValueError):
    pass


def control_file(path):
    require_root_owned_dir(path.parent)
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
        raise TransportError("Unsafe root-only control file")
    return path.read_text(encoding="utf-8")


def validate_request(data):
    fields = {"schema_version", "run_id", "artifact_id", "artifact_sha256",
              "environment", "source_sha", "image", "expires_at"}
    if not isinstance(data, dict) or set(data) != fields or data["schema_version"] != 1:
        raise TransportError("Invalid request schema")
    if data["environment"] != "pilot" or any(type(data[x]) is not int or data[x] <= 0 for x in ("run_id", "artifact_id")):
        raise TransportError("Invalid target or run ID")
    if not isinstance(data["artifact_sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", data["artifact_sha256"]):
        raise TransportError("Invalid artifact digest")
    if not isinstance(data["source_sha"], str) or not re.fullmatch(r"[a-f0-9]{40}", data["source_sha"]):
        raise TransportError("Invalid release source")
    if not isinstance(data["image"], str) or not re.fullmatch(r"ghcr\.io/aristha/openproject@sha256:[a-f0-9]{64}", data["image"]):
        raise TransportError("Invalid immutable image")
    if not isinstance(data["expires_at"], str):
        raise TransportError("Invalid expiry")
    try:
        expires = dt.datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise TransportError("Invalid expiry") from exc
    now = dt.datetime.now(dt.timezone.utc)
    if expires.tzinfo is None or not now < expires <= now + dt.timedelta(days=7):
        raise TransportError("Expired or excessive authorization")
    return data


def validate_metadata(run, artifact, approved):
    if not isinstance(run, dict) or not isinstance(artifact, dict):
        raise TransportError("Invalid GitHub response")
    repo = run.get("repository")
    workflow = run.get("path")
    member = artifact.get("workflow_run")
    if (run.get("id") != approved["run_id"] or not isinstance(repo, dict) or
        repo.get("full_name") != "aristha/openproject" or
        run.get("event") != "workflow_dispatch" or run.get("head_branch") != "dev" or
        run.get("head_sha") != approved["source_sha"] or
        run.get("status") != "completed" or run.get("conclusion") != "success" or
        not isinstance(workflow, str) or workflow.split("@", 1)[0] != WORKFLOW):
        raise TransportError("Release workflow provenance metadata rejected")
    if (not isinstance(member, dict) or member.get("id") != approved["run_id"] or
        artifact.get("id") != approved["artifact_id"] or
        artifact.get("name") != f"openproject-pilot-{run.get('run_number')}" or
        artifact.get("expired") is not False or
        type(artifact.get("size_in_bytes")) is not int or
        not 0 < artifact["size_in_bytes"] <= MAX_ZIP or
        artifact.get("digest") not in (None, "sha256:" + approved["artifact_sha256"])):
        raise TransportError("Artifact provenance metadata rejected")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def safe_redirect(url):
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    return (parsed.scheme == "https" and parsed.port in (None, 443)
            and parsed.username is None and parsed.password is None
            and any(host.endswith(suffix) for suffix in REDIRECT_HOSTS))


def http_get(url, token, *, archive=False):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "api.github.com" or not url.startswith(API + "/"):
        raise TransportError("GitHub API origin rejected")
    opener = urllib.request.build_opener(NoRedirect())
    def request(target, headers):
        try:
            return opener.open(urllib.request.Request(target, headers=headers), timeout=20)
        except urllib.error.HTTPError as exc:
            if exc.code in (301, 302, 303, 307, 308):
                return exc
            raise TransportError(f"GitHub API HTTP {exc.code}") from None
    headers = {"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "approved-release-transport"}
    response = request(url, headers)
    if archive:
        if response.status not in (301, 302, 303, 307, 308):
            raise TransportError("Expected signed artifact redirect")
        location = response.headers.get("Location", "")
        response.close()
        if not safe_redirect(location):
            raise TransportError("Artifact redirect host rejected")
        # Signed object storage must NEVER receive the GitHub token.
        response = request(location, {"User-Agent": "approved-release-transport"})
        if response.status != 200:
            raise TransportError("Signed artifact download failed")
        limit = MAX_ZIP
    else:
        if response.status != 200:
            raise TransportError("Unexpected API metadata redirect")
        limit = 128 * 1024
    with response:
        result = response.read(limit + 1)
    if len(result) > limit:
        raise TransportError("Response size limit exceeded")
    return result


def atomic_stage(target, payload):
    require_root_owned_dir(target.parent)
    if target.exists() or target.is_symlink():
        st = target.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
            raise TransportError("Unsafe existing release target")
    fd, name = tempfile.mkstemp(prefix=".release-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, target)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def audit(path, event, *, detail=""):
    record = {"time": dt.datetime.now(dt.timezone.utc).isoformat(),
              "event": event, "detail": detail[:120]}
    line = json.dumps(record, sort_keys=True)
    print("RELEASE_TRANSPORT " + line, flush=True)
    require_root_owned_dir(path.parent)
    fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as output:
        st = os.fstat(output.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
            raise TransportError("Unsafe audit log")
        output.write(line + "\n")
        output.flush()
        os.fsync(output.fileno())


def alert_spool(folder):
    require_root_owned_dir(folder)
    fd, name = tempfile.mkstemp(prefix="alert-", suffix=".json", dir=folder)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        os.fchmod(output.fileno(), 0o600)
        json.dump({"severity": "error", "component": "release-transport",
                   "time": dt.datetime.now(dt.timezone.utc).isoformat(),
                   "message": "release transport verification failed"}, output)
        output.write("\n")


def run(args, *, getter=http_get):
    if os.geteuid() != 0:
        raise TransportError("Root required for host control files")
    request = validate_request(json.loads(control_file(Path(args.request))))
    approval = read_approval(Path(args.approval))
    if any(approval[k] != request[k] for k in ("artifact_sha256", "source_sha", "image", "environment")):
        raise TransportError("Independent approval mismatch")
    token = control_file(Path(args.token_file)).strip()
    if not token or len(token) > 1024 or "\n" in token:
        raise TransportError("Invalid read-only GitHub token")
    prefix = API + "/actions"
    release = json.loads(getter(f"{prefix}/runs/{request['run_id']}", token))
    artifact = json.loads(getter(f"{prefix}/artifacts/{request['artifact_id']}", token))
    validate_metadata(release, artifact, request)
    data = getter(f"{prefix}/artifacts/{request['artifact_id']}/zip", token, archive=True)
    if hashlib.sha256(data).hexdigest() != request["artifact_sha256"]:
        raise TransportError("Downloaded ZIP differs from independently approved hash")
    with tempfile.TemporaryDirectory(prefix="release-transport-") as directory:
        bundle = Path(directory) / "artifact.zip"
        bundle.write_bytes(data)
        unpack = Path(directory) / "unpacked"
        unpack.mkdir()
        manifest = verify_zip(bundle, request["artifact_sha256"], unpack)
        if any(manifest[k] != request[k] for k in ("environment", "source_sha", "image")):
            raise TransportError("Verified release manifest differs from approval")
    if args.stage:
        atomic_stage(Path(args.output), data)
    return "STAGED" if args.stage else "VERIFIED_ONLY"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", default="/etc/betasoft/approved-release/transport-request.json")
    parser.add_argument("--approval", default="/etc/betasoft/approved-release/approval.json")
    parser.add_argument("--token-file", default="/etc/betasoft/release-transport/github-token")
    parser.add_argument("--output", default="/etc/betasoft/approved-release/release.zip")
    parser.add_argument("--audit", default="/var/lib/betasoft-release-agent/transport-audit.jsonl")
    parser.add_argument("--alerts", default="/var/lib/betasoft-release-agent/alerts")
    parser.add_argument("--stage", action="store_true", help="Only stage verified ZIP; no deploy")
    args = parser.parse_args()
    try:
        result = run(args)
        audit(Path(args.audit), result)
        return 0
    except (ValueError, OSError, urllib.error.URLError, HTTPException, json.JSONDecodeError) as exc:
        # No signed redirect URLs or bearer tokens in user-readable logs.
        print("RELEASE_TRANSPORT_REJECTED", file=sys.stderr)
        try:
            audit(Path(args.audit), "FAILED", detail=type(exc).__name__)
            alert_spool(Path(args.alerts))
        except (OSError, ValueError):
            print("RELEASE_TRANSPORT_ALERT_SPOOL_FAILED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
