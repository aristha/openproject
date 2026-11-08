#!/usr/bin/env python3
"""Host-side approved release reconciler. Never downloads or trusts GitHub unaided.

An authorized operator stages a ZIP and a root-owned approval JSON locally.
Default is observe-only. --execute requires explicit opt-in and strict gates.
"""
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import zipfile
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "portable"))
from verify_release import FILES, verify

APPROVAL_FIELDS = {
    "schema_version", "environment", "artifact_sha256", "image",
    "source_sha", "expires_at", "schema_approved",
}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
IMAGE = re.compile(r"ghcr\.io/aristha/openproject@sha256:[0-9a-f]{64}\Z")
BUNDLE_NAMES = FILES | {"SHA256SUMS"}


def reject(reason):
    raise ValueError(reason)


def read_approval(path):
    st = path.lstat()
    if not path.is_file() or path.is_symlink() or st.st_uid != 0 or st.st_mode & 0o022:
        reject("Approval must be root-owned regular file, not writable by group/others")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) != APPROVAL_FIELDS:
        reject("Approval schema or keys invalid")
    if data["schema_version"] != 1 or data["environment"] != "pilot":
        reject("Only v1 pilot approvals are supported")
    if not isinstance(data["artifact_sha256"], str) or not HEX64.fullmatch(data["artifact_sha256"]):
        reject("Invalid artifact hash")
    if not isinstance(data["source_sha"], str) or not HEX40.fullmatch(data["source_sha"]):
        reject("Invalid approved source revision")
    if not isinstance(data["image"], str) or not IMAGE.fullmatch(data["image"]):
        reject("Invalid approved immutable image")
    if data["schema_approved"] != "NO_MIGRATIONS":
        reject("Schema requires explicit NO_MIGRATIONS approval")
    if not isinstance(data["expires_at"], str):
        reject("Invalid approval expiry")
    try:
        expiry = dt.datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))
    except ValueError:
        reject("Invalid approval expiry format")
    if expiry.tzinfo is None:
        reject("Approval expiry must include timezone")
    now = dt.datetime.now(dt.timezone.utc)
    if expiry <= now or expiry > now + dt.timedelta(days=7):
        reject("Approval expired or unreasonably far in future")
    return data


def verify_zip(zip_path, approved_hash, output):
    if zip_path.is_symlink() or not zip_path.is_file():
        reject("Release ZIP missing or symlinked")
    if zip_path.stat().st_size > 8 * 1024 * 1024:
        reject("Release ZIP exceeds 8 MiB")
    if hashlib.sha256(zip_path.read_bytes()).hexdigest() != approved_hash:
        reject("Release ZIP differs from independently approved SHA256")
    with zipfile.ZipFile(zip_path) as z:
        if sum(info.file_size for info in z.infolist()) > 4 * 1024 * 1024:
            reject("Release ZIP uncompressed size exceeds 4 MiB")
        if set(z.namelist()) != BUNDLE_NAMES or len(z.infolist()) != len(BUNDLE_NAMES):
            reject("Unexpected ZIP contents")
        for entry in z.infolist():
            if entry.is_dir() or entry.file_size > 1024 * 1024:
                reject("Unsafe file entry")
            # No directories, symlinks, executable ZIP traversal, or duplicate entries.
            if entry.filename not in BUNDLE_NAMES:
                reject("Unexpected ZIP path")
            if ((entry.external_attr >> 16) & 0o170000) == 0o120000:
                reject("Symlinks prohibited")
            (output / entry.filename).write_bytes(z.read(entry))
    verify(output)
    return json.loads((output / "release.json").read_text(encoding="utf-8"))


def permitted_window(now):
    local = now.astimezone(ZoneInfo("Asia/Ho_Chi_Minh"))
    return local.weekday() < 5 and (8, 45) <= (local.hour, local.minute) < (17, 15)


def require_root_owned_dir(path):
    """Reject unsafe directory components, including symlinks and writable parents."""
    if not path.is_absolute():
        reject("Agent directory path must be absolute")
    current = Path("/")
    for component in path.parts[1:]:
        current = current / component
        st = current.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            reject("Agent directory path has unsafe ownership or permissions")


def require_root_executable(path):
    if not path.is_absolute():
        reject("Backup hook must use an absolute path")
    require_root_owned_dir(path.parent)
    st = path.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0
            or st.st_mode & 0o022 or not os.access(path, os.X_OK)):
        reject("Backup hook must be a root-owned, non-writable executable regular file")


def require_root_lock(fd):
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
        reject("Agent lock file must be root-only")


def read_state(path):
    if not path.exists() and not path.is_symlink():
        return None
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
        reject("Agent deployment state must be a root-only regular file")
    return json.loads(path.read_text(encoding="utf-8"))


def run(args):
    if os.geteuid() != 0:
        reject("Agent must run as root on pilot to use root-only Docker Compose plugin")
    inbox = Path(args.inbox)
    require_root_owned_dir(inbox)
    approval_path = inbox / "approval.json"
    zip_path = inbox / "release.zip"
    if not approval_path.exists():
        print("AGENT_NO_APPROVED_RELEASE")
        return 0
    approval = read_approval(approval_path)
    if not zip_path.exists():
        reject("Approved release ZIP missing")

    state_dir = Path(args.state_dir)
    require_root_owned_dir(state_dir)
    lock_path = state_dir / "agent.lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a+") as lock:
        require_root_lock(lock.fileno())
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with tempfile.TemporaryDirectory(prefix="openproject-agent-") as scratch:
            extracted = Path(scratch)
            release = verify_zip(zip_path, approval["artifact_sha256"], extracted)
            if release["environment"] != approval["environment"]:
                reject("Environment mismatch")
            if release["image"] != approval["image"] or release["source_sha"] != approval["source_sha"]:
                reject("Approval does not match release metadata")
            if release["migrations"] != "not-performed":
                reject("Migration-bearing releases rejected")

            state_file = state_dir / "last-deployed.json"
            previous = read_state(state_file)
            if previous is not None and previous.get("artifact_sha256") == approval["artifact_sha256"]:
                print("AGENT_ALREADY_APPLIED")
                return 0

            if not args.execute:
                print("AGENT_OBSERVE_ONLY verified approved release; nothing deployed")
                return 0
            if os.environ.get("OPENPROJECT_AGENT_EXECUTE_ENABLED") != "YES":
                reject("Execution disabled; root-only config must explicitly enable it")
            if not permitted_window(dt.datetime.now(dt.timezone.utc)):
                reject("Outside weekday 08:45–17:15 Asia/Ho_Chi_Minh deployment window")
            backup = Path(args.backup_hook)
            require_root_executable(backup)
            # Only execute the inspected, checksum-verified, explicitly approved release script.
            deploy = extracted / "deploy.sh"
            env = {
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "HOME": "/root",
                "LANG": "C.UTF-8",
                "DEPLOY_ROOT": args.deploy_root,
                "DEPLOY_BACKUP_HOOK": str(backup),
                "DEPLOY_SCHEMA_APPROVED": "NO_MIGRATIONS",
            }
            cmd = ["/bin/bash", str(deploy), "--execute", approval["image"]]
            print("AGENT_START_APPROVED_RELEASE image=" + approval["image"], flush=True)
            subprocess.run(cmd, check=True, env=env, timeout=1500)
            # An atomic state record is committed only on successful deploy.
            record = {
                "artifact_sha256": approval["artifact_sha256"],
                "source_sha": approval["source_sha"],
                "image": approval["image"],
                "deployed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            }
            fd, temp_path = tempfile.mkstemp(prefix=".last-deployed-", dir=state_dir)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as state_out:
                    os.fchmod(state_out.fileno(), 0o600)
                    json.dump(record, state_out, indent=2)
                    state_out.write("\n")
                    state_out.flush()
                    os.fsync(state_out.fileno())
                os.replace(temp_path, state_file)
            finally:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
            print("AGENT_DEPLOY_SUCCESS", flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inbox", default="/etc/betasoft/approved-release")
    parser.add_argument("--state-dir", default="/var/lib/betasoft-release-agent")
    parser.add_argument("--deploy-root", default="/opt/openproject-pilot")
    parser.add_argument("--backup-hook", default="/usr/local/libexec/betasoft-aws-s3-backup.sh")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    try:
        return run(args)
    except (ValueError, OSError, subprocess.SubprocessError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        print("AGENT_REJECTED: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
