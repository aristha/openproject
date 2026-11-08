#!/usr/bin/env python3
"""Opt-in, bounded outbound delivery of Phase-2 failure alerts (no deployment)."""
import argparse
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from approved_release_agent import require_root_owned_dir
from release_transport import NoRedirect, control_file

MAX_ALERT = 16 * 1024
MAX_ATTEMPTS = 3
RETRY_CODES = {408, 429, 500, 502, 503, 504}


class DeliveryError(ValueError):
    pass


def config_from(path):
    config = json.loads(control_file(Path(path)))
    if not isinstance(config, dict) or set(config) != {
        "schema_version", "endpoint", "expected_host", "token_file"
    } or config["schema_version"] != 1:
        raise DeliveryError("Alert delivery config schema invalid")
    address = config["endpoint"]
    if not isinstance(address, str) or len(address) > 2048:
        raise DeliveryError("Invalid notification endpoint")
    parsed = urllib.parse.urlsplit(address)
    host = parsed.hostname
    if (parsed.scheme != "https" or not host or host != config["expected_host"] or
            parsed.port not in (None, 443) or parsed.username is not None or
            parsed.password is not None or parsed.fragment or
            host in ("localhost", "metadata.google.internal") or
            host.endswith((".local", ".internal")) or
            not re.fullmatch(r"[a-z0-9.-]+", host) or
            len(host) > 253 or not parsed.path.startswith("/")):
        raise DeliveryError("Alert endpoint origin rejected")
    try:
        ipaddress.ip_address(host)
        raise DeliveryError("IP-address alert destination prohibited")
    except ValueError as exc:
        if isinstance(exc, DeliveryError):
            raise
    if not isinstance(config["token_file"], str) or not config["token_file"].startswith("/"):
        raise DeliveryError("Alert token path must be absolute")
    return config


def publish(url, token, event, key):
    payload = json.dumps({"idempotency_key": key, "event": event},
                         sort_keys=True).encode("utf-8")
    opener = urllib.request.build_opener(NoRedirect())
    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + token,
                 "Idempotency-Key": key, "User-Agent": "betasoft-release-alert"})
    try:
        with opener.open(req, timeout=10) as resp:
            status = resp.status
            resp.read(2048)
    except urllib.error.HTTPError as exc:
        status = exc.code
        exc.close()
    except (urllib.error.URLError, TimeoutError, OSError):
        return "retry"
    if 200 <= status < 300:
        return "ok"
    return "retry" if status in RETRY_CODES else "reject"


def safe_alert(path):
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077 or st.st_size > MAX_ALERT:
        raise DeliveryError("Unsafe alert spool entry")
    content = path.read_bytes()
    if len(content) > MAX_ALERT:
        raise DeliveryError("Alert payload exceeds size limit")
    event = json.loads(content)
    if (not isinstance(event, dict) or event.get("severity") != "error" or
            event.get("component") != "release-transport" or
            not isinstance(event.get("message"), str) or
            event.get("message") != "release transport verification failed" or
            not isinstance(event.get("time"), str)):
        raise DeliveryError("Unexpected alert schema")
    return event, hashlib.sha256(content).hexdigest()


def run(args, *, sender=publish, sleeper=time.sleep):
    if os.geteuid() != 0:
        raise DeliveryError("Root-only alert dispatcher")
    spool, delivered = Path(args.spool), Path(args.delivered)
    require_root_owned_dir(spool)
    require_root_owned_dir(delivered)
    config = config_from(args.config)
    token = control_file(Path(config["token_file"])).strip()
    if not token or len(token) > 1024 or "\n" in token:
        raise DeliveryError("Invalid notification credential")
    fd = os.open(spool / ".delivery.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+") as lock:
        st = os.fstat(lock.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
            raise DeliveryError("Unsafe dispatcher lock")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        failures = 0
        for path in sorted(spool.glob("alert-*.json")):
            event, key = safe_alert(path)
            destination = delivered / path.name
            if destination.exists() or destination.is_symlink():
                raise DeliveryError("Refusing to overwrite delivered alert")
            for attempt in range(MAX_ATTEMPTS):
                result = sender(config["endpoint"], token, event, key)
                if result == "ok":
                    os.replace(path, destination)
                    print("ALERT_DELIVERED key=" + key[:12], flush=True)
                    break
                if result != "retry":
                    failures += 1
                    break
                if attempt + 1 < MAX_ATTEMPTS:
                    sleeper(2 ** attempt)
            else:
                failures += 1
        if failures:
            raise DeliveryError("Alert delivery incomplete; pending alerts retained")
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/betasoft/release-transport/alert-delivery.json")
    parser.add_argument("--spool", default="/var/lib/betasoft-release-agent/alerts")
    parser.add_argument("--delivered", default="/var/lib/betasoft-release-agent/alerts-delivered")
    args = parser.parse_args()
    try:
        return run(args)
    except (DeliveryError, OSError, ValueError, json.JSONDecodeError) as exc:
        print("ALERT_DISPATCH_REJECTED: " + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
