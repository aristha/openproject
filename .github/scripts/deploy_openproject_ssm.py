#!/usr/bin/env python3
"""Send the reviewed pilot deployment script using AWS SSM Run Command."""
import argparse
import base64
import json
import pathlib
import re
import subprocess
import sys
import time

def aws(*parts):
    proc = subprocess.run(["aws", *parts, "--region", "ap-southeast-2", "--output", "json"],
                          capture_output=True, text=True, check=True)
    return json.loads(proc.stdout) if proc.stdout.strip() else {}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"i-[0-9a-f]{8,17}", args.instance_id):
        parser.error("Invalid EC2 instance ID")
    if not re.fullmatch(r"ghcr\.io/aristha/openproject@sha256:[0-9a-f]{64}", args.image):
        parser.error("Require immutable GHCR image digest")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{2,62}", args.bucket):
        parser.error("Invalid bucket")
    path = pathlib.Path(__file__).with_name("openproject-remote-deploy.sh")
    script = path.read_text()
    if args.dry_run:
        print("DRY_RUN_OK: reviewed script, image digest, bucket and instance arguments validated")
        print("No AWS changes executed.")
        return
    state = aws("ec2", "describe-instances", "--instance-ids", args.instance_id)
    inst = state["Reservations"][0]["Instances"][0]
    if inst["State"]["Name"] != "running":
        sys.exit("EC2 is not running. Deployment will NOT start a stopped instance.")
    encoded = base64.b64encode(script.encode()).decode()
    # All inputs above are strictly validated; avoid shell interpolation of user-provided code.
    line = f"echo '{encoded}' | base64 -d > /tmp/betasoft-deploy.sh && bash /tmp/betasoft-deploy.sh '{args.image}' '{args.bucket}'"
    sent = aws("ssm", "send-command",
               "--document-name", "AWS-RunShellScript",
               "--instance-ids", args.instance_id,
               "--comment", "BetaSoft GitHub Actions manual pilot deploy",
               "--timeout-seconds", "1800",
               "--parameters", json.dumps({"commands": ["set -eu", line]}))
    cid = sent["Command"]["CommandId"]
    print("SSM CommandId:", cid, flush=True)
    for _ in range(120):
        time.sleep(10)
        try:
            status = aws("ssm", "get-command-invocation", "--command-id", cid,
                         "--instance-id", args.instance_id)
        except subprocess.CalledProcessError:
            continue
        if status["Status"] in ("Success", "Failed", "Cancelled", "TimedOut"):
            print("Status:", status["Status"])
            print("Output:", status.get("StandardOutputContent", "")[-3000:])
            print("Errors:", status.get("StandardErrorContent", "")[-3000:])
            if status["Status"] != "Success":
                sys.exit(1)
            return
    sys.exit("SSM command polling timeout; check AWS SSM CommandId before retry.")

if __name__ == "__main__":
    main()
