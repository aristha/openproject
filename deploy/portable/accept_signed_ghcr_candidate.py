#!/usr/bin/env python3
"""Read-only online GHCR Cosign/SLSA acceptance. No image push, approval or deploy."""
import argparse
import base64
import json
import os
import shutil
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from image_provenance import (IMAGE, ISSUER, ProvenanceError,
                              parse_verified_cosign, verify_image)

SOURCE = re.compile(r"[a-f0-9]{40}\Z")
DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
IDENTITY = ("https://github.com/aristha/openproject/.github/workflows/"
            "fork-build-attested-image.yml@refs/heads/dev")
IMAGE_NAME = "ghcr.io/aristha/openproject@"
MAX_OUTPUT = 1024 * 1024


def policy_for(digest, source):
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        raise ProvenanceError("Expected immutable lowercase image digest")
    if not isinstance(source, str) or not SOURCE.fullmatch(source):
        raise ProvenanceError("Expected full lowercase image-build source SHA")
    return {
        "image": IMAGE_NAME + digest,
        "build_sha": source,
        "certificate_identity": IDENTITY,
        "certificate_oidc_issuer": ISSUER,
        "source_repository": "aristha/openproject",
    }


def run_acceptance(digest, source, *, runner=subprocess.run):
    policy = policy_for(digest, source)
    image = policy["image"]
    # GitHub cosign-installer installs under runner HOME, not /usr/local/bin.
    # Resolve only for the explicitly invoked read-only acceptance workflow.
    binary = shutil.which("cosign")
    if not binary or not os.path.isabs(binary):
        raise ProvenanceError("Runner Cosign executable unavailable")
    # Preserve the runner's GHCR Docker login. The host release agent still
    # uses its own root-owned binary and isolated HOME by default.
    environment = os.environ.copy()
    # Positive: Cosign verifies Fulcio identity, issuer, signed statement,
    # image digest and transparency log. Python validates the SLSA subject/SHA.
    if verify_image(image, policy, runner=runner,
                    cosign_binary=binary, subprocess_env=environment) is not True:
        raise ProvenanceError("Verified image did not meet acceptance contract")

    # Negative source SHA: a successful signature alone MUST NOT authorize an
    # image whose reviewed builder commit differs from the statement.
    wrong_source = ("0" if source[0] != "0" else "1") + source[1:]
    statement_command = [
        binary, "verify-attestation",
        "--type", "slsaprovenance1",
        "--certificate-identity", IDENTITY,
        "--certificate-oidc-issuer", ISSUER,
        "--output", "json", image,
    ]
    completed = runner(statement_command, capture_output=True, timeout=90,
                       check=False, env=environment)
    if completed.returncode != 0:
        raise ProvenanceError("Cannot re-verify signed statement for SHA negative test")
    wrong_policy = dict(policy, build_sha=wrong_source)
    try:
        parse_verified_cosign(completed.stdout, wrong_policy)
    except ProvenanceError:
        pass
    else:
        raise ProvenanceError("Wrong image-build source was accepted")

    # Negative signer: exact identity MUST reject a different certificate.
    # The signed image remains unchanged; only the expected signer changes.
    wrong_identity = IDENTITY.replace("@refs/heads/dev", "@refs/heads/not-dev")
    wrong_signer = list(statement_command)
    wrong_signer[wrong_signer.index("--certificate-identity") + 1] = wrong_identity
    rejected = runner(wrong_signer, capture_output=True, timeout=90,
                      check=False, env=environment)
    if rejected.returncode == 0:
        raise ProvenanceError("Unexpected signer identity was accepted")

    # Negative digest: request a DIFFERENT immutable OCI image digest. A valid
    # attestation must not bind a different image under the same repository.
    other_digest = ("0" if digest[7] != "0" else "1") + digest[8:]
    if len(other_digest) != 64:
        raise ProvenanceError("Invalid negative-test digest")
    other_image = IMAGE_NAME + "sha256:" + other_digest
    wrong_image = list(statement_command)
    wrong_image[-1] = other_image
    rejected = runner(wrong_image, capture_output=True, timeout=90,
                      check=False, env=environment)
    if rejected.returncode == 0:
        raise ProvenanceError("Unexpected image digest was accepted")

    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--build-sha", required=True)
    args = parser.parse_args()
    try:
        run_acceptance(args.image_digest, args.build_sha)
    except (OSError, subprocess.TimeoutExpired, ProvenanceError, ValueError):
        print("GHCR_SIGNED_PROVENANCE_ACCEPTANCE_FAILED", file=sys.stderr)
        return 1
    print("GHCR_SIGNED_PROVENANCE_ACCEPTANCE_PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
