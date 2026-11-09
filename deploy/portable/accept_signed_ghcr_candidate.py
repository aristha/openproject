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
from check_verified_build_attestation import verified_output_schema

SOURCE = re.compile(r"[a-f0-9]{40}\Z")
DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
IDENTITY = ("https://github.com/aristha/openproject/.github/workflows/"
            "fork-build-attested-image.yml@refs/heads/dev")
IMAGE_NAME = "ghcr.io/aristha/openproject@"
MAX_OUTPUT = 1024 * 1024


class AcceptanceStageError(ProvenanceError):
    """Publicly printable static diagnostic code, never an untrusted error."""

    def __init__(self, stage, code, *, schema=None, detail="GHCR acceptance failed"):
        self.stage = stage
        self.code = code
        self.schema = schema
        super().__init__(detail)


def safe_diagnostic(error):
    if isinstance(error, AcceptanceStageError):
        message = ("GHCR_SIGNED_PROVENANCE_ACCEPTANCE_FAILED stage=" +
                   error.stage + " code=" + error.code)
        if error.schema is not None:
            message += " schema=" + error.schema
        return message
    return "GHCR_SIGNED_PROVENANCE_ACCEPTANCE_FAILED stage=preflight code=INPUT_OR_RUNTIME_REJECTED"


def checked_cosign(runner, command, environment, *, stage):
    try:
        return runner(command, capture_output=True, timeout=90,
                      check=False, env=environment)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AcceptanceStageError(stage, "COSIGN_EXECUTION_ERROR") from exc


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
    # Separate cryptographic process errors from verified-statement schema/policy
    # rejection. Never emit raw Cosign stdout/stderr or untrusted payloads.
    observed = {}
    def observed_runner(command, **kwargs):
        completed = runner(command, **kwargs)
        observed["returncode"] = completed.returncode
        observed["stdout"] = completed.stdout
        return completed

    try:
        positive = verify_image(
            image, policy, runner=observed_runner,
            cosign_binary=binary, subprocess_env=environment)
    except (ProvenanceError, OSError, subprocess.TimeoutExpired) as exc:
        if observed.get("returncode") is None:
            code = "COSIGN_EXECUTION_ERROR"
        elif observed["returncode"] != 0:
            code = "COSIGN_CRYPTO_REJECTED"
        else:
            code = "VERIFIED_STATEMENT_POLICY_REJECTED"
        schema = (verified_output_schema(observed["stdout"][:MAX_OUTPUT])
                  if code == "VERIFIED_STATEMENT_POLICY_REJECTED" else None)
        raise AcceptanceStageError("positive", code, schema=schema) from exc
    if positive is not True:
        raise AcceptanceStageError("positive", "VERIFIED_STATEMENT_POLICY_REJECTED")

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
    completed = checked_cosign(runner, statement_command, environment,
                               stage="negative_source")
    if completed.returncode != 0:
        raise AcceptanceStageError("negative_source", "COSIGN_CRYPTO_REJECTED")
    wrong_policy = dict(policy, build_sha=wrong_source)
    try:
        parse_verified_cosign(completed.stdout, wrong_policy)
    except ProvenanceError:
        pass
    else:
        raise AcceptanceStageError("negative_source", "WRONG_SOURCE_ACCEPTED", detail="Wrong image-build source was accepted")

    # Negative signer: exact identity MUST reject a different certificate.
    # The signed image remains unchanged; only the expected signer changes.
    wrong_identity = IDENTITY.replace("@refs/heads/dev", "@refs/heads/not-dev")
    wrong_signer = list(statement_command)
    wrong_signer[wrong_signer.index("--certificate-identity") + 1] = wrong_identity
    rejected = checked_cosign(runner, wrong_signer, environment,
                              stage="negative_signer")
    if rejected.returncode == 0:
        raise AcceptanceStageError("negative_signer", "WRONG_SIGNER_ACCEPTED", detail="Unexpected signer identity was accepted")

    # Negative digest: request a DIFFERENT immutable OCI image digest. A valid
    # attestation must not bind a different image under the same repository.
    other_digest = ("0" if digest[7] != "0" else "1") + digest[8:]
    if len(other_digest) != 64:
        raise ProvenanceError("Invalid negative-test digest")
    other_image = IMAGE_NAME + "sha256:" + other_digest
    wrong_image = list(statement_command)
    wrong_image[-1] = other_image
    rejected = checked_cosign(runner, wrong_image, environment,
                              stage="negative_digest")
    if rejected.returncode == 0:
        raise AcceptanceStageError("negative_digest", "WRONG_DIGEST_ACCEPTED", detail="Unexpected image digest was accepted")

    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--build-sha", required=True)
    args = parser.parse_args()
    try:
        run_acceptance(args.image_digest, args.build_sha)
    except (OSError, subprocess.TimeoutExpired, ProvenanceError, ValueError) as exc:
        print(safe_diagnostic(exc), file=sys.stderr)
        return 1
    print("GHCR_SIGNED_PROVENANCE_ACCEPTANCE_PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
