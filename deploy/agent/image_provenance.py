#!/usr/bin/env python3
"""Fail-closed Sigstore SLSA image provenance gate for approved ZIP staging.

Cosign performs signature/certificate/transparency-log verification; this module
additionally binds the verified statement to the approved image and build SHA.
No builder keys or trusted roots are downloaded from untrusted operator input.
"""
import base64
import binascii
import json
import os
from pathlib import Path
import re
import subprocess

from approved_release_agent import require_root_owned_dir
from release_transport import control_file

IMAGE = re.compile(r"ghcr\.io/aristha/openproject@sha256:([a-f0-9]{64})\Z")
SHA = re.compile(r"[a-f0-9]{40}\Z")
WORKFLOW_ID = re.compile(
    r"https://github\.com/aristha/openproject/\.github/workflows/"
    r"[a-zA-Z0-9_.-]+\.ya?ml@refs/heads/dev\Z"
)
PREDICATE = "https://slsa.dev/provenance/v1"
ISSUER = "https://token.actions.githubusercontent.com"
SOURCES = {"git+https://github.com/aristha/openproject", "https://github.com/aristha/openproject"}
MAX_RESULT = 1024 * 1024


class ProvenanceError(ValueError):
    pass


def load_policy(path):
    data = json.loads(control_file(Path(path)))
    if not isinstance(data, dict) or set(data) != {
        "schema_version", "image", "build_sha", "certificate_identity",
        "certificate_oidc_issuer", "source_repository"
    }:
        raise ProvenanceError("Provenance policy schema rejected")
    if (type(data["schema_version"]) is not int or data["schema_version"] != 1
            or not isinstance(data["image"], str) or not IMAGE.fullmatch(data["image"])
            or not isinstance(data["build_sha"], str) or not SHA.fullmatch(data["build_sha"])
            or not isinstance(data["certificate_identity"], str)
            or not WORKFLOW_ID.fullmatch(data["certificate_identity"])
            or data["certificate_oidc_issuer"] != ISSUER
            or data["source_repository"] != "aristha/openproject"):
        raise ProvenanceError("Provenance trust policy rejected")
    return data


def verified_statement(statement, *, digest, build_sha):
    if not isinstance(statement, dict):
        return False
    if (statement.get("_type") != "https://in-toto.io/Statement/v1"
            or statement.get("predicateType") != PREDICATE):
        return False
    subjects = statement.get("subject")
    if not isinstance(subjects, list):
        return False
    matches = [s for s in subjects if isinstance(s, dict)
               and isinstance(s.get("digest"), dict)
               and s["digest"].get("sha256") == digest
               and s.get("name") in ("ghcr.io/aristha/openproject",
                                      "pkg:docker/aristha/openproject")]
    if not matches:
        return False
    predicate = statement.get("predicate")
    definition = predicate.get("buildDefinition") if isinstance(predicate, dict) else None
    resolved = definition.get("resolvedDependencies") if isinstance(definition, dict) else None
    if not isinstance(resolved, list):
        return False
    for dependency in resolved:
        if not isinstance(dependency, dict):
            continue
        src = dependency.get("uri")
        hashes = dependency.get("digest")
        if src in SOURCES and isinstance(hashes, dict) and hashes.get("gitCommit") == build_sha:
            return True
    return False


def parse_verified_cosign(result, policy):
    """Cosign must have exited successfully; output never substitutes for verification."""
    if len(result) > MAX_RESULT:
        raise ProvenanceError("Cosign verification output too large")
    try:
        entries = json.loads(result)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ProvenanceError("Malformed cosign verification output") from exc
    if isinstance(entries, dict):
        entries = [entries]
    if not isinstance(entries, list) or not entries:
        raise ProvenanceError("Missing verified attestations")
    digest = IMAGE.fullmatch(policy["image"]).group(1)
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("payload"), str):
            continue
        try:
            decoded = base64.b64decode(entry["payload"], validate=True)
            statement = json.loads(decoded)
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if verified_statement(statement, digest=digest, build_sha=policy["build_sha"]):
            return True
    raise ProvenanceError("No signed SLSA statement binds approved image and build SHA")


def verify_image(image, policy, *, runner=subprocess.run):
    if image != policy["image"]:
        raise ProvenanceError("Approved image differs from image provenance policy")
    command = [
        "/usr/local/bin/cosign", "verify-attestation",
        "--type", "slsaprovenance1",
        "--certificate-identity", policy["certificate_identity"],
        "--certificate-oidc-issuer", ISSUER,
        "--output", "json", image,
    ]
    # Do not allow insecure-ignore-tlog, insecure-ignore-sct, --key, --check-claims=false.
    try:
        completed = runner(command, capture_output=True, timeout=90, check=False,
                           env={"PATH": "/usr/local/bin:/usr/bin:/bin",
                                "HOME": "/root", "LANG": "C.UTF-8"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProvenanceError("Cosign unavailable or timed out") from exc
    if completed.returncode != 0:
        raise ProvenanceError("Cosign cryptographic provenance verification failed")
    return parse_verified_cosign(completed.stdout, policy)
