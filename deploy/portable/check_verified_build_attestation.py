#!/usr/bin/env python3
"""Post-Cosign-verify check: bind signed statement to exact pushed GHCR digest.

The input MUST come from a successful 'cosign verify-attestation', never
directly from the registry or from unauthenticated workflow JSON.
"""
import argparse
from pathlib import Path
import re

from image_provenance import IMAGE, parse_verified_cosign, ProvenanceError
from write_slsa_build_predicate import SOURCE_SHA, WORKFLOW


def check(verified_json, source_sha, image_digest):
    if not SOURCE_SHA.fullmatch(source_sha) or not re.fullmatch(r"sha256:[a-f0-9]{64}", image_digest):
        raise ValueError("Invalid immutable image/build revision")
    if len(verified_json) > 1024 * 1024:
        raise ValueError("Oversized attestation result")
    policy = {
        "image": "ghcr.io/aristha/openproject@" + image_digest,
        "build_sha": source_sha,
        "certificate_identity": WORKFLOW + "@refs/heads/dev",
        "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
    }
    return parse_verified_cosign(verified_json, policy)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--verified-json", required=True)
    p.add_argument("--source-sha", required=True)
    p.add_argument("--image-digest", required=True)
    args = p.parse_args()
    try:
        result = Path(args.verified_json).read_bytes()
        check(result, args.source_sha, args.image_digest)
    except (OSError, ValueError, ProvenanceError) as exc:
        # Safe failure diagnosis: report shape only, never original untrusted
        # statement content, certificate, credential or JSON payload.
        raise SystemExit("SIGNED_IMAGE_PROVENANCE_REJECTED: " +
                         type(exc).__name__) from exc
    print("SIGNED_IMAGE_PROVENANCE_VERIFIED")


if __name__ == "__main__":
    main()
