#!/usr/bin/env python3
"""Post-Cosign-verify check: bind signed statement to exact pushed GHCR digest.

The input MUST come from a successful 'cosign verify-attestation', never
directly from the registry or from unauthenticated workflow JSON.
"""
import argparse
import json
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


def verified_output_schema(data):
    """Non-sensitive field names only. Never print payload, signature or identities."""
    try:
        obj = json.loads(data)
    except (ValueError, UnicodeDecodeError, TypeError):
        return "invalid-json"
    items = obj if isinstance(obj, list) else [obj]
    if not items:
        return "empty-array"
    first = items[0]
    if not isinstance(first, dict):
        return "unsupported-entry"
    safe_keys = {"payload", "payloadType", "statement", "predicateType",
                 "_type", "critical", "optional", "verificationResult",
                 "bundle", "signedEnvelope", "attestation"}
    return "keys:" + ",".join(sorted(k for k in first if k in safe_keys))


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
        # This is only a schema fingerprint. Never dump untrusted payloads,
        # certificates, signatures or secrets to the public GitHub log.
        shape = verified_output_schema(locals().get("result", b""))
        raise SystemExit("SIGNED_IMAGE_PROVENANCE_REJECTED: " +
                         type(exc).__name__ + " " + shape) from exc
    print("SIGNED_IMAGE_PROVENANCE_VERIFIED")


if __name__ == "__main__":
    main()
