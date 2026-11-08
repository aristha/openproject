#!/usr/bin/env python3
"""Generate narrowly scoped SLSA v1 predicate for this reviewed GitHub image build.

This JSON is a *claim*, not proof. The GitHub Actions identity and OCI digest
must also be verified cryptographically by Cosign before promotion.
"""
import argparse
import json
import re
from pathlib import Path

SOURCE_SHA = re.compile(r"[a-f0-9]{40}\Z")
IMAGE_DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
WORKFLOW = "https://github.com/aristha/openproject/.github/workflows/fork-build-attested-image.yml"
SOURCE = "git+https://github.com/aristha/openproject"
BUILDTYPE = "https://github.com/aristha/openproject/attested-ghcr-build/v1"


def predicate(source_sha, image_digest, run_id, run_attempt):
    if not isinstance(source_sha, str) or not SOURCE_SHA.fullmatch(source_sha):
        raise ValueError("Build source must be a full 40-hex commit")
    if not isinstance(image_digest, str) or not IMAGE_DIGEST.fullmatch(image_digest):
        raise ValueError("Image digest must be immutable sha256:<64hex>")
    if any(type(item) is not int or item <= 0 for item in (run_id, run_attempt)):
        raise ValueError("Invalid GitHub workflow run identity")
    return {
        "buildDefinition": {
            "buildType": BUILDTYPE,
            "externalParameters": {
                "source": SOURCE + "@" + source_sha,
                "dockerfile": "docker/prod/Dockerfile",
                "target": "ghcr.io/aristha/openproject@" + image_digest,
            },
            "internalParameters": {},
            "resolvedDependencies": [{
                "uri": SOURCE,
                "digest": {"gitCommit": source_sha},
            }],
        },
        "runDetails": {
            "builder": {"id": WORKFLOW + "@refs/heads/dev"},
            "metadata": {"invocationId": f"https://github.com/aristha/openproject/actions/runs/{run_id}/attempts/{run_attempt}"},
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--run-attempt", type=int, required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    data = predicate(args.source_sha, args.image_digest, args.run_id, args.run_attempt)
    destination = Path(args.output)
    destination.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
