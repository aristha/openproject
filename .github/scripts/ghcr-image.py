"""Inspect GHCR without logging registry credentials or replacing existing tags."""

import base64
import json
import os
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])


def main():
    mode = sys.argv[1]
    repository = os.environ["GHCR_REPOSITORY"]
    tag = os.environ["GHCR_TAG"]
    if repository != "aristha/openproject" or not re.fullmatch(r"sha-[0-9a-f]{40}", tag):
        raise ValueError("Unexpected repository or commit tag")
    credentials = f'{os.environ["GITHUB_ACTOR"]}:{os.environ["GHCR_TOKEN"]}'
    query = urlencode({"service": "ghcr.io", "scope": f"repository:{repository}:pull,push"})
    request = Request("https://ghcr.io/token?" + query, headers={
        "Authorization": "Basic " + base64.b64encode(credentials.encode()).decode(),
    })
    with urlopen(request, timeout=30) as response:
        token = json.load(response)["token"]

    def manifest(reference):
        request = Request(f"https://ghcr.io/v2/{repository}/manifests/{reference}", headers={
            "Authorization": "Bearer " + token,
            "Accept": ACCEPT,
        })
        with urlopen(request, timeout=30) as response:
            return json.load(response), response.headers["Docker-Content-Digest"]

    if mode == "check":
        try:
            _, digest = manifest(tag)
        except HTTPError as error:
            if error.code != 404:
                raise
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
                output.write("exists=false\n")
            return
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest or ""):
            raise ValueError("Registry returned no valid existing digest")
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            output.write(f"exists=true\ndigest={digest}\n")
        print("Existing SHA tag will be reused without building or pushing.")
    elif mode == "report":
        digest = os.environ["GHCR_DIGEST"]
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("Build returned no valid digest")
        image, actual_digest = manifest(tag)
        if actual_digest != digest:
            raise ValueError("Published tag does not match the expected digest")
        if "manifests" in image:
            images = [item for item in image["manifests"]
                      if item.get("platform", {}).get("os") == "linux"
                      and item.get("platform", {}).get("architecture") == "amd64"]
            if len(images) != 1:
                raise ValueError("Expected exactly one linux/amd64 image")
            image, _ = manifest(images[0]["digest"])
        size = sum(layer["size"] for layer in image["layers"])
        reference = f"ghcr.io/{repository}"
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
            summary.write(f"### Published image\n- Tag: `{reference}:{tag}`\n")
            summary.write(f"- Digest reference: `{reference}@{digest}`\n")
            summary.write(f"- Compressed linux/amd64 layer size: {size:,} bytes ({size / 1024**2:.1f} MiB)\n")
            summary.write("- This is registry layer size, not unpacked disk usage.\n")
        print(f"Verified {reference}@{digest}; compressed layers: {size} bytes")
    else:
        raise ValueError("Expected check or report")


if __name__ == "__main__":
    try:
        main()
    except HTTPError as error:
        sys.exit(f"GHCR HTTP {error.code}; refusing to publish or report unverified metadata. Check package access and the failing step.")
    except (KeyError, ValueError, URLError) as error:
        sys.exit(f"GHCR inspection failed ({type(error).__name__}); no credentials were logged.")
