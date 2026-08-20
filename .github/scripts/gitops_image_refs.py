#!/usr/bin/env python3
"""Extract every first-party (`ghcr.io/thenervelab/hippius-*`) container
image reference from the gitops Helm values, normalised to
`repository@sha256:<digest>` (one per line, deduped).

Two conventions appear in the charts and both are handled:

  * split fields — a mapping with `repository: ghcr.io/thenervelab/hippius-…`
    and a sibling `digest: sha256:…` (kbs / broker / vali / edge / the
    tenant-baker sub-image);
  * a combined string — `image: "ghcr.io/thenervelab/hippius-…:tag@sha256:…"`
    (the epoch-closer CronJob).

Third-party images (alpine/socat, aws-cli, node, …) are intentionally
excluded — they are not signed by this repo's CI, so the verify gate that
consumes this list only asserts our own supply-chain provenance.
"""

from __future__ import annotations

import pathlib
import re
import sys

import yaml

PREFIX = "ghcr.io/thenervelab/hippius-"
# `repo(:tag)?@sha256:<64-hex>` — the tag is optional and dropped (the
# digest is authoritative for `cosign verify`).
COMBINED = re.compile(
    r"(ghcr\.io/thenervelab/hippius-[a-z0-9-]+)(?::[A-Za-z0-9._-]+)?@(sha256:[0-9a-f]{64})"
)
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _walk(node: object, out: set[str]) -> None:
    if isinstance(node, dict):
        repo = node.get("repository")
        digest = node.get("digest")
        if (
            isinstance(repo, str)
            and repo.startswith(PREFIX)
            and isinstance(digest, str)
            and DIGEST.match(digest)
        ):
            out.add(f"{repo}@{digest}")
        for value in node.values():
            _walk(value, out)
    elif isinstance(node, list):
        for item in node:
            _walk(item, out)
    elif isinstance(node, str):
        for repo, digest in COMBINED.findall(node):
            out.add(f"{repo}@{digest}")


def main(roots: list[str]) -> int:
    refs: set[str] = set()
    for root in roots:
        for path in sorted(pathlib.Path(root).rglob("*.yaml")):
            text = path.read_text()
            # Combined `repo:tag@sha256:…` strings are found by regex on the
            # raw text — this works even for Helm TEMPLATE files (whose
            # `{{ … }}` directives are not valid YAML).
            for repo, digest in COMBINED.findall(text):
                refs.add(f"{repo}@{digest}")
            # Split `repository:`/`digest:` fields need a real parse. Only
            # values.yaml carries them; templates reference `.Values.…` and
            # do not parse as YAML, so skip a parse failure rather than fail
            # the gate on un-rendered Helm.
            try:
                docs = list(yaml.safe_load_all(text))
            except yaml.YAMLError:
                continue
            for doc in docs:
                _walk(doc, refs)
    for ref in sorted(refs):
        print(ref)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:] or ["deploy/gitops"]))
