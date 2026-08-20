#!/usr/bin/env python3
"""Bind each TRUST-CRITICAL gitops image digest to a DECLARED build provenance,
and verify that declaration against the image's Sigstore signature.

Why this exists (P3 — "the KBS CVM measurement binds the VM shape, not the
code inside it"):

  The KBS runs as a `kata-qemu-snp` confidential pod. Its SEV-SNP launch
  measurement covers the CVM shape only — OVMF, guest kernel, initrd,
  cmdline. The container image is **guest-pulled at runtime** from a
  reference the (untrusted) host hands to the guest, so it is NOT in the
  measurement. Two different KBS binaries in the same CVM shape produce the
  SAME measurement, and the broker's `kbsMeasurementAllowlist` — the only
  runtime gate on the KBS's own identity — cannot tell them apart.

  Nothing here changes that. What this DOES close is the weaker, adjacent
  gap that the ref-agnostic `verify-gitops-signatures` gate leaves open: it
  proves a pinned digest was signed by *some* build of this repo, on *any*
  ref, and says nothing about WHICH source produced the binary. The digest's
  human-readable provenance lived only in a YAML comment — and that comment
  was wrong by three weeks and one branch when this check was written.

  So: every image block in `TRUST_CRITICAL_IMAGES` must DECLARE the
  provenance of the digest it pins (workflow ref, commit sha, run URL, and
  whether that source is merged), and `cosign verify` is run with those
  declared values as EXACT constraints (`--certificate-identity`,
  `--certificate-github-workflow-sha`). A declaration that does not match
  the signature fails. A digest bumped without updating the declaration
  fails. A build from an unmerged ref must say so out loud, in the diff,
  with a reason.

  That list is now EVERY first-party image the gitops charts deploy, not
  just the two at the confidentiality boundary — see `TRUST_CRITICAL_IMAGES`
  for why the distinction was not worth keeping.

  This is a REVIEW-surface control, not a runtime one. It says which build
  the chart CLAIMS, checkably; it does not say which build the cluster
  pulled. See `deploy/gitops/apps/kbs/README.md` § "What the KBS measurement
  does not cover" for what an attacker can still do.

Usage:
    verify_image_provenance.py                     # offline policy checks
    verify_image_provenance.py --cosign /usr/bin/cosign   # + Sigstore binding
    verify_image_provenance.py --print-cosign-args        # show the argv
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys
from typing import Any

import yaml

# EVERY first-party image this repo's gitops deploys, as
# `(values.yaml, dotted key of the image block)`.
#
# It started as two — the KBS, which releases every tenant disk KEK, and the
# broker, which mints the Vault capability that lets it. The other four were
# covered only by the deliberately ref-AGNOSTIC gate in
# `verify-gitops-signatures.yml`, whose own comment calls it too weak for
# trust-critical images: it pins neither the branch nor the commit, so the
# exact failure this file was written for — the KBS running a
# `refs/pull/897/merge` build that is not reachable from any commit in this
# repository — passes it clean.
#
# Nothing about "trust-critical" is confined to the confidentiality boundary.
# vali holds the Vault credential and drives every launch, §24 erase and §25
# migration; the Edge is the only path between miners and vali and stamps the
# peer identity vali authorises on; the tenant-baker produces the rootfs
# whose measurement the §22 allowlist pins; the epoch-closer signs the
# on-chain extrinsic that sets every miner's reward. There is no member of
# this list whose substitution is survivable, so the list is simply "all of
# them" — which also removes the judgement call about where the boundary is.
TRUST_CRITICAL_IMAGES = (
    ("deploy/gitops/apps/kbs/values.yaml", "image"),
    ("deploy/gitops/apps/kbs-vault-broker/values.yaml", "image"),
    ("deploy/gitops/apps/edge-gateway/values.yaml", "image"),
    ("deploy/gitops/apps/vali/values.yaml", "image"),
    # The vali chart carries three: its own, plus the baker image it hands to
    # the bake Job through the ConfigMap and the epoch-closer the CronJob
    # runs. Neither sub-image is a separate chart, so a per-file list would
    # have silently covered one of the three.
    ("deploy/gitops/apps/vali/values.yaml", "tenantBake.image"),
    ("deploy/gitops/apps/vali/values.yaml", "epochClose.image"),
)

# BOTH names are accepted because this repo was renamed `hippius-compute` →
# `hippius-compute-internal`. A Fulcio certificate records the repo name AT
# BUILD TIME and is immutable, so the pinned images split into two eras:
# everything built before the rename is signed under the old name, everything
# after under the new one. Accepting only one era rejects the other.
#
# ⚠️ Safe ONLY while both names stay ours. The old name is a GitHub redirect
# today, and a redirected name becomes claimable once nothing occupies it — so
# a repo we do NOT control taking `thenervelab/hippius-compute` could mint
# certificates satisfying this check. Never give that name to a public or
# externally-contributed repo (the open-source repo is `hippius-cvm`
# precisely so this stays true).
#
# Cleanup, once every pinned image has been rebuilt post-rename: collapse
# REPOS to the `-internal` name alone.
REPOS = ("thenervelab/hippius-compute", "thenervelab/hippius-compute-internal")
REPO = REPOS[-1]  # the CURRENT name — used in operator-facing message text
_REPO_ALT = "(?:" + "|".join(re.escape(r) for r in REPOS) + ")"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
MAIN_REF = "refs/heads/main"

# The Fulcio SAN a `*-image.yml` workflow in THIS repo signs under. The `ref`
# group is the git ref the build ran on — `refs/heads/main` for a merged
# build, `refs/pull/<n>/merge` for a pre-merge PR build. The `repo` group is
# captured rather than assumed: cosign pins the signing repository by EXACT
# match (not a pattern), so the value it is given must come from the identity
# this regex just validated, never from a constant that names only one era.
WORKFLOW_REF_RE = re.compile(
    r"^https://github\.com/(?P<repo>" + _REPO_ALT + r")"
    + r"/\.github/workflows/[a-z0-9-]+-image\.yml@(?P<ref>refs/\S+)$"
)
RUN_URL_RE = re.compile(
    r"^https://github\.com/" + _REPO_ALT + r"/actions/runs/\d+(/attempts/\d+)?$"
)
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_PREFIX = "ghcr.io/thenervelab/hippius-"

# An acknowledgement has to carry an actual explanation — a "yes" or a "n/a"
# is a rubber stamp, and this repo has shipped enough of those.
MIN_ACK_LEN = 60


class ProvenanceError(Exception):
    """A trust-critical image's provenance declaration is missing or invalid."""


def check_declaration(source: str, image: Any) -> dict[str, Any]:
    """Validate one chart's `image:` block and return its provenance.

    Pure: no filesystem, no network. `source` is only used in messages.
    """
    if not isinstance(image, dict):
        raise ProvenanceError(f"{source}: no `image:` mapping")

    repository = image.get("repository")
    if not isinstance(repository, str) or not repository.startswith(REPOSITORY_PREFIX):
        raise ProvenanceError(
            f"{source}: image.repository must be a first-party "
            f"{REPOSITORY_PREFIX}* reference, got {repository!r}"
        )
    digest = image.get("digest")
    if not isinstance(digest, str) or not DIGEST_RE.match(digest):
        raise ProvenanceError(
            f"{source}: image.digest must be `sha256:<64 lower-case hex>` "
            f"(a TAG is never acceptable here), got {digest!r}"
        )

    prov = image.get("provenance")
    if not isinstance(prov, dict):
        raise ProvenanceError(
            f"{source}: image.provenance is REQUIRED for a trust-critical chart — "
            "declare the workflow ref, commit sha and run URL that produced "
            f"{repository}@{digest}"
        )

    workflow_ref = prov.get("workflowRef")
    if not isinstance(workflow_ref, str):
        raise ProvenanceError(f"{source}: image.provenance.workflowRef must be a string")
    m = WORKFLOW_REF_RE.match(workflow_ref)
    if not m:
        raise ProvenanceError(
            f"{source}: image.provenance.workflowRef must be a "
            f"`{REPO}/.github/workflows/<name>-image.yml@<ref>` identity, "
            f"got {workflow_ref!r}"
        )
    ref = m.group("ref")
    repo = m.group("repo")

    commit_sha = prov.get("commitSha")
    if not isinstance(commit_sha, str) or not COMMIT_RE.match(commit_sha):
        raise ProvenanceError(
            f"{source}: image.provenance.commitSha must be a 40-char lower-case "
            f"git sha, got {commit_sha!r}"
        )

    run_url = prov.get("runUrl")
    if not isinstance(run_url, str) or not RUN_URL_RE.match(run_url):
        raise ProvenanceError(
            f"{source}: image.provenance.runUrl must be a {REPO} Actions run URL, "
            f"got {run_url!r}"
        )

    merged = prov.get("mergedSource")
    if not isinstance(merged, bool):
        raise ProvenanceError(
            f"{source}: image.provenance.mergedSource must be an explicit "
            f"true/false, got {merged!r}"
        )
    # The load-bearing consistency rule: `mergedSource` is not a free-text
    # claim, it is a restatement of the ref. A build on any ref other than
    # main was made from a tree that is NOT in this repo's history (a
    # `refs/pull/<n>/merge` commit is ephemeral and unrecoverable), so the
    # running binary cannot be re-derived from source.
    if merged != (ref == MAIN_REF):
        raise ProvenanceError(
            f"{source}: image.provenance.mergedSource={merged} contradicts "
            f"workflowRef ref {ref!r} — mergedSource is true if and only if the "
            f"build ran on {MAIN_REF}"
        )

    ack = prov.get("unmergedSourceAck")
    if not merged:
        if not isinstance(ack, str) or len(ack.strip()) < MIN_ACK_LEN:
            raise ProvenanceError(
                f"{source}: this chart pins an image built from {ref!r}, i.e. from "
                "source that is NOT in this repo's history. That is permitted only "
                "with an explicit image.provenance.unmergedSourceAck explaining "
                f"which PR it came from and when it will be re-pinned (>= "
                f"{MIN_ACK_LEN} chars), got {ack!r}"
            )
    elif ack is not None:
        raise ProvenanceError(
            f"{source}: image.provenance.unmergedSourceAck must be absent when "
            "mergedSource is true — a stale acknowledgement reads as an open "
            "exception that is no longer real"
        )

    return {
        "source": source,
        "ref": f"{repository}@{digest}",
        "workflow_ref": workflow_ref,
        # The repo cosign pins by exact match — taken from the validated
        # identity above, so a pre-rename and a post-rename image each get
        # the name their own certificate actually carries.
        "repo": repo,
        "commit_sha": commit_sha,
        "run_url": run_url,
        "merged_source": merged,
    }


def cosign_args(declaration: dict[str, Any]) -> list[str]:
    """The `cosign verify` argv that binds a DECLARED provenance to the
    image's actual Sigstore signature.

    Every constraint here is exact, and every one is load-bearing:
      * `--certificate-identity` (not `-regexp`) pins the signing workflow
        AND the git ref it ran on;
      * `--certificate-github-workflow-sha` pins the exact source commit —
        without it, any build of any commit on that same ref satisfies the
        identity;
      * `--certificate-github-workflow-repository` pins the repo;
      * `--certificate-oidc-issuer` pins GitHub Actions as the issuer.
    Verified against the live signatures: dropping either of the first two
    lets a different build pass.
    """
    return [
        "verify",
        "--certificate-identity",
        declaration["workflow_ref"],
        "--certificate-oidc-issuer",
        OIDC_ISSUER,
        "--certificate-github-workflow-sha",
        declaration["commit_sha"],
        "--certificate-github-workflow-repository",
        declaration["repo"],
        declaration["ref"],
    ]


_MISSING = object()


def resolve(doc: Any, key_path: str) -> Any:
    """Walk a dotted key path (`tenantBake.image`) through a values doc.

    Returns `_MISSING` — distinct from a key present-but-null — when any
    segment is absent, so a renamed key fails LOUDLY instead of degrading
    into "no `image:` mapping".
    """
    node = doc
    for part in key_path.split("."):
        if not isinstance(node, dict) or part not in node:
            return _MISSING
        node = node[part]
    return node


def load_declarations(root: pathlib.Path) -> list[dict[str, Any]]:
    """Validate every trust-critical image block under `root`. Raises on the
    first failure; a missing values.yaml — or a missing key inside one — is
    itself a failure (the chart moved and this gate silently stopped covering
    it, which is the one outcome a gate must never have)."""
    out = []
    for rel, key in TRUST_CRITICAL_IMAGES:
        source = f"{rel} [{key}]"
        path = root / rel
        if not path.is_file():
            raise ProvenanceError(
                f"{source}: trust-critical values file not found — did the chart "
                "move? Update TRUST_CRITICAL_IMAGES rather than letting the gate "
                "go blind."
            )
        doc = yaml.safe_load(path.read_text())
        image = resolve(doc, key)
        if image is _MISSING:
            raise ProvenanceError(
                f"{source}: key not found in the chart — it was renamed or the "
                "sub-chart moved. Update TRUST_CRITICAL_IMAGES rather than "
                "letting the gate go blind."
            )
        out.append(check_declaration(source, image))
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=".", help="repository root")
    ap.add_argument("--cosign", help="path to cosign; run the Sigstore binding too")
    ap.add_argument(
        "--print-cosign-args",
        action="store_true",
        help="print the cosign argv for each image instead of running it",
    )
    args = ap.parse_args(argv)

    try:
        declarations = load_declarations(pathlib.Path(args.root))
    except ProvenanceError as e:
        print(f"::error::image provenance: {e}", file=sys.stderr)
        return 1

    for d in declarations:
        state = "merged (refs/heads/main)" if d["merged_source"] else "UNMERGED SOURCE"
        print(f"{d['source']}\n  image      {d['ref']}\n  identity   {d['workflow_ref']}")
        print(f"  commit     {d['commit_sha']}\n  run        {d['run_url']}\n  source     {state}")
        if args.print_cosign_args:
            print("  cosign     " + " ".join(cosign_args(d)))

    if not args.cosign:
        return 0

    failed = 0
    for d in declarations:
        argv_ = [args.cosign, *cosign_args(d)]
        print(f"::group::cosign verify {d['ref']}")
        proc = subprocess.run(argv_, capture_output=True, text=True, check=False)
        print(proc.stdout)
        if proc.returncode != 0:
            print(proc.stderr, file=sys.stderr)
            print(
                f"::error::{d['source']}: the DECLARED provenance does not match the "
                f"Sigstore signature on {d['ref']} — the pinned digest was not built "
                f"by {d['workflow_ref']} from commit {d['commit_sha']}",
                file=sys.stderr,
            )
            failed += 1
        else:
            print(f"OK  {d['ref']} matches its declared provenance")
        print("::endgroup::")

    if failed:
        print(f"::error::{failed} trust-critical image(s) failed provenance binding", file=sys.stderr)
        return 1
    print(f"All {len(declarations)} trust-critical image provenance declarations verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
