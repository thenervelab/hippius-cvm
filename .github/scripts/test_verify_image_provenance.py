#!/usr/bin/env python3
"""Tests for `verify_image_provenance.py` — the P3 image-provenance binding.

One test per CLAIM the gate makes. The claims are:

  C1  a trust-critical chart with no `image.provenance` block is REFUSED;
  C2  a digest that is a TAG, or malformed, is REFUSED;
  C3  the declared workflow identity must be a `*-image.yml` workflow in
      THIS repo (a signature from anywhere else cannot be declared);
  C4  `mergedSource` is a restatement of the ref, not a free-text claim —
      claiming `true` for a PR build (or `false` for a main build) is REFUSED;
  C5  a build from an unmerged ref REQUIRES a substantive acknowledgement;
  C6  a stale acknowledgement on a merged build is REFUSED;
  C7  the cosign argv actually carries the DECLARED identity AND the DECLARED
      commit sha as EXACT constraints — this is the binding itself: remove
      either flag and a different build of the same repo verifies clean;
  C8  the real, committed charts satisfy the policy.

Run: `python3 -m unittest discover -s .github/scripts -p 'test_*.py'`
(also wired into the required `rust` CI job via
`scripts/dev/image-provenance-test.sh`).
"""

from __future__ import annotations

import copy
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from verify_image_provenance import (  # noqa: E402
    MAIN_REF,
    OIDC_ISSUER,
    TRUST_CRITICAL_IMAGES,
    ProvenanceError,
    check_declaration,
    cosign_args,
    load_declarations,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

WF = "https://github.com/thenervelab/hippius-compute/.github/workflows"
SHA = "6173f3879b253084594cdc49474850980ca2050a"
DIGEST = "sha256:" + "ab" * 32

MERGED = {
    "repository": "ghcr.io/thenervelab/hippius-kbs-server",
    "digest": DIGEST,
    "provenance": {
        "workflowRef": f"{WF}/kbs-image.yml@{MAIN_REF}",
        "commitSha": SHA,
        "runUrl": "https://github.com/thenervelab/hippius-compute/actions/runs/1234",
        "mergedSource": True,
    },
}

UNMERGED = {
    "repository": "ghcr.io/thenervelab/hippius-kbs-server",
    "digest": DIGEST,
    "provenance": {
        "workflowRef": f"{WF}/kbs-image.yml@refs/pull/897/merge",
        "commitSha": SHA,
        "runUrl": "https://github.com/thenervelab/hippius-compute/actions/runs/1234/attempts/1",
        "mergedSource": False,
        "unmergedSourceAck": (
            "PR #897 was merged as 558c7a5c; the built tree is the ephemeral "
            "refs/pull/897/merge commit and is not recoverable from this repo."
        ),
    },
}


def mutate(base: dict, **prov) -> dict:
    """Copy `base`, overriding provenance keys (a `None` value deletes)."""
    out = copy.deepcopy(base)
    for k, v in prov.items():
        if v is None:
            out["provenance"].pop(k, None)
        else:
            out["provenance"][k] = v
    return out


class HappyPath(unittest.TestCase):
    def test_merged_declaration_accepted(self):
        d = check_declaration("x", MERGED)
        self.assertTrue(d["merged_source"])
        self.assertEqual(d["commit_sha"], SHA)
        self.assertEqual(d["ref"], f"ghcr.io/thenervelab/hippius-kbs-server@{DIGEST}")

    def test_unmerged_declaration_with_ack_accepted(self):
        d = check_declaration("x", UNMERGED)
        self.assertFalse(d["merged_source"])


class C1_ProvenanceRequired(unittest.TestCase):
    def test_missing_provenance_block_refused(self):
        img = {"repository": MERGED["repository"], "digest": DIGEST}
        with self.assertRaisesRegex(ProvenanceError, "image.provenance is REQUIRED"):
            check_declaration("x", img)

    def test_no_image_mapping_refused(self):
        with self.assertRaisesRegex(ProvenanceError, "no `image:` mapping"):
            check_declaration("x", None)


class C2_DigestPinning(unittest.TestCase):
    def test_tag_instead_of_digest_refused(self):
        img = copy.deepcopy(MERGED)
        img["digest"] = "latest"
        with self.assertRaisesRegex(ProvenanceError, "image.digest must be"):
            check_declaration("x", img)

    def test_short_digest_refused(self):
        img = copy.deepcopy(MERGED)
        img["digest"] = "sha256:abcd"
        with self.assertRaises(ProvenanceError):
            check_declaration("x", img)

    def test_third_party_repository_refused(self):
        img = copy.deepcopy(MERGED)
        img["repository"] = "docker.io/library/alpine"
        with self.assertRaisesRegex(ProvenanceError, "first-party"):
            check_declaration("x", img)


class C3_IdentityShape(unittest.TestCase):
    def test_foreign_repo_identity_refused(self):
        img = mutate(MERGED, workflowRef=f"https://github.com/evil/repo/.github/workflows/kbs-image.yml@{MAIN_REF}")
        with self.assertRaisesRegex(ProvenanceError, "workflowRef must be"):
            check_declaration("x", img)

    def test_non_image_workflow_refused(self):
        img = mutate(MERGED, workflowRef=f"{WF}/ci.yml@{MAIN_REF}")
        with self.assertRaises(ProvenanceError):
            check_declaration("x", img)

    def test_bad_commit_sha_refused(self):
        for bad in ("6173F387" + "0" * 32, "deadbeef", 12345, None):
            with self.subTest(bad=bad):
                with self.assertRaises(ProvenanceError):
                    check_declaration("x", mutate(MERGED, commitSha=bad))

    def test_bad_run_url_refused(self):
        img = mutate(MERGED, runUrl="https://example.com/build/7")
        with self.assertRaisesRegex(ProvenanceError, "runUrl"):
            check_declaration("x", img)


class C4_MergedSourceIsARestatementOfTheRef(unittest.TestCase):
    def test_claiming_merged_for_a_pr_build_refused(self):
        img = mutate(UNMERGED, mergedSource=True, unmergedSourceAck=None)
        with self.assertRaisesRegex(ProvenanceError, "contradicts"):
            check_declaration("x", img)

    def test_claiming_unmerged_for_a_main_build_refused(self):
        img = mutate(MERGED, mergedSource=False, unmergedSourceAck="x" * 80)
        with self.assertRaisesRegex(ProvenanceError, "contradicts"):
            check_declaration("x", img)

    def test_non_boolean_merged_source_refused(self):
        for bad in ("true", 1, None):
            with self.subTest(bad=bad):
                with self.assertRaises(ProvenanceError):
                    check_declaration("x", mutate(MERGED, mergedSource=bad))


class C5_UnmergedNeedsSubstantiveAck(unittest.TestCase):
    def test_unmerged_without_ack_refused(self):
        img = mutate(UNMERGED, unmergedSourceAck=None)
        with self.assertRaisesRegex(ProvenanceError, "unmergedSourceAck"):
            check_declaration("x", img)

    def test_rubber_stamp_ack_refused(self):
        for bad in ("ok", "n/a", "   " + "y" * 10):
            with self.subTest(bad=bad):
                with self.assertRaises(ProvenanceError):
                    check_declaration("x", mutate(UNMERGED, unmergedSourceAck=bad))


class C6_NoStaleAckOnMergedBuilds(unittest.TestCase):
    def test_ack_on_merged_build_refused(self):
        img = mutate(MERGED, unmergedSourceAck="left over from the previous pin, " * 3)
        with self.assertRaisesRegex(ProvenanceError, "must be absent"):
            check_declaration("x", img)


class C7_CosignArgvIsTheBinding(unittest.TestCase):
    """THE binding test. If the declaration→signature constraints are removed
    from the argv, the gate degrades to the pre-existing ref-agnostic check
    and these fail."""

    def test_argv_pins_the_declared_identity_exactly(self):
        argv = cosign_args(check_declaration("x", UNMERGED))
        self.assertIn("--certificate-identity", argv)
        self.assertNotIn(
            "--certificate-identity-regexp",
            argv,
            "a regexp identity accepts a build from ANY ref — that is exactly "
            "the gap this check exists to close",
        )
        self.assertEqual(
            argv[argv.index("--certificate-identity") + 1],
            UNMERGED["provenance"]["workflowRef"],
        )

    def test_argv_pins_the_declared_commit_sha(self):
        argv = cosign_args(check_declaration("x", UNMERGED))
        self.assertIn(
            "--certificate-github-workflow-sha",
            argv,
            "without the sha constraint any build of any commit on the same ref "
            "satisfies the identity, and the declared commit is decorative",
        )
        self.assertEqual(
            argv[argv.index("--certificate-github-workflow-sha") + 1], SHA
        )

    def test_argv_pins_issuer_repo_and_the_image_digest(self):
        argv = cosign_args(check_declaration("x", MERGED))
        self.assertEqual(argv[argv.index("--certificate-oidc-issuer") + 1], OIDC_ISSUER)
        self.assertEqual(
            argv[argv.index("--certificate-github-workflow-repository") + 1],
            "thenervelab/hippius-compute",
        )
        self.assertEqual(argv[0], "verify")
        self.assertEqual(argv[-1], f"ghcr.io/thenervelab/hippius-kbs-server@{DIGEST}")


class C9_GateCannotGoBlind(unittest.TestCase):
    """A trust-critical image block that moved must FAIL the gate, not
    silently drop out of its coverage."""

    def test_missing_values_file_refused(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ProvenanceError, "not found"):
                load_declarations(pathlib.Path(tmp))

    def test_renamed_key_refused_and_names_the_chart(self):
        """The sub-images (`tenantBake.image`, `epochClose.image`) live INSIDE
        another chart's values, so a rename does not remove a file — the old
        per-file lookup would just have found nothing. It must fail loudly,
        and the message must say WHICH block."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            for rel, _ in TRUST_CRITICAL_IMAGES:
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("someOtherKey: {}\n")
            with self.assertRaises(ProvenanceError) as cm:
                load_declarations(root)
            msg = str(cm.exception)
            self.assertIn("key not found", msg)
            self.assertIn(TRUST_CRITICAL_IMAGES[0][0], msg)


class C10_CoverageIsEveryFirstPartyGitopsImage(unittest.TestCase):
    """The list must cover every first-party image the gitops charts pin.

    This is the CLAIM of this extension. Before it, four of six were guarded
    only by `verify-gitops-signatures.yml`'s ref-AGNOSTIC check — the one
    whose documented blind spot (it pins neither branch nor commit) is
    exactly how the KBS came to run a `refs/pull/897/merge` build. A new
    chart that adds an image and forgets this list re-opens that gap
    silently, so the drift is asserted rather than trusted.
    """

    def test_no_first_party_gitops_digest_is_uncovered(self):
        sys.path.insert(0, str(REPO_ROOT / ".github" / "scripts"))
        from gitops_image_refs import main as refs_main  # noqa: E402

        import contextlib
        import io

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            refs_main([str(REPO_ROOT / "deploy" / "gitops")])
        in_charts = {line for line in buf.getvalue().split() if line}

        declared = {d["ref"] for d in load_declarations(REPO_ROOT)}
        uncovered = in_charts - declared
        self.assertEqual(
            uncovered,
            set(),
            "first-party image digest(s) in deploy/gitops with NO provenance "
            "declaration — add them to TRUST_CRITICAL_IMAGES: "
            + ", ".join(sorted(uncovered)),
        )


class C8_RealCharts(unittest.TestCase):
    def test_committed_trust_critical_charts_declare_provenance(self):
        declarations = load_declarations(REPO_ROOT)
        self.assertEqual(len(declarations), len(TRUST_CRITICAL_IMAGES))
        by_source = {d["source"]: d for d in declarations}
        for rel, key in TRUST_CRITICAL_IMAGES:
            self.assertIn(f"{rel} [{key}]", by_source)
        for d in declarations:
            self.assertTrue(d["ref"].startswith("ghcr.io/thenervelab/hippius-"))
            # Every declaration must produce a runnable, fully-constrained argv.
            argv = cosign_args(d)
            self.assertIn("--certificate-identity", argv)
            self.assertIn("--certificate-github-workflow-sha", argv)

    def test_the_four_previously_uncovered_images_are_now_declared(self):
        """Named explicitly so deleting one from `TRUST_CRITICAL_IMAGES`
        fails by name rather than by an arithmetic count."""
        declared = {d["source"] for d in load_declarations(REPO_ROOT)}
        for source in (
            "deploy/gitops/apps/edge-gateway/values.yaml [image]",
            "deploy/gitops/apps/vali/values.yaml [image]",
            "deploy/gitops/apps/vali/values.yaml [tenantBake.image]",
            "deploy/gitops/apps/vali/values.yaml [epochClose.image]",
        ):
            self.assertIn(source, declared)


if __name__ == "__main__":
    unittest.main(verbosity=2)
