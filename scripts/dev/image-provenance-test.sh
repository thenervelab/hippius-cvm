#!/usr/bin/env bash
# P3 — trust-critical image provenance: the OFFLINE half of the gate.
#
# The KBS's SEV-SNP launch measurement binds the CVM shape, not the
# container image running inside it (the image is guest-pulled at runtime
# from a reference the host supplies). Nothing at runtime can tell two
# different KBS binaries apart. So the deployment-side claim about WHICH
# build is in that CVM has to be worth something: each trust-critical chart
# declares its digest's build provenance, and `.github/workflows/
# verify-gitops-signatures.yml` binds that declaration to the digest's
# Sigstore signature with `cosign verify --certificate-identity` +
# `--certificate-github-workflow-sha`.
#
# That online binding needs network + cosign, so it lives in its own
# workflow. THIS script is the part that runs in the REQUIRED `rust` job:
# the hermetic policy unit tests plus the offline validation of the real,
# committed charts. It needs neither network nor cosign.
#
# Root-free. Run from the repo root.
set -euo pipefail

cd "$(dirname "$0")/../.."

echo "== image-provenance: policy unit tests =="
python3 -m unittest discover -s .github/scripts -p 'test_verify_image_provenance.py' -v

echo
echo "== image-provenance: committed trust-critical charts =="
python3 .github/scripts/verify_image_provenance.py

echo
echo "image-provenance-test: OK"
