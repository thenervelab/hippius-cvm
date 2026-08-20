#!/usr/bin/env bash
# release-diverges-only-in-config.sh — the branch we publish must differ
# from `main` in configuration and documentation ONLY.
#
# WHY THIS IS THE INVARIANT THAT MATTERS. `main` is what CI compiles and
# tests; `release/**` is what gets published. Everything else in this repo
# argues that the published tree DISCLOSES nothing. This argues something
# different and just as load-bearing: that it BEHAVES like the tree we
# tested. If a scrub ever edits a `.rs` or a `.py` on the release branch
# alone, the binary a miner builds from the public repo stops being the
# binary our test suite ever ran, and nothing else here would notice.
#
# When this was written the invariant held across 29 release-only commits:
# 63 files under `deploy/`, three at the root, and not one byte of code.
#
# A scrub that genuinely needs a code change is not blocked — it goes to
# `main` and merges forward, which is how #993 (the VEK fixture) is
# structured. The rule is about WHERE the change lands, not whether it is
# allowed.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/../.." && pwd)"
cd "${ROOT}"

BASE="${RELEASE_DIVERGENCE_BASE:-origin/main}"

if ! git rev-parse --verify --quiet "${BASE}" >/dev/null; then
    # Never a skip: unable to compare means unable to verify, and a check
    # that passes when it compared nothing is the defect this repository
    # keeps rediscovering in its own guards.
    echo "release-divergence: '${BASE}' is not available — cannot compare, so this FAILS."
    echo "  fetch it first (CI: actions/checkout with fetch-depth: 0, then git fetch origin main)."
    exit 1
fi

# A three-dot diff is computed from the MERGE BASE. In a shallow clone
# there is none, and git returns an empty diff — indistinguishable from
# "the branches agree". This check shipped without the guard below and its
# first CI run reported "no divergence" across 66 changed files, because
# `actions/checkout` defaults to depth 1. Absent history is a FAILURE.
if ! git merge-base "${BASE}" HEAD >/dev/null 2>&1; then
    echo "release-divergence: no merge base between '${BASE}' and HEAD."
    echo "  The clone is almost certainly shallow, and a three-dot diff over a"
    echo "  shallow clone returns EMPTY — which would read as 'no divergence'."
    echo "  Fetch full history (actions/checkout with fetch-depth: 0)."
    exit 1
fi

mapfile -t changed < <(git diff --name-only "${BASE}...HEAD")

if (( ${#changed[@]} == 0 )); then
    echo "release-divergence: no divergence from ${BASE}"
    exit 0
fi

# Areas a scrub may legitimately touch. Deliberately NOT a catch-all: the
# point is that code paths are absent from it.
allowed() {
    case "$1" in
        deploy/*|docs/*|*.md|.gitleaks.toml|.publish-denylist.example|.gitignore) return 0 ;;
        *) return 1 ;;
    esac
}

violations=()
for f in "${changed[@]}"; do
    allowed "${f}" || violations+=("${f}")
done

echo "release-divergence: ${#changed[@]} file(s) differ from ${BASE}"

if (( ${#violations[@]} > 0 )); then
    echo "release-divergence: ${#violations[@]} of them are OUTSIDE config and documentation:"
    printf '    %s\n' "${violations[@]}"
    echo
    echo "  The published tree would no longer be the tree CI tests. If the change"
    echo "  is genuinely needed, put it on \`main\` and merge forward — that keeps"
    echo "  one tested source of truth and still reaches the release branch."
    exit 1
fi

echo "release-divergence: config and documentation only — the published tree is"
echo "                    byte-identical to ${BASE} everywhere else."
