#!/usr/bin/env bash
# release-creator-test.sh — one workflow, and only one, writes GitHub
# Releases: `.github/workflows/miner-agent-release.yml`.
#
# Releases are immutable on the public repository: once published, a
# release takes no new asset and its tag cannot be reused. On 2026-10-08
# `sbom.yml`, running on the same tag as the release workflow, created the
# release first (`gh release create --generate-notes`), which PUBLISHED it
# with no assets. Both workflows' uploads were then refused (HTTP 422), and
# v2026.10.08 stays an empty release for good.
#
# So this checks:
#   1. no other workflow creates, uploads to, edits or deletes a release
#      (gh CLI, the REST API, or a release action);
#   2. the release workflow creates its release as a draft, and publishes
#      it (`--draft=false`) exactly once, as its last release command;
#   3. sbom.yml does not run on tags by itself (the release workflow
#      calls it).
#
# `--self-test` runs the checks against mutated copies and fails unless
# each mutation is caught.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/../.." && pwd)"
CREATOR="miner-agent-release.yml"
# gh with any flags before `release`, any `uses:` of a release action, any
# REST path under /releases. A read of /releases matches too: no workflow
# but the creator needs one.
WRITES='(^|[^[:alnum:]_-])gh([[:space:]]+[^[:space:]]+)*[[:space:]]+release[[:space:]]+(create|upload|edit|delete)|uses:[^#]*release|repos/.*/releases'

# Code lines only: a comment may explain the rule it is not breaking.
code() { grep -vE '^[[:space:]]*#' "$1"; }

check() {
    local wf="$1" fail=0 f name
    for f in "${wf}"/*.yml "${wf}"/*.yaml; do
        [[ -e "${f}" ]] || continue
        name="$(basename "${f}")"
        [[ "${name}" == "${CREATOR}" ]] && continue
        if code "${f}" | grep -qE "${WRITES}"; then
            echo "FAIL ${name}: writes a release; only ${CREATOR} may (see this script's header)"
            fail=1
        fi
    done

    local rel="${wf}/${CREATOR}"
    if [[ ! -f "${rel}" ]]; then
        echo "FAIL ${CREATOR} is missing"
        return 1
    fi
    if ! code "${rel}" | grep -qE 'gh release create'; then
        echo "FAIL ${CREATOR}: creates no release"
        fail=1
    fi
    if code "${rel}" | grep -E 'gh release create' | grep -vqE -- '--draft( |$)'; then
        echo "FAIL ${CREATOR}: a 'gh release create' without --draft publishes before the assets are attached"
        fail=1
    fi
    local publishes last
    publishes="$(code "${rel}" | grep -cE -- '--draft=false')"
    last="$(code "${rel}" | grep -E 'gh release (create|upload|edit|delete)' | tail -1)"
    if [[ "${publishes}" -ne 1 ]]; then
        echo "FAIL ${CREATOR}: expected exactly one '--draft=false', found ${publishes}"
        fail=1
    elif [[ "${last}" != *"--draft=false"* ]]; then
        echo "FAIL ${CREATOR}: publishing (--draft=false) must be the last release command"
        fail=1
    fi

    if [[ -f "${wf}/sbom.yml" ]] && code "${wf}/sbom.yml" | grep -qE '^[[:space:]]+tags:'; then
        echo "FAIL sbom.yml runs on tags by itself; ${CREATOR} calls it"
        fail=1
    fi
    return "${fail}"
}

self_test() {
    local tmp bad=0
    tmp="$(mktemp -d)"
    trap 'find "${tmp}" -mindepth 1 -delete; rmdir "${tmp}"' RETURN

    mutate() { # <label> <sed expression> <file>
        local label="$1" expr="$2" file="$3"
        local dir="${tmp}/${label}"
        mkdir -p "${dir}"
        cp "${ROOT}"/.github/workflows/*.yml "${dir}/"
        sed -i -E "${expr}" "${dir}/${file}"
        if cmp -s "${dir}/${file}" "${ROOT}/.github/workflows/${file}"; then
            echo "SELF-TEST BROKEN ${label}: the mutation changed nothing"
            bad=1
        elif check "${dir}" >/dev/null; then
            echo "SELF-TEST MISSED ${label}"
            bad=1
        else
            echo "self-test caught ${label}"
        fi
    }
    mutate other-creates   '$a\      - run: gh release create "$TAG" --generate-notes' sbom.yml
    mutate other-api       '$a\      - run: gh api -X POST repos/o/r/releases' sbom.yml
    mutate other-api-expr  '$a\      - run: gh api "repos/${{ github.repository }}/releases"' sbom.yml
    mutate other-gh-flags  '$a\      - run: gh --repo o/r release create v1' sbom.yml
    mutate other-action    '$a\      - uses: ncipollo/release-action@0000000000000000000000000000000000000000' sbom.yml
    mutate no-create       's/^( +)gh release create .*$/\1true/' "${CREATOR}"
    mutate not-draft       's/ --draft --title/ --title/' "${CREATOR}"
    mutate no-publish      's/gh release edit "\$TAG" --draft=false/true/' "${CREATOR}"
    mutate publish-early   's/gh release edit "\$TAG" --draft=false/true/; s/^( +)gh release create (.*)$/\1gh release edit "$TAG" --draft=false\n\1gh release create \2/' "${CREATOR}"
    mutate sbom-on-tags    's/^(  push:)$/\1\n    tags: ["v*"]/' sbom.yml
    return "${bad}"
}

if [[ "${1:-}" == "--self-test" ]]; then
    self_test || exit 1
fi
if check "${ROOT}/.github/workflows"; then
    echo "release-creator: OK — only ${CREATOR} writes releases, draft first, published last"
else
    exit 1
fi
