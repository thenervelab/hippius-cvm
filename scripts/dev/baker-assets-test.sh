#!/usr/bin/env bash
# baker-assets-test.sh — every asset `tenant-image-bake.sh` reads out of its
# own directory must actually be COPYed into the baker image.
#
# Why this exists: #908 taught the bake to stage the §23 keepalive shim and
# shipped a CI test that EXECUTES the staging block against a temp rootfs —
# but nothing asserted the baker IMAGE carried the shim. The Dockerfile was
# never told to COPY it. Both the image build and the whole test suite stayed
# green, and the gap surfaced only when a real bake ran and died with
# "keepalive shim missing" at step 3 of 6, after pulling a cloud image.
#
# The shape is this repo's most repeated defect: a thing is declared in one
# place and not wired in the other, and every test that exercises the declared
# half passes. So the pin has to be the RELATIONSHIP — bake script reads X ⇒
# Dockerfile ships X — not either side alone.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BAKE="${HERE}/../tenant-image-bake.sh"
DOCKERFILE="${HERE}/../../binaries/tenant-baker/Dockerfile"

for f in "${BAKE}" "${DOCKERFILE}"; do
    [[ -r "${f}" ]] || { echo "baker-assets-test: missing ${f}"; exit 1; }
done

FAILED=0
ok()  { echo "baker-assets-test: OK — $1"; }
bad() { echo "baker-assets-test: FAIL — $1"; FAILED=1; }

# `SCRIPT_DIR` is the directory holding the bake script; in the image that is
# /usr/local/bin (see the COPY of tenant-image-bake.sh). So a reference to
# ${SCRIPT_DIR}/guest/foo must be satisfied by a COPY whose destination is
# /usr/local/bin/guest/foo — either the file itself or its parent directory.
#
# COPY directives here use backslash continuations to list several sources
# against one destination, so the Dockerfile must be JOINED before matching.
# Matching line-by-line reported 7 assets as missing that have shipped for
# months — a check that cries wolf on working code is worse than no check.
JOINED="$(mktemp)"
trap 'rm -f "${JOINED}"' EXIT
sed -e ':a' -e '/\\$/{N;s/\\\n[[:space:]]*/ /;ba' -e '}' "${DOCKERFILE}" > "${JOINED}"
mapfile -t REFS < <(
    grep -oE '\$\{SCRIPT_DIR\}/[A-Za-z0-9_./-]+' "${BAKE}" \
    | sed 's|\${SCRIPT_DIR}/||' \
    | grep -v '^\.\.$' \
    | sort -u
)

(( ${#REFS[@]} > 0 )) || bad "no \${SCRIPT_DIR}/... references found — the grep broke, not the code"

for ref in "${REFS[@]}"; do
    # Accept a COPY of the exact path, or of any ancestor directory.
    found=0
    probe="${ref}"
    while :; do
        if grep -qE "^COPY[[:space:]].*[[:space:]]/usr/local/bin/${probe}/?[[:space:]]*$" "${JOINED}"; then
            found=1
            break
        fi
        parent="$(dirname "${probe}")"
        [[ "${parent}" == "." || "${parent}" == "${probe}" ]] && break
        probe="${parent}"
    done

    if (( found )); then
        ok "\${SCRIPT_DIR}/${ref} is shipped into the image"
    else
        bad "\${SCRIPT_DIR}/${ref} is READ by tenant-image-bake.sh but NOTHING copies it to /usr/local/bin/${ref} — a bake using this path dies at runtime while every test passes"
    fi

    # The source must also exist in the tree, or the COPY itself would fail.
    src="${HERE}/../${ref}"
    if [[ -e "${src}" ]]; then
        ok "source scripts/${ref} exists"
    else
        bad "source scripts/${ref} does not exist in the repo"
    fi
done

[[ "${FAILED}" == "0" ]] && echo "baker-assets-test: ALL OK" || echo "baker-assets-test: FAILURES"
exit "${FAILED}"
