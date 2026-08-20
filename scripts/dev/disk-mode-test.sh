#!/usr/bin/env bash
# Unit test for tenant-image-bake.sh's `--disk-mode` selector (golden-bake
# PR1). Exercises the argument gate WITHOUT root / network / a real image:
# the disk-mode validation runs before any required-arg / tooling / mount
# step, so a bad value fails fast and a good value falls through to the
# next validation error. Keeps the legacy default provably intact and the
# new golden_verity_overlay value provably accepted.
#
# Cheap enough for the per-PR CI gate (same tier as distro-plan-test.sh).
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BAKE="${HERE}/../tenant-image-bake.sh"

[[ -r "${BAKE}" ]] || { echo "disk-mode-test: bake script not found at ${BAKE}" >&2; exit 1; }

fail=0
BAD_MODE_ERR='disk-mode must be legacy_luks or golden_verity_overlay'

# Run the bake with the given args, capturing stderr + exit code. The bake
# always fails early here (no real inputs) — we only assert WHICH gate it
# died at.
run_bake() {
    set +e
    bash "${BAKE}" "$@" </dev/null 2>"${TMP_ERR}" >/dev/null
    RC=$?
    set -e
}

TMP_ERR="$(mktemp)"
trap 'rm -f "${TMP_ERR}"' EXIT

# 1. An invalid --disk-mode is rejected at the disk-mode gate (exit 1),
#    before the required-arg checks. No other args needed.
run_bake --disk-mode bogus
if (( RC == 0 )) || ! grep -qF "${BAD_MODE_ERR}" "${TMP_ERR}"; then
    echo "disk-mode-test: FAIL — invalid --disk-mode not rejected (rc=${RC})" >&2
    cat "${TMP_ERR}" >&2
    fail=1
else
    echo "disk-mode-test: OK — invalid --disk-mode rejected"
fi

# 2. golden_verity_overlay is ACCEPTED: it passes the disk-mode gate and
#    falls through to the next validation error (missing --base-image-url),
#    NOT the disk-mode error.
run_bake --disk-mode golden_verity_overlay
if grep -qF "${BAD_MODE_ERR}" "${TMP_ERR}" || ! grep -qF 'base-image-url is required' "${TMP_ERR}"; then
    echo "disk-mode-test: FAIL — golden_verity_overlay not accepted at the gate (rc=${RC})" >&2
    cat "${TMP_ERR}" >&2
    fail=1
else
    echo "disk-mode-test: OK — golden_verity_overlay accepted at the gate"
fi

# 3. legacy_luks (the explicit default) is likewise accepted at the gate.
run_bake --disk-mode legacy_luks
if grep -qF "${BAD_MODE_ERR}" "${TMP_ERR}" || ! grep -qF 'base-image-url is required' "${TMP_ERR}"; then
    echo "disk-mode-test: FAIL — legacy_luks not accepted at the gate (rc=${RC})" >&2
    cat "${TMP_ERR}" >&2
    fail=1
else
    echo "disk-mode-test: OK — legacy_luks accepted at the gate"
fi

# 4. The implicit default (no --disk-mode) reaches the same required-arg
#    error — proving the default is a valid disk-mode (legacy_luks).
run_bake
if grep -qF "${BAD_MODE_ERR}" "${TMP_ERR}" || ! grep -qF 'base-image-url is required' "${TMP_ERR}"; then
    echo "disk-mode-test: FAIL — implicit default disk-mode is not valid (rc=${RC})" >&2
    cat "${TMP_ERR}" >&2
    fail=1
else
    echo "disk-mode-test: OK — implicit default disk-mode accepted"
fi

if (( fail )); then
    echo "disk-mode-test: FAIL" >&2
    exit 1
fi
echo "disk-mode-test: OK (4 checks passed)"
