#!/usr/bin/env bash
# Golden test for tenant-image-bake.sh's distro dispatch (#multi-distro).
# Runs `--print-plan` (no root / network / image) against each
# os-release fixture and diffs the resolved per-distro decisions against
# the committed golden. A drift in `resolve_distro_plan` — a changed
# kernel package, a wrong family, a new distro mis-mapped — fails CI
# here, before any live bake. Cheap enough for the per-PR `rust`-style
# gate.
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BAKE="${HERE}/../tenant-image-bake.sh"
FIXTURES="${HERE}/distro-plan-fixtures"
GOLDEN="${FIXTURES}/expected.golden"

[[ -x "${BAKE}" || -r "${BAKE}" ]] || { echo "bake script not found at ${BAKE}" >&2; exit 1; }

actual=""
for f in "${FIXTURES}"/*.os-release; do
    name="$(basename "${f}" .os-release)"
    plan="$(bash "${BAKE}" --print-plan "${f}")"
    actual+="${name} ${plan}"$'\n'
done

if diff -u "${GOLDEN}" <(printf '%s' "${actual}"); then
    echo "distro-plan-test: OK ($(grep -c . "${GOLDEN}") fixtures match the golden)"
else
    echo "distro-plan-test: FAIL — resolve_distro_plan drifted from the golden." >&2
    echo "If the change is intentional, regenerate:" >&2
    echo "  for f in ${FIXTURES}/*.os-release; do n=\$(basename \$f .os-release); echo \"\$n \$(bash ${BAKE} --print-plan \$f)\"; done > ${GOLDEN}" >&2
    exit 1
fi
