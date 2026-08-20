#!/usr/bin/env bash
# verify-reproducible-bake.sh — run `tenant-image-bake.sh` twice with
# identical inputs + identical SOURCE_DATE_EPOCH, then diff the
# three output SHAs (qcow2 + kernel + initrd).
#
# #284 acceptance-criteria item 2 — "two independent bakes of the
# same input produce identical output SHAs" — is currently *manual*:
# an operator runs this script after a bake-script change to
# confirm reproducibility hasn't regressed. The CI dual-bake gate
# (item 3) lands as a separate follow-up that wires this into a
# workflow.
#
# What this script is NOT
# -----------------------
# Not a proof of reproducibility across DIFFERENT workstations
# (apt resolves package versions at bake time, and there's no
# snapshot service pinned today — issue #284 deferred item 1). Two
# bakes on the SAME workstation within minutes of each other should
# converge; two bakes on different workstations or different days
# will not, until apt is pinned to a snapshot repo. The script's
# value is regression detection: a bake-script change that breaks
# same-workstation reproducibility surfaces here before it ships.
#
# Usage
# -----
#   scripts/verify-reproducible-bake.sh \
#       --base-image-url   https://cloud-images.ubuntu.com/noble/20260801/noble-server-cloudimg-amd64.img \
#       --base-image-sha256 0533b0655c32e68b31d792ecd6ccfca95abdbc536c4446874fe0513bd4140ffe \
#       --hippius-release-bin target/x86_64-unknown-linux-gnu/release/hippius-guest-release \
#       --hippius-vsock-bin    target/x86_64-unknown-linux-gnu/release/hippius-vsock-ticket \
#       --source-date-epoch    1700000000
#
# All arguments are forwarded verbatim to two `tenant-image-bake.sh`
# invocations under `out/verify-A/` and `out/verify-B/`. The script
# then compares the resulting `tenant-<sha>.qcow2.sha256`,
# `tenant-<sha>.vmlinuz.sha256`, `tenant-<sha>.initrd.img.sha256`
# files between the two runs (the bake script produces these
# alongside the binary artifacts).
#
# Exit codes
# ----------
#   0 — both bakes succeeded and all three SHAs match across runs.
#   1 — at least one SHA differs (reproducibility regression) — the
#       script prints a unified diff of the three SHA files so an
#       operator can localize which artifact drifted.
#   2 — one of the two bakes failed; the script forwards the bake's
#       exit code in stderr.

set -Eeuo pipefail

PROG="$(basename "$0")"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BAKE_SCRIPT="${SCRIPT_DIR}/tenant-image-bake.sh"

log() { printf '%s: %s\n' "${PROG}" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

[[ -x "${BAKE_SCRIPT}" ]] || die "bake script not executable: ${BAKE_SCRIPT}"

# Sniff every arg the operator passed and (a) extract the
# --source-date-epoch if present so we can warn when it's missing,
# (b) build a clean argv we'll forward verbatim to the bake.
forward_args=()
saw_sde=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --source-date-epoch)
            saw_sde=1
            forward_args+=("$1" "$2"); shift 2
            ;;
        --output-dir)
            die "--output-dir is set internally by this script; do not pass it"
            ;;
        *)
            forward_args+=("$1"); shift
            ;;
    esac
done

if [[ "${saw_sde}" -eq 0 ]]; then
    log "WARN: --source-date-epoch not passed; reproducibility is" \
        "expected to fail (the bake will default to 86400 in each" \
        "run, but other non-determinism sources may still differ)."
fi

OUT_A="$(pwd)/out/verify-A"
OUT_B="$(pwd)/out/verify-B"
rm -rf -- "${OUT_A}" "${OUT_B}"
mkdir -p -- "${OUT_A}" "${OUT_B}"

# Read the KEK from stdin ONCE and tee it into two temp files (one
# per bake) so the operator only types / pipes the KEK once.
KEK_DIR="$(mktemp -d /dev/shm/verify-bake-XXXXXX)"
trap 'shred -u -- "${KEK_DIR}"/* 2>/dev/null || true; rm -rf -- "${KEK_DIR}"' EXIT
KEK_A="${KEK_DIR}/kek-A.bin"
KEK_B="${KEK_DIR}/kek-B.bin"
cat > "${KEK_A}"
cp -- "${KEK_A}" "${KEK_B}"

log "BAKE A → ${OUT_A}"
"${BAKE_SCRIPT}" "${forward_args[@]}" --output-dir "${OUT_A}" \
    --kek-source file --kek-file "${KEK_A}" \
    || { log "ERROR: bake A failed"; exit 2; }

log "BAKE B → ${OUT_B}"
"${BAKE_SCRIPT}" "${forward_args[@]}" --output-dir "${OUT_B}" \
    --kek-source file --kek-file "${KEK_B}" \
    || { log "ERROR: bake B failed"; exit 2; }

# Compare every `.sha256` file in OUT_A against the same-named file
# in OUT_B. The bake emits one .sha256 per binary artifact; matching
# them all = byte-identical bake.
divergent=0
for sha_a in "${OUT_A}"/*.sha256; do
    [[ -e "${sha_a}" ]] || die "BAKE A produced no .sha256 files in ${OUT_A}"
    name="$(basename "${sha_a}")"
    sha_b="${OUT_B}/${name}"
    if [[ ! -e "${sha_b}" ]]; then
        log "DIFF: ${name} present in A but not B"
        divergent=1
        continue
    fi
    if ! cmp -s "${sha_a}" "${sha_b}"; then
        log "DIFF: ${name}"
        diff -u "${sha_a}" "${sha_b}" >&2 || true
        divergent=1
    else
        log "OK:   ${name}  $(cat "${sha_a}")"
    fi
done

if [[ "${divergent}" -ne 0 ]]; then
    log "REPRODUCIBILITY REGRESSION — see diffs above. Per #284:" \
        "two same-workstation bakes with identical inputs +" \
        "--source-date-epoch must produce identical SHAs."
    exit 1
fi

log "all SHAs match — bake is reproducible on this workstation."
