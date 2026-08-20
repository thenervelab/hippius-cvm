#!/usr/bin/env bash
# Root-free unit test for the security-load-bearing logic of the golden
# dracut cmdline hook `parse-hippius-golden.sh` (dracut module
# 95hippius-golden): it must set `rootok=1` IFF the measured cmdline
# signals golden (dm-verity.root= PRESENT and hippius.luks_header_sha256=
# ABSENT) — the SAME both-tokens fail-closed signal the shared overlay
# lib + the miner-agent + the vali emitter use. A fail-OPEN here (rootok
# claimed on a legacy cmdline) would let dracut skip the LUKS root; a
# fail-CLOSED regression (rootok not claimed on golden) would strand the
# boot in emergency. Pins both without a container/live boot.
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
HOOK="${HERE}/../dracut/95hippius-golden/parse-hippius-golden.sh"
[[ -r "${HOOK}" ]] || { echo "golden-dracut-parse-test: hook not found at ${HOOK}" >&2; exit 1; }

fail=0
ok()  { echo "golden-dracut-parse-test: OK — $*"; }
err() { echo "golden-dracut-parse-test: FAIL — $*" >&2; fail=1; }

GOOD_HASH="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# Drive the hook with a given cmdline; echo the resulting rootok value.
# Stubs `getarg` (dracut-lib) against a CMDLINE string and `info` so the
# hook sources + runs without a live initrd.
run_hook() {
    CMDLINE="$1" bash -c '
        getarg() {
            _k="${1%=}"
            for _t in ${CMDLINE}; do
                case "${_t}" in
                    "${_k}"=*) printf "%s" "${_t#*=}"; return 0 ;;
                esac
            done
            return 1
        }
        info() { :; }
        rootok=""
        . "'"${HOOK}"'"
        printf "%s" "${rootok}"
    '
}

# 1. Golden cmdline → rootok=1.
[[ "$(run_hook "ro quiet dm-verity.root=${GOOD_HASH} hippius.disk_gb=10 boot=hippius-golden")" == "1" ]] \
    && ok "golden cmdline claims root (rootok=1)" \
    || err "golden cmdline did NOT claim root"

# 2. Legacy cmdline (luks header present, no verity root) → rootok unset.
[[ "$(run_hook "ro quiet hippius.luks_header_sha256=${GOOD_HASH} hippius.disk_gb=10")" == "" ]] \
    && ok "legacy cmdline does not claim root" \
    || err "legacy cmdline wrongly claimed root (fail-open!)"

# 3. Both tokens present (hostile splice) → fail closed, rootok unset.
[[ "$(run_hook "ro dm-verity.root=${GOOD_HASH} hippius.luks_header_sha256=${GOOD_HASH}")" == "" ]] \
    && ok "both-tokens cmdline fails closed (does not claim root)" \
    || err "both-tokens cmdline wrongly claimed root (fail-open!)"

# 4. Neither token (bare) → rootok unset.
[[ "$(run_hook "ro quiet console=ttyS0")" == "" ]] \
    && ok "bare cmdline does not claim root" \
    || err "bare cmdline wrongly claimed root"

exit "${fail}"
