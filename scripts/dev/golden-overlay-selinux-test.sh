#!/usr/bin/env bash
#
# Unit test for the SELinux root-inode labeling in
# `hippius_golden_mount_overlay` (scripts/initramfs/hippius-golden-overlay.sh).
#
# The per-VM overlay upper is a freshly `mkfs.ext4`'d volume with no SELinux
# labels. overlayfs derives the MERGED root dir ("/") label from the UPPER's
# own root-dir inode (it IGNORES the `rootcontext=` mount option), so an
# enforcing RHEL guest sees "/" as `unlabeled_t` and DENIES every confined
# domain `search /` (journald / NetworkManager / netbird / getty all fail).
# The fix stamps the RO lower's "/" label (`root_t`) onto the upper's
# overlay-root dir via `setfattr` BEFORE the overlay mount, gated on the lower
# shipping /etc/selinux/config so the Debian/Ubuntu (no-SELinux) path is
# byte-identical.
#
# Root-free: `mount`/`setfattr`/`getfattr` are mocked to capture calls; no
# devices, no /proc, no real xattrs.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
LIB="${HERE}/../initramfs/hippius-golden-overlay.sh"
[ -r "${LIB}" ] || { echo "golden-overlay-selinux-test: lib not found at ${LIB}" >&2; exit 1; }

fail=0
ok()  { echo "golden-overlay-selinux-test: OK — $*"; }
err() { echo "golden-overlay-selinux-test: FAIL — $*" >&2; fail=1; }

# shellcheck source=scripts/initramfs/hippius-golden-overlay.sh
. "${LIB}"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

HIPPIUS_GOLDEN_LOWER_MNT="${WORK}/lower"
HIPPIUS_GOLDEN_UPPER_MNT="${WORK}/upper"
SETFATTR_LOG="${WORK}/setfattr"
OVERLAY_OPTS_LOG="${WORK}/overlay-opts"

# The label the mocked `getfattr` reports on the lower "/". A real lower
# carries `root_t`; the test uses a distinctive value to prove the code reads
# it (rather than blindly hardcoding).
LOWER_ROOT_LABEL="system_u:object_r:root_t:s0"

command() {           # shadow `command -v getfattr` → present
    if [ "${1:-}" = "-v" ] && [ "${2:-}" = "getfattr" ]; then echo getfattr; return 0; fi
    builtin command "$@"
}
getfattr() {          # report the lower "/" label
    printf '%s' "${LOWER_ROOT_LABEL}"
}
setfattr() {          # capture: name value target
    # args: -n security.selinux -v <label> <target>
    _val=""; _tgt=""; _prev=""
    for _a in "$@"; do
        [ "${_prev}" = "-v" ] && _val="${_a}"
        _tgt="${_a}"; _prev="${_a}"
    done
    printf '%s\t%s\n' "${_val}" "${_tgt}" >>"${SETFATTR_LOG}"
    return 0
}
mount() {
    _prev=""; _is_overlay=0
    for _a in "$@"; do
        [ "${_prev}" = "-t" ] && [ "${_a}" = "overlay" ] && _is_overlay=1
        _prev="${_a}"
    done
    if [ "${_is_overlay}" = "1" ]; then
        _prev=""
        for _a in "$@"; do
            [ "${_prev}" = "-o" ] && printf '%s' "${_a}" >"${OVERLAY_OPTS_LOG}"
            _prev="${_a}"
        done
    fi
    return 0
}
hippius_die() { echo "hippius_die: $*" >&2; exit 1; }
hippius_log() { :; }
# Keep the anti-rollback gate inert here (its own gate is
# scripts/dev/golden-stamp-test.sh): point both stamp paths at files that
# cannot exist, so this SELinux-only test never reaches the gate or the
# confirm binary even on a host where /run/hippius happens to be populated.
HIPPIUS_GOLDEN_STAMP_EXPECTED="${WORK}/no-such-expected"
HIPPIUS_GOLDEN_STAMP_CTX="${WORK}/no-such-ctx"

run_case() {
    # $1 = "selinux" | "plain"
    rm -rf "${HIPPIUS_GOLDEN_LOWER_MNT}" "${HIPPIUS_GOLDEN_UPPER_MNT}"
    mkdir -p "${HIPPIUS_GOLDEN_LOWER_MNT}" "${HIPPIUS_GOLDEN_UPPER_MNT}"
    if [ "$1" = "selinux" ]; then
        mkdir -p "${HIPPIUS_GOLDEN_LOWER_MNT}/etc/selinux"
        : >"${HIPPIUS_GOLDEN_LOWER_MNT}/etc/selinux/config"
    fi
    : >"${SETFATTR_LOG}"; : >"${OVERLAY_OPTS_LOG}"
    # Subshell — a fail-closed hippius_die (exit 1) must not abort the test.
    ( hippius_golden_mount_overlay "${WORK}/sysroot" ) >/dev/null 2>&1 || true
}

# ── Case 1: SELinux base → stamp the lower "/" label onto the upper root ──
run_case selinux
if grep -q "	${HIPPIUS_GOLDEN_UPPER_MNT}/upper$" "${SETFATTR_LOG}" \
   && grep -q "^${LOWER_ROOT_LABEL}	" "${SETFATTR_LOG}"; then
    ok "SELinux base stamps the real lower label onto upper/upper"
else
    err "SELinux base did NOT stamp upper root (log='$(cat "${SETFATTR_LOG}")')"
fi
# The overlay mount options must be UNCHANGED (fix is not a mount-option).
opts_selinux="$(cat "${OVERLAY_OPTS_LOG}")"
case "${opts_selinux}" in
    "lowerdir=${HIPPIUS_GOLDEN_LOWER_MNT},upperdir=${HIPPIUS_GOLDEN_UPPER_MNT}/upper,workdir=${HIPPIUS_GOLDEN_UPPER_MNT}/work")
        ok "SELinux base overlay mount options unchanged (no rootcontext)" ;;
    *)  err "SELinux base overlay opts unexpected (opts='${opts_selinux}')" ;;
esac

# ── Case 2: no SELinux (Debian/Ubuntu) → NO setfattr, byte-identical ─────
run_case plain
if [ -s "${SETFATTR_LOG}" ]; then
    err "non-SELinux base called setfattr (log='$(cat "${SETFATTR_LOG}")')"
else
    ok "non-SELinux base does not touch SELinux labels"
fi
opts_plain="$(cat "${OVERLAY_OPTS_LOG}")"
case "${opts_plain}" in
    "lowerdir=${HIPPIUS_GOLDEN_LOWER_MNT},upperdir=${HIPPIUS_GOLDEN_UPPER_MNT}/upper,workdir=${HIPPIUS_GOLDEN_UPPER_MNT}/work")
        ok "non-SELinux base overlay opts byte-identical" ;;
    *)  err "non-SELinux base overlay opts changed (opts='${opts_plain}')" ;;
esac

# ── Case 3: override knob is honoured ────────────────────────────────────
HIPPIUS_GOLDEN_ROOT_SECONTEXT="system_u:object_r:custom_root_t:s0"
run_case selinux
unset HIPPIUS_GOLDEN_ROOT_SECONTEXT
if grep -q "^system_u:object_r:custom_root_t:s0	" "${SETFATTR_LOG}"; then
    ok "HIPPIUS_GOLDEN_ROOT_SECONTEXT override honoured"
else
    err "override not honoured (log='$(cat "${SETFATTR_LOG}")')"
fi

# ── Case 4: a malformed override FAILS CLOSED (no setfattr, no mount) ─────
HIPPIUS_GOLDEN_ROOT_SECONTEXT="not a context; rm -rf /"
run_case selinux
unset HIPPIUS_GOLDEN_ROOT_SECONTEXT
if [ ! -s "${SETFATTR_LOG}" ] && [ ! -s "${OVERLAY_OPTS_LOG}" ]; then
    ok "malformed rootcontext override fails closed (no stamp, no mount)"
else
    err "malformed override NOT rejected (setfattr='$(cat "${SETFATTR_LOG}")' opts='$(cat "${OVERLAY_OPTS_LOG}")')"
fi

if [ "${fail}" -ne 0 ]; then
    echo "golden-overlay-selinux-test: FAILED" >&2
    exit 1
fi
echo "golden-overlay-selinux-test: OK (all checks passed)"
