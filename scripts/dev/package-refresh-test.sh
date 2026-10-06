#!/usr/bin/env bash
# Unit test for tenant-image-bake.sh's `--package-refresh` (F6, scheduled
# golden re-bake). Root-free, no network, no image:
#
#   1. the argument gate: a stamp with shell-/path-active bytes is refused
#      before anything else runs; a well-formed one passes the gate;
#   2. the stamp keys the stage-1 cache (a cached stage-1 baked against
#      older packages must never satisfy a refresh);
#   3. BOTH chroot arms run their upgrade only when PKG_REFRESH is set, and
#      both chroot env(1) lines pass it.
#
# Same tier as disk-mode-test.sh (per-PR CI gate).
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BAKE="${HERE}/../tenant-image-bake.sh"
ENTRYPOINT="${HERE}/../../binaries/tenant-baker/entrypoint.sh"

[[ -r "${BAKE}" ]] || { echo "package-refresh-test: bake script not found at ${BAKE}" >&2; exit 1; }

fail=0
ok()  { echo "package-refresh-test: OK — $*"; }
err() { echo "package-refresh-test: FAIL — $*" >&2; fail=1; }

BAD_ERR='--package-refresh must match'
TMP_ERR="$(mktemp)"
trap 'rm -f "${TMP_ERR}"' EXIT

run_bake() {
    set +e
    bash "${BAKE}" "$@" </dev/null 2>"${TMP_ERR}" >/dev/null
    RC=$?
    set -e
}

# 1. Gate.
for bad in 'x;reboot' '../up' 'a b' "$(printf 'x%.0s' {1..65})"; do
    run_bake --package-refresh "${bad}"
    if (( RC == 0 )) || ! grep -qF -- "${BAD_ERR}" "${TMP_ERR}"; then
        err "stamp '${bad}' not rejected (rc=${RC})"; cat "${TMP_ERR}" >&2
    else
        ok "stamp '${bad}' rejected"
    fi
done
run_bake --package-refresh 20261101
if grep -qF -- "${BAD_ERR}" "${TMP_ERR}" || ! grep -qF 'base-image-url is required' "${TMP_ERR}"; then
    err "stamp 20261101 not accepted at the gate (rc=${RC})"; cat "${TMP_ERR}" >&2
else
    ok "stamp 20261101 accepted at the gate"
fi
HCC_BAKE_PKG_REFRESH='bad stamp' run_bake
if ! grep -qF -- "${BAD_ERR}" "${TMP_ERR}"; then
    err "\$HCC_BAKE_PKG_REFRESH not validated"
else
    ok "\$HCC_BAKE_PKG_REFRESH validated"
fi

# 2. Cache key.
if grep -qF 'echo "pkg_refresh=${package_refresh:-none}"' "${BAKE}"; then
    ok "stamp folded into the stage-1 cache key"
else
    err "stamp missing from the stage-1 cache key"
fi

# 2b. A refresh stage-1 is single-use, so it is never stored (the cache PVC
#     has no GC); the skip sits inside stage1_cache_store.
store_fn="$(sed -n '/^stage1_cache_store() {$/,/^}$/p' "${BAKE}")"
if grep -qF 'if [[ -n "${package_refresh}" ]]; then' <<<"${store_fn}" \
    && grep -qF 'stage-1 cache store skipped' <<<"${store_fn}"; then
    ok "refresh stage-1 not stored in the cache"
else
    err "stage1_cache_store does not skip a package-refresh stage-1"
fi

# 3. Both chroot arms: gated upgrade + env pass-through.
apt_arm="$(sed -n "/<<'CHROOT_EOF'/,/^CHROOT_EOF\$/p" "${BAKE}")"
rhel_arm="$(sed -n "/<<'CHROOT_RHEL_EOF'/,/^CHROOT_RHEL_EOF\$/p" "${BAKE}")"
grep -qE '^if \[ -n "\$\{PKG_REFRESH:-\}" \]; then$' <<<"${apt_arm}" \
    && grep -qE '^    apt-get -y .* dist-upgrade$' <<<"${apt_arm}" \
    && ok "apt arm: dist-upgrade gated on PKG_REFRESH" \
    || err "apt arm: no PKG_REFRESH-gated dist-upgrade"
grep -qE '^if \[ -n "\$\{PKG_REFRESH:-\}" \]; then$' <<<"${rhel_arm}" \
    && grep -qF '${DNF} upgrade' <<<"${rhel_arm}" \
    && ok "dnf arm: upgrade gated on PKG_REFRESH" \
    || err "dnf arm: no PKG_REFRESH-gated upgrade"
n_env="$(grep -cF 'PKG_REFRESH="${package_refresh}" \' "${BAKE}")"
if [[ "${n_env}" == 2 ]]; then
    ok "both chroot env(1) lines pass PKG_REFRESH"
else
    err "expected 2 chroot env(1) lines passing PKG_REFRESH, found ${n_env}"
fi

# 3b. Stage 5 refuses a kernel/initrd pair built for different kernels (a
#     refresh can leave two kernels installed). The function is lifted
#     VERBATIM from the bake and run on real kernel names.
if grep -qxF 'assert_kernel_initrd_match "${kernel_src}" "${initrd_src}"' "${BAKE}"; then
    ok "stage 5 calls assert_kernel_initrd_match"
else
    err "stage 5 does not call assert_kernel_initrd_match"
fi
match_fn="$(sed -n '/^assert_kernel_initrd_match() {$/,/^}$/p' "${BAKE}")"
[[ -n "${match_fn}" ]] || err "assert_kernel_initrd_match not found in the bake"
check_pair() {  # expect(match|mismatch) kernel initrd
    local got
    if bash -c "die() { echo \"\$*\" >&2; exit 3; }; ${match_fn}; assert_kernel_initrd_match '$2' '$3'" 2>/dev/null; then
        got=match
    else
        got=mismatch
    fi
    if [[ "${got}" == "$1" ]]; then ok "$1: ${2##*/} / ${3##*/}"; else err "expected $1, got ${got}: $2 / $3"; fi
}
check_pair match    /m/boot/vmlinuz-6.8.0-85-generic /m/boot/initrd.img-6.8.0-85-generic
check_pair match    /m/boot/vmlinuz-6.12.48+deb13-amd64 /m/boot/initrd.img-6.12.48+deb13-amd64
check_pair match    /m/boot/vmlinuz-6.17.1-300.fc43.x86_64 /m/boot/initramfs-6.17.1-300.fc43.x86_64.img
check_pair mismatch /m/boot/vmlinuz-6.17.1-300.fc43.x86_64 /m/boot/initramfs-6.17.4-300.fc43.x86_64.img
check_pair mismatch /m/boot/vmlinuz-6.12.0-55.el10.x86_64 /m/boot/initramfs-6.12.0-60.el10.x86_64.img
check_pair mismatch /m/boot/vmlinuz-6.8.0-85-generic /m/boot/initrd.img-6.8.0-90-generic

# 4. The baker entrypoint forwards vali's stamp.
if grep -qF 'BAKE_ARGS+=(--package-refresh "${BAKE_PACKAGE_REFRESH}")' "${ENTRYPOINT}"; then
    ok "entrypoint forwards BAKE_PACKAGE_REFRESH"
else
    err "entrypoint does not forward BAKE_PACKAGE_REFRESH"
fi

exit "${fail}"
