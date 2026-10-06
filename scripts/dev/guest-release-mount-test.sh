#!/usr/bin/env bash
# Guest components release — the boot step for REAL (root only; CI runs it
# with sudo). guest-release-test.sh drives the step with a fake mount; this
# one builds a release, then runs `_hippius_golden_components_run` with the
# release's real static busybox doing the copy, the sha check and the loop
# mount of the real squashfs, under a `/run` mounted the way
# initramfs-tools mounts it (nodev,noexec,nosuid), and checks:
#   - the image is mounted ro,nosuid,nodev and its agents EXECUTE although
#     the /run it sits under is noexec;
#   - after `mount --move` of /run into a new root (what initramfs-tools
#     does before run-init, and what systemd's switch-root does for /run),
#     the image is still mounted there and its agents still execute;
#   - the unit links point at that final path.
#
#   sudo GUEST_RELEASE_TEST_STATIC_BUSYBOX=<static busybox> \
#       bash scripts/dev/guest-release-mount-test.sh
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "${HERE}/../.." && pwd)"
LIB="${REPO}/scripts/initramfs/hippius-golden-overlay.sh"
BUILD="${REPO}/scripts/guest/build-guest-release.sh"
STATIC_BB="${GUEST_RELEASE_TEST_STATIC_BUSYBOX:?set GUEST_RELEASE_TEST_STATIC_BUSYBOX to a static busybox}"

[[ "$(id -u)" -eq 0 ]] || { echo "guest-release-mount-test: needs root" >&2; exit 2; }

fail=0
ok()  { echo "guest-release-mount-test: OK — $*"; }
err() { echo "guest-release-mount-test: FAIL — $*" >&2; fail=1; }

T="$(mktemp -d)"
cleanup() {
    # Deepest mounts first.
    for m in "${T}/newroot/run/hippius/guest" "${T}/newroot/run" "${T}/run/hippius/guest" "${T}/run" "${T}"; do
        if mountpoint -q "${m}" 2>/dev/null; then umount -l "${m}" 2>/dev/null || true; fi
    done
    rm -r "${T}"
}
trap cleanup EXIT
# A private mount tree, like the initramfs's: the kernel refuses to move
# a mount whose parent is shared (the runner's / is).
mount --bind "${T}" "${T}"
mount --make-rprivate "${T}"

# A release whose agents are shell scripts printing their own name.
mkdir -p "${T}/bins"
for b in hippius-agent-keepalive hippius-agent-tenant-telemetry hippius-agent-initramfs \
         hippius-guest-release hippius-vsock-ticket; do
    printf '#!/bin/sh\necho %s --attest-components\n' "${b}" > "${T}/bins/${b}"
    chmod 0755 "${T}/bins/${b}"
done
"${BUILD}" --bin-dir "${T}/bins" --busybox "${STATIC_BB}" --commit "$(printf 'c%.0s' $(seq 40))" \
    --source-date-epoch 1700000000 --out "${T}/out" >/dev/null 2>&1 \
    || { echo "guest-release-mount-test: the builder failed" >&2; exit 1; }

# The initramfs as the boot step sees it: the release dir, /run mounted
# like initramfs-tools does it, the assembled root.
mkdir -p "${T}/rel" "${T}/run" "${T}/root/etc/systemd/system" "${T}/lower" "${T}/newroot/run"
cp "${T}/out/release" "${T}/out/components.squashfs" "${T}/rel/"
install -m 0755 "${STATIC_BB}" "${T}/rel/busybox"
mount -t tmpfs -o nodev,noexec,nosuid,mode=0755 tmpfs "${T}/run"

bash -c "set -eu
hippius_log() { printf '%s\n' \"\$*\" >> '${T}/log'; }
hippius_die() { printf 'DIE %s\n' \"\$*\" >> '${T}/log'; exit 42; }
. '${LIB}'
HIPPIUS_GOLDEN_LOWER_MNT='${T}/lower'
_hippius_golden_components_run '${T}/root' '${T}/rel' '${T}/run/hippius'" \
    || { cat "${T}/log" >&2; err "the boot step failed"; }

MNT="${T}/run/hippius/guest"
if mountpoint -q "${MNT}"; then
    opts="$(findmnt -n -o OPTIONS "${MNT}")"
    for o in ro nosuid nodev; do
        [[ ",${opts}," == *",${o},"* ]] || err "image mount lacks ${o}: ${opts}"
    done
    [[ ",${opts}," != *",noexec,"* ]] || err "image mount is noexec: ${opts}"
    [[ "$(findmnt -n -o FSTYPE "${MNT}")" == squashfs ]] || err "image mount is not squashfs"
    [[ "$("${MNT}/bin/hippius-agent-keepalive")" == "hippius-agent-keepalive --attest-components" ]] \
        || err "an agent does not execute from the image under a noexec /run"
    ok "image loop-mounted by the release's busybox, ro,nosuid,nodev, agents execute under a noexec /run"
else
    cat "${T}/log" >&2
    err "the image is not mounted"
fi
grep -q 'mounted=yes' "${T}/run/hippius/guest-components" || err "status does not say mounted"

# switch_root: /run moves into the new root with its submounts.
mount --move "${T}/run" "${T}/newroot/run"
NEW="${T}/newroot/run/hippius/guest"
if mountpoint -q "${NEW}"; then
    [[ "$("${NEW}/bin/hippius-agent-tenant-telemetry")" == "hippius-agent-tenant-telemetry --attest-components" ]] \
        || err "an agent does not execute after the move"
    [[ -f "${NEW}/units/hippius-eol-sign.service" ]] || err "units missing after the move"
    ok "after mount --move of /run the image is still mounted and executable in the new root"
else
    err "the image did not follow /run into the new root"
fi
[[ "$(readlink "${T}/root/etc/systemd/system/hippius-keepalive.service")" == /run/hippius/guest/units/hippius-keepalive.service ]] \
    || err "unit link does not name the final path"
ok "unit links name /run/hippius/guest/units/… (the path after switch_root)"

[[ ${fail} -eq 0 ]] || { echo "guest-release-mount-test: FAILED" >&2; exit 1; }
echo "guest-release-mount-test: all passed"
