#!/usr/bin/env bash
# Container gate for the `95hippius-golden` dracut module (golden-bake,
# RHEL family). For each RHEL-family image (CentOS Stream 10, Fedora):
#   1. install dracut + a kernel + cryptsetup in a container,
#   2. stage the module + stub binaries + the shared release core + the
#      shared golden overlay lib + the EMPTY golden crypttab,
#   3. `dracut --no-hostonly --add hippius-golden`,
#   4. `lsinitrd`-assert: the mount + teardown units present AND enabled
#      (mount RequiredBy=initrd-root-fs.target so systemd waits for
#      /sysroot; teardown WantedBy=initrd-switch-root.target), the cmdline
#      rootok hook present, the runner + net-teardown + core + overlay lib
#      + binaries staged, and the REQUIRED KERNEL MODULES (sev-guest /
#      vsock chain / dm_integrity / dm_verity / overlay / squashfs) made
#      it in.
#
# This is the golden analogue of scripts/dev/dracut-module-test.sh (the
# legacy 90hippius-luks gate). Needs docker (or podman via DOCKER=podman).
# Heavier than a unit test (~2-4 min/distro) — wired to the dracut-module
# CI workflow, not the per-PR rust job.
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "${HERE}/../.." && pwd)"
DOCKER="${DOCKER:-docker}"
IMAGES=(${DRACUT_TEST_IMAGES:-quay.io/centos/centos:stream10 fedora:latest})

run_one() {
    local image="$1"
    echo "=== ${image} (golden) ==="
    "${DOCKER}" run --rm -i \
        -v "${REPO}/scripts/dracut/95hippius-golden:/mod:ro" \
        -v "${REPO}/scripts/initramfs/hippius-release-core.sh:/core.sh:ro" \
        -v "${REPO}/scripts/initramfs/hippius-golden-overlay.sh:/overlay.sh:ro" \
        "${image}" bash -s <<'INNER'
set -euo pipefail
# veritysetup is a SEPARATE package on RHEL/Fedora (split out of
# cryptsetup) — the golden module needs it to open the dm-verity lower;
# the bake installs it explicitly in golden mode, so install it here too.
# `attr` provides setfattr/getfattr — the module inst's them to stamp the
# overlay-root SELinux label; the bake installs it in golden mode too.
dnf -y -q install dracut dracut-network kernel-core kernel-modules kernel-modules-extra \
    cryptsetup veritysetup e2fsprogs attr systemd iproute >/dev/null
KVER=$(ls /lib/modules | sort -V | tail -1)
echo "kernel: ${KVER}"

# Stage what module-setup expects on the "host" being baked:
install -d /etc/hippius /usr/lib/dracut/modules.d/95hippius-golden
cp /core.sh /etc/hippius/hippius-release-core.sh
cp /overlay.sh /etc/hippius/hippius-golden-overlay.sh
cp /mod/* /usr/lib/dracut/modules.d/95hippius-golden/
chmod 0755 /usr/lib/dracut/modules.d/95hippius-golden/*.sh
# Stub static binaries (the real ones are musl-static; any executable
# with no ldd deps exercises the same `inst` path).
printf '#!/bin/sh\nexit 0\n' > /usr/sbin/hippius-guest-release
printf '#!/bin/sh\nexit 0\n' > /usr/sbin/hippius-vsock-ticket
chmod 0755 /usr/sbin/hippius-guest-release /usr/sbin/hippius-vsock-ticket
# The EMPTY golden crypttab the bake's golden arm writes (root is the
# overlay, not a crypttab device).
cat > /etc/crypttab <<'EOF'
# hippius-bake-managed (golden_verity_overlay): intentionally EMPTY.
EOF

dracut --force --no-hostonly --add hippius-golden --kver "${KVER}" /tmp/test-initrd.img
echo "initrd built: $(du -h /tmp/test-initrd.img | cut -f1)"

fail=0
# List ONCE to a file and grep THAT — any `... | grep -q` under pipefail
# dies with SIGPIPE (141) even on a match.
lsinitrd /tmp/test-initrd.img > /tmp/lsinitrd.txt
need() {
    if ! grep -qE "$1" /tmp/lsinitrd.txt; then
        echo "MISSING in initrd: $1" >&2; fail=1
    fi
}
# Units present + enabled. The mount unit MUST be wired into
# initrd-root-fs.target.requires (so systemd waits for /sysroot before
# switch-root); the teardown into initrd-switch-root.target.wants.
need 'usr/lib/systemd/system/hippius-golden-mount.service'
need 'usr/lib/systemd/system/hippius-net-teardown.service'
need 'initrd-root-fs.target.requires/hippius-golden-mount.service'
need 'initrd-switch-root.target.wants/hippius-net-teardown.service'
# The cmdline rootok hook (so dracut does not emergency on the absent
# root=), the mount runner + teardown, the shared core + overlay lib +
# binaries. Path-AGNOSTIC (basename match): Fedora merged /sbin into
# /usr/bin, CS10 keeps /usr/sbin — dracut's merge symlinks resolve either.
need 'parse-hippius-golden.sh'
need '/hippius-golden-mount'
need '/hippius-net-teardown'
need 'hippius-release-core.sh'
need 'hippius-golden-overlay.sh'
need '/hippius-guest-release'
need '/hippius-vsock-ticket'
need '/sed'
# The golden overlay assembly needs the RO dm-verity lower + the
# guest-keyed upper + the overlayfs root; assert the kernel stack made it
# in (builtin would also satisfy boot).
for mod in sev-guest dm-integrity dm-crypt dm-verity overlay squashfs vmw_vsock_virtio_transport vsock; do
    if ! grep -qE "${mod//-/[-_]}\.ko" /tmp/lsinitrd.txt; then
        # tolerate builtin: check modules.builtin for it
        if ! grep -qE "/${mod//-/[-_]}\.ko" "/lib/modules/${KVER}/modules.builtin"; then
            echo "MISSING kernel module in initrd (and not builtin): ${mod}" >&2; fail=1
        fi
    fi
done
# veritysetup + mkfs.ext4 must be present for the assembly.
need '/veritysetup'
need '/mkfs.ext4|/mke2fs'
# setfattr must be present — the overlay lib stamps the overlay-root SELinux
# label with it on RHEL golden boots (a hard requirement, inst'd non-optional).
need '/setfattr'
[ "${fail}" -eq 0 ] && echo "GOLDEN-DRACUT-MODULE-OK" || exit 1
INNER
}

rc=0
for img in "${IMAGES[@]}"; do
    run_one "${img}" || { echo "FAILED for ${img}" >&2; rc=1; }
done
exit "${rc}"
